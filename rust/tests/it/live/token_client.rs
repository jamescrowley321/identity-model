//! Integration tests for the OAuth 2.0 token client against a real provider.
//!
//! `#[ignore]`-gated so a bare `cargo test` (no provider up) stays green. The
//! `integration-tests-rust` CI job boots the local `infra/` node-oidc-provider
//! (`:9010`), runs the unit suite, then runs these with
//! `cargo test -- --ignored` under `TEST_REQUIRE_LIVE=1` (infra skips fail).
//!
//! Run locally:
//!
//! ```text
//! make infra-up
//! make test-integration-rust      # or: cd rust && cargo test -- --ignored
//! make infra-down
//! ```
//!
//! Provider selection follows the shared `TEST_*` convention (the
//! `.env.node-oidc` profile the Makefile sources). `TEST_DISCO_ADDRESS` is the
//! full discovery-document URL; the issuer is that URL minus the
//! `/.well-known/openid-configuration` suffix, and `token_endpoint` is resolved
//! from the fetched discovery document. If `TEST_DISCO_ADDRESS` is unset the
//! test skips (returns) rather than failing.
//!
//! Mirrors the Go reference (`go/pkg/token/token_integration_test.go`):
//!
//! * `client_credentials` (CC-001/CC-002): obtains a real
//!   access token via the client-credentials grant with the default
//!   `client_secret_basic` auth and asserts `access_token`/`token_type` are set.
//! * `client_credentials_invalid_client` (CC-004): a bad client
//!   secret surfaces a typed [`IdentityError::TokenEndpoint`] (RFC 6749 §5.2) —
//!   or, for providers with a non-RFC error body, an [`IdentityError::Http`]
//!   carrying the 4xx status.
//! * `authorization_code_pkce_rejected` (ACG-004/005/006, partial):
//!   exchanging an invalid authorization code that carries a PKCE
//!   `code_verifier` reaches the live token endpoint and is rejected with a
//!   typed [`IdentityError::TokenEndpoint`] (`invalid_grant`). This verifies the
//!   request shape (grant type, code, code_verifier) and live error parsing.
//! * `authorization_code_pkce_end_to_end` (ACG-001..003, CONS-1.4):
//!   a full headless authorization-code + PKCE round-trip driving
//!   node-oidc-provider's devInteractions (login + consent) with no browser,
//!   then the real token-endpoint exchange with the `code_verifier`.

use std::time::Duration;

use rs_identity_model::{DiscoveryClient, IdentityError, PkceChallenge, TokenClient};

use crate::common::authcode::follow_to_callback;
use crate::common::env::{env_nonempty, issuer_from_env, skip_or_fail};
use crate::common::live::discover_or_skip;

/// Discovers the live provider's `token_endpoint`, skipping the test when the
/// provider is unreachable so a missing local stack does not fail CI-less runs.
async fn token_endpoint_or_skip(issuer: &str, allow_http: bool) -> Option<String> {
    let meta = discover_or_skip(issuer, allow_http).await?;
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );
    Some(meta.token_endpoint)
}

// CC-001 / CC-002: the client-credentials grant obtains a real access token from
// the provider using the default client_secret_basic authentication.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn client_credentials() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_CLIENT_ID"),
        env_nonempty("TEST_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_CLIENT_ID/TEST_CLIENT_SECRET unset for this provider profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some(token_endpoint) = token_endpoint_or_skip(&issuer, allow_http).await else {
        return;
    };

    let client = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build token client");

    let scope = env_nonempty("TEST_SCOPE");
    let resp = client
        .client_credentials(scope.as_deref())
        .await
        .unwrap_or_else(|e| panic!("client_credentials against live provider: {e}"));
    assert!(
        !resp.access_token.is_empty(),
        "empty access_token: {resp:?}"
    );
    assert!(!resp.token_type.is_empty(), "empty token_type: {resp:?}");
}

// CC-004: a bad client secret produces a typed error from the live provider,
// exercising the real RFC 6749 §5.2 error path. node-oidc-provider returns a
// standard `invalid_client` error body -> TokenEndpoint; providers with a
// proprietary body surface as Http carrying the 4xx status.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn client_credentials_invalid_client() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(client_id) = env_nonempty("TEST_CLIENT_ID") else {
        skip_or_fail("TEST_CLIENT_ID unset for this provider profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some(token_endpoint) = token_endpoint_or_skip(&issuer, allow_http).await else {
        return;
    };

    let client = TokenClient::builder()
        .client_id(client_id)
        .client_secret("wrong-secret")
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build token client");

    let err = client
        .client_credentials(env_nonempty("TEST_SCOPE").as_deref())
        .await
        .expect_err("bad client secret must be rejected");
    match err {
        IdentityError::TokenEndpoint {
            ref error, status, ..
        } => {
            assert!(!error.is_empty(), "token error has empty code: {err:?}");
            assert!((400..500).contains(&status), "status = {status}, want 4xx");
        }
        IdentityError::Http(msg) => {
            // Non-RFC error bodies surface as Http; accept as a live 4xx path.
            eprintln!("provider returned non-OAuth error body (accepted): {msg}");
        }
        other => panic!("err = {other:?}, want TokenEndpoint or Http for invalid_client"),
    }
}

// ACG-004 / ACG-005 / ACG-006 (partial): exchanging an invalid authorization
// code that carries a PKCE code_verifier reaches the live token endpoint and is
// rejected with a typed TokenEndpoint error. Confirms request shape and live
// error parsing independent of the end-to-end flow below.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn authorization_code_pkce_rejected() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(public_client_id) = env_nonempty("TEST_PKCE_PUBLIC_CLIENT_ID") else {
        skip_or_fail("TEST_PKCE_PUBLIC_CLIENT_ID unset for this provider profile");
        return;
    };
    let redirect_uri = env_nonempty("TEST_REDIRECT_URI")
        .unwrap_or_else(|| "http://localhost:3000/callback".into());

    let allow_http = issuer.starts_with("http://");
    let Some(token_endpoint) = token_endpoint_or_skip(&issuer, allow_http).await else {
        return;
    };

    // Public client: no secret, so credentials go in the body (client_id only).
    let client = TokenClient::builder()
        .client_id(public_client_id)
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build public token client");

    let pkce = PkceChallenge::generate().expect("generate PKCE challenge");
    let err = client
        .exchange_code("invalid-code", &redirect_uri, Some(&pkce.code_verifier))
        .await
        .expect_err("invalid authorization code must be rejected");
    match err {
        IdentityError::TokenEndpoint {
            ref error, status, ..
        } => {
            assert!(!error.is_empty(), "token error has empty code: {err:?}");
            assert!((400..500).contains(&status), "status = {status}, want 4xx");
        }
        other => panic!("err = {other:?}, want TokenEndpoint (invalid_grant)"),
    }
}

// ── Headless authorization-code + PKCE end-to-end (CONS-1.4 / AC-0A.5) ──────
//
// Drives node-oidc-provider's devInteractions (login + consent) with a plain
// HTTP client — no browser — then exchanges the callback code through
// [`TokenClient::exchange_code`] with the PKCE verifier. Mirrors the Go
// `TestIntegration_AuthorizationCode_PKCE_EndToEnd` and the Python suite's
// `perform_auth_code_flow`. Skips (cleanly) on provider profiles without
// devInteractions.

#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn authorization_code_pkce_end_to_end() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(public_client_id) = env_nonempty("TEST_PKCE_PUBLIC_CLIENT_ID") else {
        skip_or_fail("TEST_PKCE_PUBLIC_CLIENT_ID unset for this provider profile");
        return;
    };
    let Some(redirect_uri) = env_nonempty("TEST_REDIRECT_URI") else {
        skip_or_fail("TEST_REDIRECT_URI unset for this provider profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    let meta = match discovery.discover(&issuer).await {
        Ok(meta) => meta,
        Err(e) => {
            skip_or_fail(&format!(
                "provider not reachable at {issuer} (run `make infra-up`): {e}"
            ));
            return;
        }
    };
    assert!(
        !meta.authorization_endpoint.is_empty(),
        "discovery returned empty authorization_endpoint"
    );

    let pkce = PkceChallenge::generate().expect("generate PKCE challenge");
    let state = PkceChallenge::generate()
        .expect("generate state entropy")
        .code_verifier;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build flow http client");
    let mut cookies = std::collections::HashMap::new();

    let auth_url = url::Url::parse_with_params(
        &meta.authorization_endpoint,
        &[
            ("client_id", public_client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", state.as_str()),
            ("code_challenge", pkce.code_challenge.as_str()),
            ("code_challenge_method", pkce.code_challenge_method.as_str()),
        ],
    )
    .expect("build authorize URL");

    let (landed, status, mut callback) =
        follow_to_callback(&http, &mut cookies, http.get(auth_url), &redirect_uri)
            .await
            .expect("authorize leg");

    if callback.is_none() {
        // A >=400 rendered AT the authorization endpoint itself (no redirect)
        // is how node-oidc reports the regressions this suite must catch —
        // unknown client_id, redirect_uri mismatch — so it is a hard failure,
        // never a skip. (Error redirects back to redirect_uri are caught via
        // the callback's `error` param below.)
        let auth_path = url::Url::parse(&meta.authorization_endpoint)
            .map(|u| u.path().to_string())
            .unwrap_or_default();
        assert!(
            !((status.is_client_error() || status.is_server_error()) && landed.path() == auth_path),
            "authorization endpoint rejected the request: {status} at {landed}"
        );
        // Providers without node-oidc's devInteractions redirect AWAY to a
        // real (or missing) browser login UI — e.g. IdentityServer's
        // /Account/Login 404s in the headless fixture. Skip, don't fail.
        if status.is_client_error()
            || status.is_server_error()
            || !landed.path().contains("/interaction/")
        {
            skip_or_fail(&format!(
                "provider has no devInteractions (landed on {landed} with {status}); headless flow unavailable"
            ));
            return;
        }
        // devInteractions login: a single endpoint dispatches on `prompt`.
        let login = http.post(landed.clone()).form(&[
            ("prompt", "login"),
            ("login", "test-user"),
            ("password", "test"),
        ]);
        let (after_login, status, cb) =
            follow_to_callback(&http, &mut cookies, login, &redirect_uri)
                .await
                .expect("login leg");
        assert!(
            cb.is_some() || !(status.is_client_error() || status.is_server_error()),
            "login failed: {status} at {after_login}"
        );
        callback = cb;
        if callback.is_none() && after_login.path().contains("/interaction/") {
            let consent = http
                .post(after_login.clone())
                .form(&[("prompt", "consent")]);
            let (after_consent, status, cb) =
                follow_to_callback(&http, &mut cookies, consent, &redirect_uri)
                    .await
                    .expect("consent leg");
            assert!(
                cb.is_some() || !(status.is_client_error() || status.is_server_error()),
                "consent failed: {status} at {after_consent}"
            );
            callback = cb;
        }
    }
    let callback = callback.expect("auth code flow did not reach the redirect URI");
    let callback = url::Url::parse(&callback).expect("parse callback URL");
    let params: std::collections::HashMap<_, _> = callback.query_pairs().collect();
    assert!(
        !params.contains_key("error"),
        "authorization error at callback: {callback}"
    );
    assert_eq!(
        params.get("state").map(AsRef::as_ref),
        Some(state.as_str()),
        "callback state mismatch"
    );
    let code = params.get("code").expect("callback carried no code");

    let Some(token_endpoint) = token_endpoint_or_skip(&issuer, allow_http).await else {
        return;
    };
    let client = TokenClient::builder()
        .client_id(public_client_id)
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build public token client");
    let token = client
        .exchange_code(code, &redirect_uri, Some(&pkce.code_verifier))
        .await
        .expect("authorization-code exchange with PKCE verifier");
    assert!(
        !token.access_token.is_empty(),
        "empty access_token in exchange response"
    );
    assert!(
        token.id_token.as_deref().is_some_and(|t| !t.is_empty()),
        "openid-scoped code exchange returned no id_token"
    );
}
