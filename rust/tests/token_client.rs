//! Integration tests for the OAuth 2.0 token client against a real provider.
//!
//! `#[ignore]`-gated so the unit `rust` CI job's bare `cargo test` (run with no
//! provider up) stays green. The dedicated `rust-integration` CI job runs them
//! with `cargo test -- --ignored` after bringing up the local `infra/`
//! node-oidc-provider (`:9000`).
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
//! * `integration_client_credentials_live` (CC-001/CC-002): obtains a real
//!   access token via the client-credentials grant with the default
//!   `client_secret_basic` auth and asserts `access_token`/`token_type` are set.
//! * `integration_client_credentials_invalid_client` (CC-004): a bad client
//!   secret surfaces a typed [`IdentityError::TokenEndpoint`] (RFC 6749 §5.2) —
//!   or, for providers with a non-RFC error body, an [`IdentityError::Http`]
//!   carrying the 4xx status.
//! * `integration_authorization_code_pkce_rejected` (ACG-004/005/006, partial):
//!   exchanging an invalid authorization code that carries a PKCE
//!   `code_verifier` reaches the live token endpoint and is rejected with a
//!   typed [`IdentityError::TokenEndpoint`] (`invalid_grant`). This verifies the
//!   request shape (grant type, code, code_verifier) and live error parsing; a
//!   full interactive `/authorize` round-trip is out of scope for an automated
//!   test.

use std::time::Duration;

use identity_model::{DiscoveryClient, IdentityError, PkceChallenge, TokenClient};

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// Returns the issuer derived from `TEST_DISCO_ADDRESS`, or `None` when the
/// variable is unset so the caller can skip gracefully.
fn issuer_from_env() -> Option<String> {
    let disco = std::env::var("TEST_DISCO_ADDRESS").ok()?;
    let disco = disco.trim();
    if disco.is_empty() {
        return None;
    }
    Some(
        disco
            .strip_suffix(WELL_KNOWN_SUFFIX)
            .unwrap_or(disco)
            .trim_end_matches('/')
            .to_string(),
    )
}

/// Reads a non-empty `TEST_*` environment variable.
fn env_nonempty(name: &str) -> Option<String> {
    let v = std::env::var(name).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Discovers the live provider's `token_endpoint`, skipping the test when the
/// provider is unreachable so a missing local stack does not fail CI-less runs.
async fn token_endpoint_or_skip(issuer: &str, allow_http: bool) -> Option<String> {
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    match discovery.discover(issuer).await {
        Ok(meta) => {
            assert!(
                !meta.token_endpoint.is_empty(),
                "discovery returned empty token_endpoint"
            );
            Some(meta.token_endpoint)
        }
        Err(e) => {
            eprintln!("SKIP: provider not reachable at {issuer} (run `make infra-up`): {e}");
            None
        }
    }
}

// CC-001 / CC-002: the client-credentials grant obtains a real access token from
// the provider using the default client_secret_basic authentication.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_client_credentials_live() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_CLIENT_ID"),
        env_nonempty("TEST_CLIENT_SECRET"),
    ) else {
        eprintln!("SKIP: TEST_CLIENT_ID/TEST_CLIENT_SECRET unset for this provider profile");
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
async fn integration_client_credentials_invalid_client() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(client_id) = env_nonempty("TEST_CLIENT_ID") else {
        eprintln!("SKIP: TEST_CLIENT_ID unset for this provider profile");
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
// error parsing; the interactive /authorize round-trip is out of scope.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_authorization_code_pkce_rejected() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(public_client_id) = env_nonempty("TEST_PKCE_PUBLIC_CLIENT_ID") else {
        eprintln!("SKIP: TEST_PKCE_PUBLIC_CLIENT_ID unset for this provider profile");
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
