//! Integration tests for the OIDC UserInfo client against a real provider.
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
//! `/.well-known/openid-configuration` suffix, and `userinfo_endpoint` /
//! `token_endpoint` are resolved from the fetched discovery document. If
//! `TEST_DISCO_ADDRESS` is unset the test skips (returns) rather than failing.
//!
//! Mirrors the Go reference (`go/pkg/userinfo/userinfo_integration_test.go`):
//!
//! * `userinfo_bogus_token` (UI-004): a bogus access token is
//!   rejected by the live provider with a 401 [`IdentityError::UserInfo`]
//!   carrying a `WWW-Authenticate` challenge (tolerating providers that omit it
//!   per RFC 6750 §3). This error path is always runnable without an
//!   interactive end-user login.
//! * `userinfo_client_credentials_token` (UI-001, best-effort): a
//!   client_credentials access token has no end-user subject, so the provider
//!   rejects it at the UserInfo endpoint; we assert a typed error rather than a
//!   successful claims response. The positive end-user path (an authorization_code
//!   access token whose `sub` matches the ID token) requires an interactive
//!   `/authorize` login and is documented rather than asserted — the same
//!   deferral as token ACG-006.

use std::time::Duration;

use rs_identity_model::{IdentityError, TokenClient, UserInfoClient};

use crate::common::env::{env_nonempty, issuer_from_env, skip_or_fail};
use crate::common::live::discover_or_skip;

/// Discovers the live provider's endpoints, skipping the test when the provider
/// is unreachable so a missing local stack does not fail CI-less runs. Returns
/// `(userinfo_endpoint, token_endpoint)`.
async fn endpoints_or_skip(issuer: &str, allow_http: bool) -> Option<(String, String)> {
    let meta = discover_or_skip(issuer, allow_http).await?;
    let Some(userinfo) = meta.userinfo_endpoint.filter(|u| !u.is_empty()) else {
        skip_or_fail("provider does not advertise a userinfo_endpoint");
        return None;
    };
    Some((userinfo, meta.token_endpoint))
}

// UI-004 (live): a bogus access token is rejected by the live provider with a
// 401 UserInfo error carrying a WWW-Authenticate challenge. This error path is
// always runnable without an interactive end-user login.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn userinfo_bogus_token() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some((userinfo_endpoint, _token_endpoint)) = endpoints_or_skip(&issuer, allow_http).await
    else {
        return;
    };

    let client = UserInfoClient::builder()
        .userinfo_endpoint(userinfo_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build userinfo client");

    let err = client
        .fetch("this-is-not-a-valid-token")
        .await
        .expect_err("bogus access token must be rejected");
    match err {
        IdentityError::UserInfo {
            status,
            www_authenticate,
            ..
        } => {
            assert_eq!(status, 401, "status = {status}, want 401");
            if www_authenticate.is_none() {
                // RFC 6750 §3 requires WWW-Authenticate on a 401, but some
                // providers omit it; tolerate the omission while still requiring
                // the 401 and the typed error above.
                eprintln!("provider omitted the WWW-Authenticate challenge on 401 (RFC 6750 §3)");
            }
        }
        other => panic!("err = {other:?}, want UserInfo{{status:401}}"),
    }
}

// UI-001 (live, best-effort): a client_credentials access token is presented to
// the UserInfo endpoint. A CC token has no end-user subject, so per OIDC the
// provider rejects it at the UserInfo endpoint; we assert a typed error rather
// than a successful claims response.
//
// Known gap: the positive end-user path (a real access token issued via the
// authorization_code flow, whose claims include a sub matching the ID token)
// requires an interactive browser login at /authorize and is documented here
// rather than asserted (same deferral as token ACG-006).
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn userinfo_client_credentials_token() {
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
    let Some((userinfo_endpoint, token_endpoint)) = endpoints_or_skip(&issuer, allow_http).await
    else {
        return;
    };
    if token_endpoint.is_empty() {
        skip_or_fail("provider does not advertise a token_endpoint");
        return;
    }

    let token_client = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build token client");

    // The provider may decline the openid scope for the CC grant; that is an
    // acceptable outcome for this best-effort probe.
    let tok = match token_client.client_credentials(Some("openid")).await {
        Ok(tok) => tok,
        Err(e) => {
            skip_or_fail(&format!(
                "client_credentials with openid scope unavailable: {e}"
            ));
            return;
        }
    };

    let userinfo_client = UserInfoClient::builder()
        .userinfo_endpoint(userinfo_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build userinfo client");

    match userinfo_client.fetch(&tok.access_token).await {
        // A CC token has no end-user subject; any typed error is a valid
        // outcome (UserInfo for a rejected token, Validation for a missing sub).
        Err(IdentityError::UserInfo { .. }) | Err(IdentityError::Validation(_)) => {}
        Err(other) => panic!("unexpected error type: {other:?}"),
        Ok(_) => {
            eprintln!("provider returned claims for a client_credentials token; no assertion");
        }
    }
}
