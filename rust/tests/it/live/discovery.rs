//! Integration tests for the OIDC Discovery client against a real provider.
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
//! `/.well-known/openid-configuration` suffix. Point `TEST_DISCO_ADDRESS` at
//! another provider to run the same test there. If it is unset the test skips
//! (returns) rather than failing, so `cargo test -- --ignored` is safe without
//! a provider configured.

use rs_identity_model::DiscoveryClient;
use std::time::Duration;

use crate::common::env::{issuer_from_env, skip_or_fail};

// DISC-001 / DISC-002 / DISC-003 / DISC-004: fetch a real discovery document,
// confirm the issuer matches and the required endpoints are populated, then a
// second call within the TTL is served from cache without error.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn discovers_real_provider() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };

    // Local fixtures serve plain HTTP; allow it for http:// issuers only.
    let allow_http = issuer.starts_with("http://");
    let client = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();

    let meta = client
        .discover(&issuer)
        .await
        .unwrap_or_else(|e| panic!("discover({issuer}): {e}"));

    // DISC-003: the document's issuer matches the requested issuer.
    assert_eq!(meta.issuer.trim_end_matches('/'), issuer, "issuer mismatch");

    // DISC-002: the required endpoints are present and non-empty.
    assert!(
        !meta.authorization_endpoint.is_empty(),
        "authorization_endpoint is empty"
    );
    assert!(!meta.token_endpoint.is_empty(), "token_endpoint is empty");
    assert!(!meta.jwks_uri.is_empty(), "jwks_uri is empty");
    assert!(
        !meta.response_types_supported.is_empty(),
        "response_types_supported is empty"
    );
    assert!(
        !meta.subject_types_supported.is_empty(),
        "subject_types_supported is empty"
    );
    assert!(
        !meta.id_token_signing_alg_values_supported.is_empty(),
        "id_token_signing_alg_values_supported is empty"
    );

    // DISC-004: a second call within the TTL is served from cache and succeeds.
    let cached = client
        .discover(&issuer)
        .await
        .expect("cached re-fetch within TTL");
    assert_eq!(cached.issuer, meta.issuer, "cached document differs");
}
