//! Integration tests for the OIDC Discovery client against a real provider.
//!
//! These are `#[ignore]`-gated so the unit `rust` CI job's bare `cargo test`
//! (run with no provider up) stays green. The dedicated `rust-integration` CI
//! job runs them with `cargo test -- --ignored` after bringing up the local
//! `infra/` node-oidc-provider (`:9000`).
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

use identity_model::DiscoveryClient;
use std::time::Duration;

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

// DISC-001 / DISC-002 / DISC-003 / DISC-004: fetch a real discovery document,
// confirm the issuer matches and the required endpoints are populated, then a
// second call within the TTL is served from cache without error.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_discovers_real_provider() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
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
