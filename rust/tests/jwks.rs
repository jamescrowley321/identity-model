//! Integration tests for the JWKS client against a real provider.
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
//! `/.well-known/openid-configuration` suffix. There is no separate
//! `TEST_JWKS_ADDRESS` locally, so the `jwks_uri` is resolved from the fetched
//! discovery document. If `TEST_DISCO_ADDRESS` is unset the test skips
//! (returns) rather than failing, so `cargo test -- --ignored` is safe without
//! a provider configured.

use identity_model::{DiscoveryClient, JwksClient};
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

// JWKS-001 / JWKS-002 / JWKS-003 / JWKS-006: discover the provider, fetch its
// real JWK Set, confirm it is non-empty with usable keys, resolve the first key
// by its kid, and force a refresh without losing the keys.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_fetches_real_key_set() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };

    // Local fixtures serve plain HTTP; allow it for http:// issuers only.
    let allow_http = issuer.starts_with("http://");

    // There is no separate TEST_JWKS_ADDRESS; resolve jwks_uri via discovery.
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    let meta = discovery
        .discover(&issuer)
        .await
        .unwrap_or_else(|e| panic!("discover({issuer}): {e}"));
    assert!(
        !meta.jwks_uri.is_empty(),
        "discovery returned empty jwks_uri"
    );

    let jwks = JwksClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();

    // JWKS-001 / JWKS-002: the provider's key set fetches and parses.
    let set = jwks
        .fetch(&meta.jwks_uri)
        .await
        .unwrap_or_else(|e| panic!("fetch({}): {e}", meta.jwks_uri));
    assert!(!set.keys().is_empty(), "provider returned no keys");

    // Every returned key must carry a key type (JWKS-002).
    for key in set.keys() {
        assert!(!key.kty.is_empty(), "key {:?} missing kty", key.kid);
    }

    // JWKS-003: resolve the first key by its kid if one is published.
    let first = &set.keys()[0];
    if !first.kid.is_empty() {
        let resolved = set
            .resolve_key(&first.kid)
            .unwrap_or_else(|e| panic!("resolve_key({:?}): {e}", first.kid));
        assert_eq!(resolved.kid, first.kid);

        // The client's fetch-then-resolve path resolves the same key.
        let via_client = jwks
            .resolve_key(&meta.jwks_uri, &first.kid)
            .await
            .unwrap_or_else(|e| panic!("client resolve_key({:?}): {e}", first.kid));
        assert_eq!(via_client.kid, first.kid);
    }

    // JWKS-006: force_refresh re-fetches without error and keeps the keys.
    let refreshed = jwks
        .force_refresh(&meta.jwks_uri)
        .await
        .expect("force_refresh");
    assert!(
        !refreshed.keys().is_empty(),
        "key set empty after force_refresh"
    );
}
