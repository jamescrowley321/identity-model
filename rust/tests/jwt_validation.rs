//! Integration test for JWT validation against a real provider.
//!
//! `#[ignore]`-gated so the unit `rust` CI job's bare `cargo test` (run with no
//! provider up) stays green. The dedicated `rust-integration` CI job runs it
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
//! `/.well-known/openid-configuration` suffix, and `jwks_uri` is resolved from
//! the fetched discovery document. If `TEST_DISCO_ADDRESS` is unset the test
//! skips (returns) rather than failing.
//!
//! What it proves (JWT-001 / JWT-010): the end-to-end path
//! discovery → JWKS fetch → `validate_token_with_jwks` drives a real network
//! round-trip and a forced JWKS refresh. We sign a token with the shared
//! fixture key, whose `kid` the live provider does not publish, so key
//! resolution must force one refresh and ultimately surface
//! [`IdentityError::KeyNotFound`]. Full happy-path validation of a
//! provider-issued `id_token` (where the signature verifies) requires the
//! authorization-code flow and is deferred to R4.5/R4.6, mirroring the Go
//! reference (`go/pkg/jwt/jwt_integration_test.go`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_model::{DiscoveryClient, IdentityError, JwksClient, ValidationOptions};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::{BigUint, RsaPrivateKey};
use serde_json::{Value, json};
use std::time::Duration;

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";
const FIXTURE: &str = "../spec/test-fixtures/validation/signing-key.jwk.json";
const FIXTURE_KID: &str = "test-key-1";

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

/// Builds an RS256 [`EncodingKey`] from the shared private JWK fixture so the
/// signed token carries `kid=test-key-1` — a key the provider does not publish.
fn signing_key() -> EncodingKey {
    let jwk: Value =
        serde_json::from_slice(&std::fs::read(FIXTURE).expect("read fixture")).expect("parse jwk");
    let field = |name: &str| {
        let s = jwk[name].as_str().unwrap_or_else(|| panic!("jwk.{name}"));
        BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(s).expect("decode base64url"))
    };
    let private = RsaPrivateKey::from_components(
        field("n"),
        field("e"),
        field("d"),
        vec![field("p"), field("q")],
    )
    .expect("build RSA private key");
    let pem = private
        .to_pkcs1_pem(LineEnding::LF)
        .expect("encode PKCS#1 PEM");
    EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key")
}

// JWT-001 / JWT-010: discover the live provider, fetch its real JWKS, then
// validate a token whose kid the provider does not publish. Key resolution must
// force one JWKS refresh and surface KeyNotFound against the live endpoint.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_forced_refresh_against_live_jwks() {
    let Some(issuer) = issuer_from_env() else {
        eprintln!("SKIP: TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };

    // Local fixtures serve plain HTTP; allow it for http:// issuers only.
    let allow_http = issuer.starts_with("http://");

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

    // Prime the cache with the provider's real key set so resolution of our
    // unknown kid genuinely exercises the forced-refresh path (JWT-010).
    let set = jwks
        .fetch(&meta.jwks_uri)
        .await
        .unwrap_or_else(|e| panic!("fetch({}): {e}", meta.jwks_uri));
    assert!(!set.keys().is_empty(), "provider returned no keys");
    assert!(
        set.resolve_key(FIXTURE_KID).is_err(),
        "provider unexpectedly publishes the fixture kid; test premise invalid"
    );

    // Sign a well-formed RS256 token with the fixture key (kid=test-key-1).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(FIXTURE_KID.to_string());
    let claims = json!({
        "iss": issuer.clone(),
        "sub": "integration-subject",
        "aud": "integration-client",
        "exp": now + 3600,
        "iat": now,
    });
    let token = jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token");

    // The unknown kid drives a forced JWKS refresh; the key is still absent, so
    // validation surfaces KeyNotFound before any claim check runs.
    let options = ValidationOptions::builder().issuer(issuer.as_str()).build();
    let err = validate_expecting_err(&token, &jwks, &meta.jwks_uri, &options).await;
    match err {
        IdentityError::KeyNotFound(_) => {}
        other => panic!("err = {other:?}, want KeyNotFound after live forced refresh"),
    }
}

async fn validate_expecting_err(
    token: &str,
    jwks: &JwksClient,
    jwks_uri: &str,
    options: &ValidationOptions,
) -> IdentityError {
    identity_model::validate_token_with_jwks(token, jwks, jwks_uri, options)
        .await
        .expect_err("validation must fail for an unpublished kid")
}
