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
//! What it proves:
//!
//! * `integration_client_credentials_validate_and_tamper` (AC-9, JWT-001/009):
//!   acquires a real access token via the client-credentials grant (raw
//!   `client_secret_basic` POST — the `TokenClient` builder lands in R4.5),
//!   validates it end-to-end (discovery → JWKS → `validate_token_with_jwks`),
//!   then confirms a tampered copy is rejected. The local provider issues the
//!   client-credentials access token as an RS256 JWT signed by its published
//!   JWKS (see `infra/node-oidc-provider/provider.js`: the `urn:test:api`
//!   resource sets `accessTokenFormat: "jwt"`), so happy-path validation
//!   genuinely verifies against the live key set.
//! * `integration_forced_refresh_against_live_jwks` (JWT-001/010): signs a token
//!   with the shared fixture key whose `kid` the provider does not publish, so
//!   key resolution must force one JWKS refresh and ultimately surface
//!   [`IdentityError::KeyNotFound`], mirroring the Go reference
//!   (`go/pkg/jwt/jwt_integration_test.go`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_model::{
    DiscoveryClient, IdentityError, JwksClient, ProviderMetadata, ValidationOptions,
};
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

/// Reads a non-empty `TEST_*` environment variable.
fn env_nonempty(name: &str) -> Option<String> {
    let v = std::env::var(name).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Discovers the live provider, skipping the test if it is unreachable.
async fn discover_or_skip(issuer: &str, allow_http: bool) -> Option<ProviderMetadata> {
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    match discovery.discover(issuer).await {
        Ok(meta) => Some(meta),
        Err(e) => {
            eprintln!("SKIP: provider not reachable at {issuer} (run `make infra-up`): {e}");
            None
        }
    }
}

/// Acquires a client-credentials access token via a raw `client_secret_basic`
/// POST to the discovered `token_endpoint`. The full `TokenClient` builder is
/// story R4.5; this keeps the JWT integration test self-contained.
async fn client_credentials_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
) -> String {
    let mut form = vec![("grant_type", "client_credentials".to_string())];
    if let Some(scope) = env_nonempty("TEST_SCOPE") {
        form.push(("scope", scope));
    }
    let resp = reqwest::Client::new()
        .post(token_endpoint)
        .basic_auth(client_id, Some(client_secret))
        .form(&form)
        .send()
        .await
        .unwrap_or_else(|e| panic!("client_credentials POST to {token_endpoint}: {e}"));
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("decode token response: {e}"));
    assert!(
        status.is_success(),
        "token endpoint returned {status}: {body}"
    );
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("token response has no access_token: {body}"))
        .to_string()
}

// AC-9 / JWT-001 / JWT-009: acquire a real client-credentials token, validate it
// end-to-end against the live JWKS, then confirm a tampered copy is rejected.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_client_credentials_validate_and_tamper() {
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
    let Some(meta) = discover_or_skip(&issuer, allow_http).await else {
        return;
    };
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );
    assert!(
        !meta.jwks_uri.is_empty(),
        "discovery returned empty jwks_uri"
    );

    let token = client_credentials_token(&meta.token_endpoint, &client_id, &client_secret).await;

    let jwks = JwksClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();

    // Happy path: the provider-signed access token verifies against the live
    // JWKS and passes issuer/exp/iat validation. The audience is the provider's
    // resource indicator (urn:test:api), which is infra-specific, so we assert
    // only the discovered issuer to avoid coupling to that value.
    let options = ValidationOptions::builder()
        .issuer(meta.issuer.as_str())
        .build();
    let claims = identity_model::validate_token_with_jwks(&token, &jwks, &meta.jwks_uri, &options)
        .await
        .unwrap_or_else(|e| panic!("validate live client-credentials token: {e}"));
    assert!(claims.expiry.is_some(), "validated token missing exp");

    // Tamper path (JWT-009): flipping the final signature character must fail
    // verification against the same live key set.
    let (head, sig) = token.rsplit_once('.').expect("three segments");
    let last = sig.chars().last().expect("non-empty signature");
    let swapped = if last == 'A' { 'B' } else { 'A' };
    let tampered = format!("{head}.{}{swapped}", &sig[..sig.len() - 1]);
    let err = identity_model::validate_token_with_jwks(&tampered, &jwks, &meta.jwks_uri, &options)
        .await
        .expect_err("tampered token must be rejected");
    assert!(
        matches!(err, IdentityError::Validation(_)),
        "err = {err:?}, want Validation for tampered signature"
    );
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
