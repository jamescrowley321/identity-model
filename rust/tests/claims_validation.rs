//! Integration tests for the injectable, composable claims validators
//! (issue #603; Rust port of the Python foundation #623).
//!
//! These exercise the validators through the crate's *real* validation path —
//! [`rs_identity_model::validate_token`] — against genuinely signed tokens, from
//! a downstream crate's vantage point. The token is minted with the shared
//! `spec/test-fixtures/validation` signing key and verified against the matching
//! public key, so the injected validator provably runs only *after* the
//! signature, algorithm-allowlist, and registered-claim checks pass (the inline
//! unit tests in `src/jwt/claims_validation.rs` cover the validators in
//! isolation; these prove the pipeline wiring).
//!
//! The `#[ignore]`-gated `integration_*` tests additionally drive the validator
//! through [`rs_identity_model::validate_token_with_jwks`] against the live
//! `infra/` node-oidc provider, following the same convention as
//! `tests/jwt_validation.rs`:
//!
//! ```text
//! make infra-up
//! make test-integration-rust      # or: cd rust && cargo test -- --ignored
//! make infra-down
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rs_identity_model::{
    CombineMode, DiscoveryClient, IdentityError, JsonWebKey, JwksClient, ProviderMetadata,
    ValidationOptions, boxed, combine_claims_validators, from_fn, require_claim_value,
    require_claims, require_scopes, validate_token, validate_token_with_jwks,
};
use serde_json::{Value, json};

const FIXTURE_DIR: &str = "../spec/test-fixtures/validation";
const FIXTURE_KID: &str = "test-key-1";
const TEST_ISSUER: &str = "https://issuer.example.com";
const TEST_AUDIENCE: &str = "test-client";

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURE_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// The RS256 signing key from the shared fixture (its PKCS#1 DER form), so the
/// integration test signs with the same material as the other languages without
/// pulling the `rsa` crate (RUSTSEC-2023-0071).
fn signing_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&read_fixture("signing-key.pkcs1.der"))
}

/// The public verification key that matches [`signing_key`], resolved from the
/// JWKS fixture.
fn public_key() -> JsonWebKey {
    let jwks: Value =
        serde_json::from_slice(&read_fixture("jwks.json")).expect("parse jwks fixture");
    serde_json::from_value(jwks["keys"][0].clone()).expect("deserialize fixture key")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// Mints an RS256 token (`kid=test-key-1`) carrying `claims`.
fn mint(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(FIXTURE_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
}

/// A genuinely valid token: correct signature, issuer, audience, iat/exp, and a
/// `read` scope.
fn valid_token() -> String {
    let n = now();
    mint(json!({
        "iss": TEST_ISSUER,
        "sub": "user-1",
        "aud": TEST_AUDIENCE,
        "scope": "read openid",
        "exp": n + 3600,
        "iat": n - 5,
    }))
}

/// Options that pass the standard checks for [`valid_token`], with `validator`
/// injected as the claims-validation hook.
fn options_with<V>(validator: V) -> ValidationOptions
where
    V: rs_identity_model::ClaimsValidator + 'static,
{
    ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .audience(TEST_AUDIENCE)
        .claims_validator(validator)
        .build()
}

// A passing validator lets a genuinely valid token through the whole pipeline
// and the decoded claims are returned.
#[test]
fn passing_validator_accepts_real_token() {
    let opts = options_with(require_scopes(["read"]).expect("scopes supplied"));
    let claims =
        validate_token(&valid_token(), &public_key(), &opts).expect("valid token accepted");
    assert_eq!(claims.subject.as_deref(), Some("user-1"));
    assert_eq!(claims.issuer.as_deref(), Some(TEST_ISSUER));
}

// The token is genuinely valid (signature / aud / iss / exp all pass) — only the
// injected claims validator rejects it, proving the hook runs in the real
// pipeline. The rejection surfaces as a structured ClaimsValidation error.
#[test]
fn rejecting_validator_rejects_after_standard_checks() {
    let opts = options_with(require_scopes(["admin"]).expect("scopes supplied"));
    let err = validate_token(&valid_token(), &public_key(), &opts)
        .expect_err("missing admin scope rejected");
    match err {
        IdentityError::ClaimsValidation { reason, claim } => {
            assert!(reason.contains("admin"), "{reason}");
            assert_eq!(claim.as_deref(), Some("scope"));
        }
        other => panic!("expected ClaimsValidation, got {other:?}"),
    }
}

// A composed validator runs through the real pipeline: require sub, pin iss, and
// require the read scope — all satisfied by the valid token.
#[test]
fn combined_validators_through_real_pipeline() {
    let combined = combine_claims_validators(
        [
            boxed(require_claims(["sub"]).expect("names supplied")),
            boxed(require_claim_value("iss", TEST_ISSUER)),
            boxed(require_scopes(["read"]).expect("scopes supplied")),
        ],
        CombineMode::All,
    )
    .expect("non-empty all");
    let opts = options_with(combined);
    let claims = validate_token(&valid_token(), &public_key(), &opts).expect("all validators pass");
    assert_eq!(claims.get_str("scope"), Some("read openid"));
}

// A rejection carries the specific reason (the missing claim name), even though
// it propagates as the crate's structured error.
#[test]
fn rejection_surfaces_structured_reason() {
    let opts = options_with(require_claims(["nonexistent_claim"]).expect("names supplied"));
    let err = validate_token(&valid_token(), &public_key(), &opts)
        .expect_err("missing required claim rejected");
    match err {
        IdentityError::ClaimsValidation { reason, claim } => {
            assert!(reason.contains("nonexistent_claim"), "{reason}");
            assert_eq!(claim.as_deref(), Some("nonexistent_claim"));
        }
        other => panic!("expected ClaimsValidation, got {other:?}"),
    }
}

// Ordering guarantee: the injected validator runs only *after* the standard
// checks. An expired token is rejected by the registered-claim check before the
// validator is ever consulted, so its side effect never fires.
#[test]
fn validator_not_invoked_when_standard_checks_fail() {
    let invoked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&invoked);
    let spy = from_fn(move |_claims: &_| {
        flag.store(true, Ordering::SeqCst);
        Ok(())
    });
    let opts = ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .claims_validator(spy)
        .build();

    let n = now();
    let expired = mint(json!({ "iss": TEST_ISSUER, "exp": n - 3600, "iat": n - 7200 }));
    let err = validate_token(&expired, &public_key(), &opts).expect_err("expired token rejected");
    assert!(err.to_string().contains("expired"), "{err}");
    assert!(
        !invoked.load(Ordering::SeqCst),
        "claims validator must not run when the standard checks fail"
    );
}

// A validator that returns a non-ClaimsValidation error propagates that error
// unchanged through the pipeline rather than being reshaped into a generic
// validation failure.
#[test]
fn non_claims_error_from_validator_propagates() {
    let opts = options_with(from_fn(|_claims: &_| {
        Err(IdentityError::Configuration(
            "policy backend unavailable".to_string(),
        ))
    }));
    let err =
        validate_token(&valid_token(), &public_key(), &opts).expect_err("validator error surfaces");
    assert!(
        matches!(err, IdentityError::Configuration(_)),
        "err = {err:?}, want the validator's own Configuration error"
    );
}

// --- live legs (mirroring tests/jwt_validation.rs) --------------------------

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// Prints a SKIP marker unless `TEST_REQUIRE_LIVE=1`, in which case it panics
/// (mechanical-gate rule: the CI leg that booted the fixture must go red, not
/// green-skip, if the provider is unreachable).
fn skip_or_fail(msg: &str) {
    if std::env::var("TEST_REQUIRE_LIVE").as_deref() == Ok("1") {
        panic!("TEST_REQUIRE_LIVE=1 but {msg}");
    }
    eprintln!("SKIP: {msg}");
}

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

fn env_nonempty(name: &str) -> Option<String> {
    let v = std::env::var(name).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

async fn discover_or_skip(issuer: &str, allow_http: bool) -> Option<ProviderMetadata> {
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    match discovery.discover(issuer).await {
        Ok(meta) => Some(meta),
        Err(e) => {
            skip_or_fail(&format!(
                "provider not reachable at {issuer} (run `make infra-up`): {e}"
            ));
            None
        }
    }
}

/// Acquires a client-credentials access token via a raw `client_secret_basic`
/// POST to the discovered `token_endpoint` (as `tests/jwt_validation.rs` does).
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

/// Discovers the live provider and acquires a real client-credentials token,
/// returning `None` (after a SKIP) when the profile/provider is unavailable.
async fn live_token_and_meta() -> Option<(String, ProviderMetadata, JwksClient)> {
    let issuer = issuer_from_env()?;
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_CLIENT_ID"),
        env_nonempty("TEST_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_CLIENT_ID/TEST_CLIENT_SECRET unset for this provider profile");
        return None;
    };
    let allow_http = issuer.starts_with("http://");
    let meta = discover_or_skip(&issuer, allow_http).await?;
    let token = client_credentials_token(&meta.token_endpoint, &client_id, &client_secret).await;
    let jwks = JwksClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    Some((token, meta, jwks))
}

// A real, provider-signed token validates through the live JWKS/discovery path
// with a passing injected claims validator; the same pipeline with a rejecting
// validator surfaces the structured ClaimsValidation error *after* the live
// signature/issuer checks pass.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_injected_validator_through_live_pipeline() {
    let Some((token, meta, jwks)) = live_token_and_meta().await else {
        return;
    };

    // Passing: every provider-issued access token carries iss; require it.
    let accept = ValidationOptions::builder()
        .issuer(meta.issuer.as_str())
        .claims_validator(require_claims(["iss"]).expect("names supplied"))
        .build();
    let claims = validate_token_with_jwks(&token, &jwks, &meta.jwks_uri, &accept)
        .await
        .unwrap_or_else(|e| panic!("passing validator through live pipeline: {e}"));
    assert!(claims.expiry.is_some(), "validated token missing exp");

    // Rejecting: a claim the token cannot carry forces a structured rejection,
    // proving the hook ran after the live signature/issuer checks passed.
    let reject = ValidationOptions::builder()
        .issuer(meta.issuer.as_str())
        .claims_validator(require_claims(["definitely_absent_claim"]).expect("names supplied"))
        .build();
    let err = validate_token_with_jwks(&token, &jwks, &meta.jwks_uri, &reject)
        .await
        .expect_err("absent required claim must be rejected");
    match err {
        IdentityError::ClaimsValidation { reason, claim } => {
            assert!(reason.contains("definitely_absent_claim"), "{reason}");
            assert_eq!(claim.as_deref(), Some("definitely_absent_claim"));
        }
        other => panic!("expected ClaimsValidation from live pipeline, got {other:?}"),
    }
}
