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
//! The live counterpart, driving the same hook through
//! [`rs_identity_model::validate_token_with_jwks`] against a provider-issued
//! token, is `live::claims_validation`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rs_identity_model::{
    CombineMode, IdentityError, JwksClient, ValidationOptions, boxed, combine_claims_validators,
    from_fn, require_claim_value, require_claims, require_scopes, validate_token,
    validate_token_with_jwks,
};
use serde_json::json;

use crate::common::fixtures::{mint, now_unix, public_key, read_fixture};

const TEST_ISSUER: &str = "https://issuer.example.com";
const TEST_AUDIENCE: &str = "test-client";

/// A genuinely valid token: correct signature, issuer, audience, iat/exp, and a
/// `read` scope.
fn valid_token() -> String {
    let n = now_unix();
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

// Regression through the real pipeline: a genuinely signed token whose `aud` is
// JSON null is rejected by require_claims(["aud"]). With no expected audience the
// standard aud/azp checks are skipped, so the token passes signature/iss/exp and
// only the injected validator rejects it — proving the aud:null fail-open is
// closed end-to-end (not just in a unit).
#[test]
fn require_claims_rejects_null_aud_through_pipeline() {
    let n = now_unix();
    let token = mint(json!({
        "iss": TEST_ISSUER,
        "sub": "user-1",
        "aud": null,
        "exp": n + 3600,
        "iat": n - 5,
    }));
    let opts = ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .claims_validator(require_claims(["aud"]).expect("names supplied"))
        .build();
    let err = validate_token(&token, &public_key(), &opts).expect_err("aud:null rejected");
    match err {
        IdentityError::ClaimsValidation { claim, .. } => assert_eq!(claim.as_deref(), Some("aud")),
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

    let n = now_unix();
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

// Ordering guarantee vs signature verification: a token whose signature is
// tampered is rejected before the injected validator is consulted, so the spy
// never fires. Complements the expired-token test (which only proves ordering
// vs the registered-claim checks) by proving the hook runs *after* the crypto.
#[test]
fn validator_not_invoked_when_signature_fails() {
    let invoked = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&invoked);
    let spy = from_fn(move |_claims: &_| {
        flag.store(true, Ordering::SeqCst);
        Ok(())
    });
    let opts = ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .audience(TEST_AUDIENCE)
        .claims_validator(spy)
        .build();

    // Flip the final character of the signature segment of an otherwise-valid
    // token.
    let token = valid_token();
    let (head, sig) = token.rsplit_once('.').expect("three segments");
    let last = sig.chars().last().expect("non-empty signature");
    let swapped = if last == 'A' { 'B' } else { 'A' };
    let tampered = format!("{head}.{}{swapped}", &sig[..sig.len() - 1]);

    let err =
        validate_token(&tampered, &public_key(), &opts).expect_err("tampered signature rejected");
    assert!(err.to_string().contains("signature"), "{err}");
    assert!(
        !invoked.load(Ordering::SeqCst),
        "claims validator must not run when signature verification fails"
    );
}

// The `validate_token_with_jwks` delegation path carries the injected validator.
// Offline: a mock server serves the JWKS fixture, so the resolve-key -> verify ->
// validate -> injected-validator chain runs in plain `cargo test` (no live
// provider), unlike the `#[ignore]` live leg below. A passing validator accepts;
// a rejecting one surfaces the structured error after the real JWKS fetch and
// signature verification.
#[tokio::test]
async fn injected_validator_runs_through_jwks_delegation() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let jwks_body = String::from_utf8(read_fixture("jwks.json")).expect("utf8 jwks fixture");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_body))
        .mount(&server)
        .await;
    let jwks_uri = format!("{}/jwks", server.uri());

    let jwks = JwksClient::builder()
        .allow_http(true)
        .timeout(Duration::from_secs(5))
        .build();
    let token = valid_token();

    // Passing: the token (kid=test-key-1) resolves against the mock JWKS, its
    // signature verifies, and the injected read-scope validator accepts.
    let accept = ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .audience(TEST_AUDIENCE)
        .claims_validator(require_scopes(["read"]).expect("scopes supplied"))
        .build();
    let claims = validate_token_with_jwks(&token, &jwks, &jwks_uri, &accept)
        .await
        .expect("passing validator via jwks delegation");
    assert_eq!(claims.subject.as_deref(), Some("user-1"));

    // Rejecting: the same delegation path carries a rejecting validator, which
    // fires only after the live signature/JWKS work succeeds.
    let reject = ValidationOptions::builder()
        .issuer(TEST_ISSUER)
        .audience(TEST_AUDIENCE)
        .claims_validator(require_scopes(["admin"]).expect("scopes supplied"))
        .build();
    let err = validate_token_with_jwks(&token, &jwks, &jwks_uri, &reject)
        .await
        .expect_err("missing admin scope rejected via jwks delegation");
    match err {
        IdentityError::ClaimsValidation { reason, claim } => {
            assert!(reason.contains("admin"), "{reason}");
            assert_eq!(claim.as_deref(), Some("scope"));
        }
        other => panic!("expected ClaimsValidation via jwks delegation, got {other:?}"),
    }
}
