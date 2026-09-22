//! Injectable claims validators through the live JWKS/discovery path.
//!
//! `local::claims_validation` proves the validator hook is wired into the real
//! validation pipeline with locally minted tokens. This leg drives the same hook
//! through [`rs_identity_model::validate_token_with_jwks`] against a token the
//! live provider actually issued and signed, so the hook is shown to run after
//! a live signature and issuer check, not just after ones this suite staged.

use std::time::Duration;

use rs_identity_model::{
    IdentityError, JwksClient, ProviderMetadata, ValidationOptions, require_claims,
    validate_token_with_jwks,
};

use crate::common::env::{env_nonempty, issuer_from_env, skip_or_fail};
use crate::common::live::{client_credentials_token, discover_or_skip};

/// Discovers the live provider and acquires a real client-credentials token,
/// returning `None` (after a SKIP) when the profile/provider is unavailable.
async fn live_token_and_meta() -> Option<(String, ProviderMetadata, JwksClient)> {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return None;
    };
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
async fn injected_validator_through_live_pipeline() {
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
