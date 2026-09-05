//! Example: compose ready-made claims validators with `combine_claims_validators`
//! and run the result through the real token-validation pipeline.
//!
//! Demonstrates the injectable, composable claims-validator API (issue #603):
//! after the signature, algorithm-allowlist, and registered-claim checks pass,
//! [`validate_token`] runs a caller-supplied policy over the decoded claims. Here
//! the policy is built by *combining* [`require_claims`], [`require_scopes`], and
//! [`require_claim_value`] — the same portable building blocks the Python and Go
//! libraries ship — with [`combine_claims_validators`].
//!
//! It signs short-lived demo tokens with the shared `spec/test-fixtures/validation`
//! key (an `http://`-free, offline demonstration — no provider required):
//!
//! ```text
//! cargo run --example combined_claims_validator
//! ```

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rs_identity_model::{
    CombineMode, IdentityError, JsonWebKey, ValidationOptions, boxed, combine_claims_validators,
    require_claim_value, require_claims, require_scopes, validate_token,
};
use serde_json::{Value, json};

/// The shared fixtures live next to the crate, resolved at compile time so the
/// example runs from any working directory within the repo checkout.
const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/test-fixtures/validation"
);
const KID: &str = "test-key-1";
const ISSUER: &str = "https://issuer.example.com";
const AUDIENCE: &str = "demo-client";

fn signing_key() -> EncodingKey {
    let der = std::fs::read(format!("{FIXTURE_DIR}/signing-key.pkcs1.der"))
        .expect("read signing-key fixture");
    EncodingKey::from_rsa_der(&der)
}

fn public_key() -> JsonWebKey {
    let bytes = std::fs::read(format!("{FIXTURE_DIR}/jwks.json")).expect("read jwks fixture");
    let jwks: Value = serde_json::from_slice(&bytes).expect("parse jwks fixture");
    serde_json::from_value(jwks["keys"][0].clone()).expect("deserialize fixture key")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// Mints a genuinely signed RS256 token: a valid baseline (`iss`/`aud`/`sub`/
/// `iat`/`exp`) merged with the caller-supplied `extra` claims.
fn mint(extra: Value) -> String {
    let n = now();
    let mut claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "iat": n - 5,
        "exp": n + 3600,
    });
    let map = claims
        .as_object_mut()
        .expect("baseline claims are an object");
    for (key, value) in extra.as_object().expect("extra claims are an object") {
        map.insert(key.clone(), value.clone());
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
}

fn main() {
    let key = public_key();

    // combine(All): every member must accept, in order, failing fast on the
    // first rejection. Policy: the token must carry `sub` AND grant `read`.
    let all_policy = combine_claims_validators(
        [
            boxed(require_claims(["sub"]).expect("names supplied")),
            boxed(require_scopes(["read"]).expect("scopes supplied")),
        ],
        CombineMode::All,
    )
    .expect("non-empty all");
    let all_opts = ValidationOptions::builder()
        .issuer(ISSUER)
        .audience(AUDIENCE)
        .claims_validator(all_policy)
        .build();

    println!("== combine(All): require `sub` AND the `read` scope ==");
    match validate_token(&mint(json!({ "scope": "read openid" })), &key, &all_opts) {
        Ok(claims) => println!(
            "  accepted: sub={:?}, scope={:?}",
            claims.subject,
            claims.get_str("scope")
        ),
        Err(e) => println!("  unexpectedly rejected: {e}"),
    }
    match validate_token(&mint(json!({ "scope": "openid" })), &key, &all_opts) {
        Ok(_) => println!("  unexpectedly accepted"),
        Err(IdentityError::ClaimsValidation { reason, claim }) => {
            println!("  rejected (claim={claim:?}): {reason}");
        }
        Err(e) => println!("  rejected with a non-claims error: {e}"),
    }

    // combine(Any): at least one member must accept; if every member rejects the
    // reasons are aggregated. Policy: an `admin` role OR the `read` scope.
    let any_policy = combine_claims_validators(
        [
            boxed(require_claim_value("role", "admin")),
            boxed(require_scopes(["read"]).expect("scopes supplied")),
        ],
        CombineMode::Any,
    )
    .expect("non-empty any");
    let any_opts = ValidationOptions::builder()
        .issuer(ISSUER)
        .audience(AUDIENCE)
        .claims_validator(any_policy)
        .build();

    println!("== combine(Any): the `admin` role OR the `read` scope ==");
    match validate_token(
        &mint(json!({ "role": "user", "scope": "read" })),
        &key,
        &any_opts,
    ) {
        Ok(claims) => println!(
            "  accepted a non-admin reader via the read scope: role={:?}",
            claims.get_str("role")
        ),
        Err(e) => println!("  unexpectedly rejected: {e}"),
    }
    match validate_token(
        &mint(json!({ "role": "user", "scope": "openid" })),
        &key,
        &any_opts,
    ) {
        Ok(_) => println!("  unexpectedly accepted"),
        Err(e) => println!("  rejected (neither admin nor read-scoped): {e}"),
    }

    // The combinators and required-set constructors fail closed at construction.
    println!("== construction guards ==");
    assert!(require_scopes(Vec::<String>::new()).is_err());
    assert!(combine_claims_validators(Vec::new(), CombineMode::Any).is_err());
    println!("  require_scopes([]) and combine(Any, []) are rejected at construction");
}
