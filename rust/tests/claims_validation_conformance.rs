//! Conformance runner for the cross-language injectable claims-validator vectors
//! (`spec/test-fixtures/claims-validation/vectors.json`, issue #603).
//!
//! One shared vector set drives the Python (#623), Go (#624), and Rust (#625)
//! implementations so all three agree on the *accept / reject / construction-
//! error* outcome and the offending claim a rejection names. The rejection
//! *reason* wording is language-specific and intentionally not asserted.
//!
//! This runner reads the bespoke vector file directly — it is deliberately *not*
//! routed through the generic `spec_conformance.rs` machinery — parses it with
//! `serde_json`, builds each validator from its `validator` spec, and runs it
//! against the case `claims`.
//!
//! ## How a `Claims` value is obtained
//!
//! Rust models a decoded claim set as the typed [`rs_identity_model::Claims`],
//! whose only public constructor is the real validation pipeline
//! ([`rs_identity_model::validate_token`]) — `Claims::from_value` is
//! crate-private and the type is not `Deserialize`. So, mirroring
//! `tests/claims_validation.rs`, each case's `claims` object is minted into a
//! genuinely signed RS256 token (with the shared `spec/test-fixtures/validation`
//! key, augmented with `iat`/`exp` so the standard registered-claim checks pass)
//! and decoded back into a `Claims`; the built validator is then run against that
//! value in isolation. No issuer/audience is configured, so only the injected
//! validator can reject a decoded token. The construction-error cases carry no
//! `claims` and exercise only the constructor.
//!
//! ## One language-specific divergence (documented, conformant on outcome)
//!
//! Rust's typed `Claims` cannot represent a present-but-`null` *registered*
//! string claim: a token carrying `sub: null` (vector CLV-003) is rejected by the
//! typed decode (`claim "sub" ... must be a string`) *before* the claims
//! validator runs. That is a fail-closed rejection at an earlier layer that still
//! names `sub`, so the vector's contract (reject, naming the claim) holds — the
//! runner accepts a decode-layer rejection that names the expected claim. For
//! *unregistered* claims (and even `aud: null`) `require_claims` performs the
//! present-but-null → missing check itself, exactly as the contract requires (see
//! the inline unit tests in `src/jwt/claims_validation.rs`).

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rs_identity_model::{
    BoxedClaimsValidator, Claims, CombineMode, IdentityError, JsonWebKey, ValidationOptions, boxed,
    combine_claims_validators, require_claim_value, require_claims, require_scopes, validate_token,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

const VECTORS_FILE: &str = "../spec/test-fixtures/claims-validation/vectors.json";
const FIXTURE_DIR: &str = "../spec/test-fixtures/validation";
const FIXTURE_KID: &str = "test-key-1";

// --- vector model ------------------------------------------------------------

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    validator: Value,
    #[serde(default)]
    claims: Value,
    expect: Expect,
}

#[derive(Deserialize)]
struct Expect {
    #[serde(default)]
    accept: Option<bool>,
    #[serde(default)]
    reject: Option<Reject>,
    #[serde(default)]
    construction_error: Option<bool>,
}

#[derive(Deserialize)]
struct Reject {
    #[serde(default)]
    claim: Option<String>,
}

// --- fixture helpers (mirroring tests/claims_validation.rs) -------------------

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURE_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

fn signing_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&read_fixture("signing-key.pkcs1.der"))
}

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

/// Mints a genuinely signed RS256 token (`kid=test-key-1`) carrying `claims`.
fn mint(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(FIXTURE_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
}

/// Decodes a vector `claims` object into a typed [`Claims`] through the real
/// pipeline. The object is augmented with `iat`/`exp` (only when absent) so the
/// standard registered-claim checks pass; no issuer/audience is configured, so
/// only the separately-run injected validator can reject a decoded token.
/// Returns the decode error when the typed claim set itself refuses the payload
/// (e.g. a `null` registered string claim — see the module divergence note).
fn decode_claims(claims: &Value) -> Result<Claims, IdentityError> {
    let mut obj: Map<String, Value> = claims.as_object().cloned().unwrap_or_default();
    let n = now();
    obj.entry("iat").or_insert_with(|| json!(n - 5));
    obj.entry("exp").or_insert_with(|| json!(n + 3600));
    validate_token(
        &mint(Value::Object(obj)),
        &public_key(),
        &ValidationOptions::new(),
    )
}

// --- validator construction from a spec --------------------------------------

/// Reads a JSON array of strings (e.g. `names` / `scopes`); a missing array
/// yields the empty vec, which the `require_*` constructors reject as a
/// construction error.
fn str_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| {
            v.as_str()
                .expect("names/scopes entries are strings")
                .to_string()
        })
        .collect()
}

/// Builds a validator from its vector `spec`, returning `Err` when the spec is a
/// construction error (an unknown combinator mode or an empty required set) — the
/// idiomatic Rust equivalent of the shared contract's "construction error", which
/// the other languages surface from a fallible constructor. Child construction
/// errors propagate out of a `combine`.
fn build(spec: &Value) -> Result<BoxedClaimsValidator, String> {
    let ty = spec["type"]
        .as_str()
        .ok_or("validator spec missing `type`")?;
    match ty {
        "require_claims" => require_claims(str_vec(&spec["names"]))
            .map(boxed)
            .map_err(|e| e.to_string()),
        "require_claim_value" => {
            let name = spec["name"]
                .as_str()
                .ok_or("require_claim_value missing `name`")?
                .to_string();
            Ok(boxed(require_claim_value(name, spec["value"].clone())))
        }
        "require_scopes" => require_scopes(str_vec(&spec["scopes"]))
            .map(boxed)
            .map_err(|e| e.to_string()),
        "combine" => {
            let mode = match spec["require"].as_str() {
                Some("all") => CombineMode::All,
                Some("any") => CombineMode::Any,
                // An unknown `require` mode has no representation in Rust's
                // `CombineMode` enum, so it is a construction error — matching the
                // Python/Go string-validated `require`.
                other => return Err(format!("unknown combine mode: {other:?}")),
            };
            let mut members = Vec::new();
            for member in spec["of"].as_array().ok_or("combine missing `of` array")? {
                members.push(build(member)?);
            }
            combine_claims_validators(members, mode)
                .map(boxed)
                .map_err(|e| e.to_string())
        }
        other => Err(format!("unknown validator type: {other}")),
    }
}

// --- the runner ---------------------------------------------------------------

#[test]
fn claims_validation_conformance_vectors() {
    let raw = std::fs::read_to_string(VECTORS_FILE).expect("read claims-validation vectors");
    let vectors: Vectors = serde_json::from_str(&raw).expect("parse vectors.json");
    assert!(!vectors.cases.is_empty(), "vector file declares no cases");

    for case in &vectors.cases {
        let id = &case.id;

        // construction_error: building the validator itself must fail; no claims.
        if case.expect.construction_error == Some(true) {
            assert!(
                build(&case.validator).is_err(),
                "{id}: expected a construction error, but the validator built successfully"
            );
            continue;
        }

        let validator = build(&case.validator).unwrap_or_else(|e| {
            panic!("{id}: validator should build, but construction failed: {e}")
        });
        let decoded = decode_claims(&case.claims);

        // accept: the claims must decode and the validator must accept them.
        if case.expect.accept == Some(true) {
            let claims = decoded
                .unwrap_or_else(|e| panic!("{id}: claims should decode for an accept case: {e}"));
            validator.validate(&claims).unwrap_or_else(|e| {
                panic!("{id}: expected accept, but the validator rejected: {e}")
            });
            continue;
        }

        // reject: the token must be refused; when the vector names a claim, the
        // rejection must name exactly that claim.
        let expected = case.expect.reject.as_ref().unwrap_or_else(|| {
            panic!("{id}: expectation is neither accept, reject, nor construction_error")
        });

        match decoded {
            // Fail-closed at the typed-decode layer (e.g. `sub: null`): a
            // rejection that still names the claim satisfies the contract.
            Err(decode_err) => {
                if let Some(claim) = &expected.claim {
                    assert!(
                        decode_err.to_string().contains(claim.as_str()),
                        "{id}: decode-layer rejection {decode_err:?} does not name claim {claim:?}"
                    );
                }
            }
            Ok(claims) => {
                let err = match validator.validate(&claims) {
                    Ok(()) => panic!("{id}: expected the validator to reject"),
                    Err(e) => e,
                };
                match err {
                    IdentityError::ClaimsValidation { claim, .. } => {
                        if let Some(expected_claim) = &expected.claim {
                            assert_eq!(
                                claim.as_deref(),
                                Some(expected_claim.as_str()),
                                "{id}: rejection named the wrong claim"
                            );
                        }
                    }
                    other => panic!("{id}: expected a ClaimsValidation rejection, got {other:?}"),
                }
            }
        }
    }
}
