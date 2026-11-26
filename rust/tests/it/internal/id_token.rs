//! Rust executor for the shared ID-Token profile spec vectors.
//!
//! Drives every vector in `spec/vectors/id-token.json` (`IDT-001`..`IDT-012`)
//! through the pure [`rs_identity_model::validate_id_token_claims`] — the same
//! language-neutral vector set the Python
//! (`py/src/tests/unit/test_id_token_internal.py`) and Go runners execute —
//! asserting the accept/reject outcome and, on rejects, the canonical `reason`.
//! Offline (no provider, no signature step: the vectors carry already-decoded
//! `input.claims` plus the ID-Token header `input.header_alg`), NOT
//! `#[ignore]`-gated: it runs in every bare `cargo test`.
//!
//! Thin-executor contract: only the mapping of each canonical `reason` label to
//! the crate's typed [`IdentityError`] variant lives here (`matches_reason`);
//! the inputs and expected outcomes are the shared oracle.

use rs_identity_model::{
    Claims, IdTokenValidationOptions, IdentityError, validate_id_token_claims,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const SPEC_FILE: &str = "../spec/vectors/id-token.json";

// ── Vector schema (mirrors spec/vectors/id-token.json) ──────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    #[allow(dead_code)]
    capability: String,
    #[allow(dead_code)]
    spec: String,
    #[allow(dead_code)]
    spec_url: String,
    #[allow(dead_code)]
    #[serde(default)]
    notes: String,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    #[allow(dead_code)]
    title: String,
    #[allow(dead_code)]
    given: String,
    #[allow(dead_code)]
    when: String,
    #[allow(dead_code)]
    then: String,
    #[allow(dead_code)]
    #[serde(default)]
    references: Vec<String>,
    vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestVector {
    #[serde(default)]
    name: String,
    input: Input,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    claims: Value,
    /// The ID-Token JOSE-header `alg`. `null` (missing alg) deserializes to
    /// `None`, exercising the `alg_required` fail-closed path.
    #[serde(default)]
    header_alg: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    /// Additional audiences the client trusts besides its `client_id`
    /// (§3.1.3.7 step 3). Absent means none.
    #[serde(default)]
    trusted_audiences: Option<Vec<String>>,
    /// Opts in to the `azp` rules. Absent means false.
    #[serde(default)]
    validate_azp: bool,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    /// Whether the access token was issued with the ID Token, so `at_hash` is
    /// required. Absent means true.
    #[serde(default)]
    access_token_issued_with_id_token: Option<bool>,
    #[serde(default)]
    code: Option<String>,
    /// Whether the code was issued with the ID Token, so `c_hash` is required.
    /// Absent means true.
    #[serde(default)]
    code_issued_with_id_token: Option<bool>,
    #[serde(default)]
    max_age: Option<i64>,
    #[serde(default)]
    leeway: Option<i64>,
    now: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    outcome: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    reason: String,
}

// ── Canonical-reason mapping ────────────────────────────────────────────────

/// Whether `err` is the crate's typed variant for a canonical
/// `id_token_profile` `reason` in `id-token.json`. This is the only
/// language-specific mapping in the runner.
fn matches_reason(reason: &str, err: &IdentityError) -> bool {
    let missing =
        |name: &str| matches!(err, IdentityError::MissingClaim { claim } if claim == name);
    let hash_mismatch =
        |name: &str| matches!(err, IdentityError::TokenHashMismatch { claim } if claim == name);
    match reason {
        "untrusted_audience" => {
            matches!(err, IdentityError::IdTokenUntrustedAudience(untrusted) if !untrusted.is_empty())
        }
        "missing_sub" => missing("sub"),
        "missing_aud" => missing("aud"),
        "azp_required_multi_aud" => missing("azp"),
        "azp_mismatch" => matches!(err, IdentityError::AuthorizedPartyMismatch { .. }),
        "nonce_mismatch" => matches!(err, IdentityError::NonceMismatch),
        "auth_time_stale" => matches!(err, IdentityError::MaxAgeExceeded { .. }),
        "auth_time_missing" => missing("auth_time"),
        "at_hash_missing" => missing("at_hash"),
        "at_hash_mismatch" => hash_mismatch("at_hash"),
        "c_hash_missing" => missing("c_hash"),
        "c_hash_mismatch" => hash_mismatch("c_hash"),
        "unsupported_alg" => {
            matches!(
                err,
                IdentityError::UnsupportedHashAlgorithm { alg: Some(_) }
            )
        }
        "alg_required" => matches!(err, IdentityError::UnsupportedHashAlgorithm { alg: None }),
        other => panic!("unknown canonical reason {other:?}"),
    }
}

/// The canonical family of vectors whose caller inputs are inconsistent: the
/// crate reports them as a typed configuration variant before any profile rule
/// runs.
const CONFIGURATION_ERROR: &str = "configuration";

/// Asserts `err` is the typed variant for a `configuration`-family `reason`.
fn assert_configuration_error(label: &str, reason: &str, err: &IdentityError) {
    let matched = match reason {
        "azp_requires_client_id" => matches!(err, IdentityError::IdTokenAzpRequiresClientId),
        other => panic!("{label}: unknown configuration reason {other:?}"),
    };
    assert!(
        matched,
        "{label}: expected configuration error {reason:?}, got {err:?}"
    );
}

fn options_for(input: &Input) -> IdTokenValidationOptions {
    let mut b = IdTokenValidationOptions::builder().now(input.now);
    if let Some(client_id) = &input.client_id {
        b = b.client_id(client_id);
    }
    if let Some(trusted) = &input.trusted_audiences {
        b = b.trusted_audiences(trusted);
    }
    b = b.validate_azp(input.validate_azp);
    if let Some(nonce) = &input.nonce {
        b = b.nonce(nonce);
    }
    if let Some(access_token) = &input.access_token {
        b = b.access_token(access_token);
    }
    if let Some(issued) = input.access_token_issued_with_id_token {
        b = b.access_token_issued_with_id_token(issued);
    }
    if let Some(code) = &input.code {
        b = b.code(code);
    }
    if let Some(issued) = input.code_issued_with_id_token {
        b = b.code_issued_with_id_token(issued);
    }
    if let Some(max_age) = input.max_age {
        b = b.max_age(max_age);
    }
    if let Some(leeway) = input.leeway {
        b = b.leeway(Duration::from_secs(
            u64::try_from(leeway).expect("non-negative leeway"),
        ));
    }
    b.build()
}

#[test]
fn spec_id_token_internal() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read id-token.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse id-token.json");

    // Per-case vector counts, incremented only after a vector passes — a panic
    // ends the test, so a red vector is never counted.
    let mut executed = 0usize;
    let mut executed_vectors: BTreeMap<String, usize> = BTreeMap::new();
    for case in &capability.tests {
        assert!(!case.vectors.is_empty(), "{}: no vectors", case.id);
        for (idx, vector) in case.vectors.iter().enumerate() {
            let label = if vector.name.is_empty() {
                format!("{}[{idx}]", case.id)
            } else {
                format!("{} ({})", case.id, vector.name)
            };

            // The vectors carry already-decoded claim sets: build typed Claims
            // with no network or signature step (the offline profile entry).
            let claims = Claims::from_json(vector.input.claims.clone())
                .unwrap_or_else(|e| panic!("{label}: build claims: {e}"));
            let options = options_for(&vector.input);
            let result =
                validate_id_token_claims(&claims, vector.input.header_alg.as_deref(), &options);

            match vector.expect.outcome.as_str() {
                "accept" => {
                    result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
                }
                "reject" => {
                    let err = result.expect_err(&format!(
                        "{label}: expected reject ({})",
                        vector.expect.reason
                    ));
                    if vector.expect.error == CONFIGURATION_ERROR {
                        assert_configuration_error(&label, &vector.expect.reason, &err);
                    } else {
                        assert_eq!(
                            vector.expect.error, "id_token_profile",
                            "{label}: unexpected canonical error family {:?}",
                            vector.expect.error
                        );
                        assert!(
                            matches_reason(&vector.expect.reason, &err),
                            "{label}: rejection {err:?} does not match reason {:?}",
                            vector.expect.reason
                        );
                    }
                }
                other => panic!("{label}: unknown expected outcome {other:?}"),
            }
            executed += 1;
            *executed_vectors.entry(case.id.clone()).or_insert(0) += 1;
        }
        assert_eq!(
            executed_vectors.get(&case.id).copied().unwrap_or(0),
            case.vectors.len(),
            "{}: ran {} of {} vectors",
            case.id,
            executed_vectors.get(&case.id).copied().unwrap_or(0),
            case.vectors.len()
        );
    }

    // Cross-language parity: every vector the spec carries must have executed.
    // Derived from the spec rather than hardcoded, so adding or removing a
    // vector does not leave a stale literal asserting the old total.
    let total: usize = capability.tests.iter().map(|c| c.vectors.len()).sum();
    assert_eq!(
        executed, total,
        "expected all {total} shared id-token vectors to execute, ran {executed}"
    );
}
