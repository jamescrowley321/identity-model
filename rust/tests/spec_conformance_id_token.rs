//! Rust executor for the shared ID-Token profile conformance vectors.
//!
//! Drives every vector in `spec/vectors/id-token.json` (`IDT-001`..`IDT-011`)
//! through the pure [`rs_identity_model::validate_id_token_claims`] — the same
//! language-neutral vector set the Python
//! (`py/src/tests/unit/test_id_token_conformance.py`) and Go runners execute —
//! asserting the accept/reject outcome and, on rejects, the canonical `reason`.
//! Offline (no provider, no signature step: the vectors carry already-decoded
//! `input.claims` plus the ID-Token header `input.header_alg`), NOT
//! `#[ignore]`-gated: it runs in every bare `cargo test`.
//!
//! Thin-executor contract: only the mapping of each canonical `reason` label to
//! the crate's stable [`IdentityError::IdTokenValidation`] message shape lives
//! here (`reason_marker`); the inputs and expected outcomes are the shared
//! oracle.
//!
//! Deliberately NOT wired into `tools/spec_coverage_gate.py`: `id-token.json`
//! carries `cross_language_coverage_gate: "pending"`, so promotion into the
//! enforcement gate is Epic 23 §23.2. This runs as an ordinary Rust test.

use rs_identity_model::{
    Claims, IdTokenValidationOptions, IdentityError, validate_id_token_claims,
};
use serde::Deserialize;
use serde_json::Value;
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
    cross_language_coverage_gate: String,
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
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    code: Option<String>,
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

/// The distinctive substring the crate's [`IdentityError::IdTokenValidation`]
/// message carries for each canonical `reason` in `id-token.json`. This is the
/// only language-specific mapping in the runner.
fn reason_marker(reason: &str) -> &'static str {
    match reason {
        "missing_sub" => "required 'sub'",
        "azp_required_multi_aud" => "multiple audiences must contain an 'azp'",
        "azp_mismatch" => "'azp' claim does not match",
        "nonce_mismatch" => "'nonce' claim does not match",
        "auth_time_stale" => "'auth_time' is older than",
        "auth_time_missing" => "missing required numeric 'auth_time'",
        "at_hash_mismatch" => "'at_hash' claim does not match",
        "c_hash_mismatch" => "'c_hash' claim does not match",
        "unsupported_alg" => "Unsupported ID token 'alg'",
        "alg_required" => "header 'alg' is required",
        other => panic!("unknown canonical reason {other:?}"),
    }
}

fn options_for(input: &Input) -> IdTokenValidationOptions {
    let mut b = IdTokenValidationOptions::builder().now(input.now);
    if let Some(client_id) = &input.client_id {
        b = b.client_id(client_id);
    }
    if let Some(nonce) = &input.nonce {
        b = b.nonce(nonce);
    }
    if let Some(access_token) = &input.access_token {
        b = b.access_token(access_token);
    }
    if let Some(code) = &input.code {
        b = b.code(code);
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
fn spec_id_token_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read id-token.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse id-token.json");

    let mut executed = 0usize;
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
                    assert_eq!(
                        vector.expect.error, "id_token_profile",
                        "{label}: unexpected canonical error family {:?}",
                        vector.expect.error
                    );
                    let IdentityError::IdTokenValidation(msg) = &err else {
                        panic!("{label}: expected IdTokenValidation, got {err:?}");
                    };
                    let marker = reason_marker(&vector.expect.reason);
                    assert!(
                        msg.contains(marker),
                        "{label}: rejection {msg:?} does not match reason {:?} (marker {marker:?})",
                        vector.expect.reason
                    );
                }
                other => panic!("{label}: unknown expected outcome {other:?}"),
            }
            executed += 1;
        }
    }

    // Cross-language parity: every shared vector must have executed. The Python
    // and Go runners drive the same 30-vector oracle; this count guards against
    // a silently skipped case.
    assert_eq!(
        executed, 30,
        "expected all 30 shared id-token vectors to execute, ran {executed}"
    );
}
