//! Thin Rust executor for the shared `/spec` conformance vectors (CONS-1.5).
//!
//! Drives every executable vector in `spec/vectors/validation.json`
//! against [`rs_identity_model::validate_token`] — the same language-neutral
//! vector set the Go (`go/internal/conformance`) and Python
//! (`src/tests/unit/test_spec_conformance.py`) runners execute — so the
//! "build conformance vectors once" constraint holds. Offline (no provider),
//! NOT `#[ignore]`-gated: it runs in every bare `cargo test`.
//!
//! Thin-executor contract: the vectors carry inputs and canonical expected
//! outcomes; only the mapping of canonical error codes to
//! [`IdentityError::Validation`] message shapes lives here (`assert_reject`).
//!
//! Two deliberate deviations from the Go runner, both semantics-preserving:
//!
//! * **Clock**: `validate_token` reads the real clock (no injectable now), so
//!   time claims (Go-style duration strings) are resolved relative to the real
//!   current time instead of `options.now`. The vectors are written relative,
//!   precisely so this works in every language.
//! * **Ephemeral signing key** (JWT-009): the crate deliberately avoids the
//!   `rsa` crate (RUSTSEC-2023-0071), so instead of generating a throwaway RSA
//!   key the runner signs with the fixture key and corrupts the signature —
//!   the same "signature does not verify under the kid-resolved key" semantic
//!   through the same RS256 verification path.
//!
//! Coverage: `spec_validation_conformance` asserts every non-native case id
//! executes and every native case names a real Rust test. When
//! `SPEC_COVERAGE_OUT` is set (by `tools/spec_coverage_gate.py`), the executed
//! ids are written there in the shared report shape.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rs_identity_model::{
    IdentityError, JsonWebKey, JsonWebKeySet, ValidationOptions, validate_token,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

const SPEC_FILE: &str = "../spec/vectors/validation.json";
const FIXTURE_ROOT: &str = "../spec/test-fixtures";
const SIGNING_KEY_DER: &str = "../spec/test-fixtures/validation/signing-key.pkcs1.der";
const JWKS_FIXTURE: &str = "../spec/test-fixtures/validation/jwks.json";
const FIXTURE_KID: &str = "test-key-1";

/// Rust anchors for native-executed cases: the per-language equivalent of the
/// vector's Go `native_test`. Checked for existence by the coverage gate below.
fn rust_native_tests() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([(
        "JWT-010",
        "rust/tests/jwt_validation.rs::integration_forced_refresh_against_live_jwks",
    )])
}

// ── Vector schema (mirrors go/internal/conformance/spec.go) ─────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
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
    #[serde(default)]
    vectors: Vec<TestVector>,
    #[serde(default)]
    execution: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    native_test: String,
}

impl Case {
    fn is_native(&self) -> bool {
        self.execution == "native"
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestVector {
    #[serde(default)]
    name: String,
    token: TokenSpec,
    options: VectorOptions,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenSpec {
    #[serde(default)]
    r#static: String,
    #[serde(default)]
    signing_key: String,
    #[serde(default)]
    header_kid: String,
    #[serde(default)]
    alg: String,
    #[serde(default)]
    claims: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorOptions {
    /// Fixed reference clock — unused here; time claims resolve against the
    /// real clock (see module docs).
    #[allow(dead_code)]
    #[serde(default)]
    now: String,
    #[serde(default)]
    expected_issuer: String,
    #[serde(default)]
    expected_audience: String,
    #[serde(default)]
    expected_nonce: String,
    #[serde(default)]
    clock_skew: String,
    #[serde(default)]
    required_claims: Vec<String>,
    #[serde(default)]
    allowed_algorithms: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    outcome: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    claim: String,
    #[serde(default)]
    claims: Map<String, Value>,
}

// ── Minting ──────────────────────────────────────────────────────────────────

/// Parses the Go `time.ParseDuration` subset the vectors use (`-1h`, `60s`).
fn parse_go_duration(s: &str) -> f64 {
    let (sign, body) = match s.strip_prefix('-') {
        Some(rest) => (-1.0, rest),
        None => (1.0, s),
    };
    let mut total = 0.0;
    let mut num = String::new();
    for c in body.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            let amount: f64 = num.parse().unwrap_or_else(|e| {
                panic!("bad duration {s:?}: {e}");
            });
            total += amount
                * match c {
                    'h' => 3600.0,
                    'm' => 60.0,
                    's' => 1.0,
                    other => panic!("bad duration unit {other:?} in {s:?}"),
                };
            num.clear();
        }
    }
    assert!(num.is_empty(), "trailing number in duration {s:?}");
    sign * total
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Converts exp/nbf/iat duration strings into absolute NumericDates relative
/// to the real current time.
fn resolve_claims(claims: &Map<String, Value>) -> Map<String, Value> {
    let now = now_unix();
    let mut out = Map::new();
    for (name, value) in claims {
        if matches!(name.as_str(), "exp" | "nbf" | "iat") {
            let s = value.as_str().unwrap_or_else(|| {
                panic!("time claim {name:?} must be a duration string, got {value:?}")
            });
            out.insert(name.clone(), json!(now + parse_go_duration(s) as i64));
        } else {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

fn mint_token(spec: &TokenSpec) -> String {
    if !spec.r#static.is_empty() {
        let path = format!("{FIXTURE_ROOT}/{}", spec.r#static);
        return std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read static token {path}: {e}"))
            .trim()
            .to_string();
    }

    let alg = if spec.alg.is_empty() {
        "RS256"
    } else {
        &spec.alg
    };
    assert_eq!(alg, "RS256", "the fixture signing key is RS256-only");
    let key = EncodingKey::from_rsa_der(
        &std::fs::read(SIGNING_KEY_DER).expect("read signing-key fixture"),
    );

    let mut header = Header::new(Algorithm::RS256);
    let kid = if spec.header_kid.is_empty() {
        FIXTURE_KID
    } else {
        &spec.header_kid
    };
    header.kid = Some(kid.to_string());

    let claims = resolve_claims(&spec.claims);
    let token = jsonwebtoken::encode(&header, &claims, &key).expect("sign vector token");

    if spec.signing_key == "ephemeral" {
        // Corrupt the signature instead of signing with a throwaway RSA key
        // (see module docs). Flip a character early in the signature segment —
        // NOT the last char: the RS256 signature's final base64url char carries
        // only 2 significant bits, so flipping it can produce non-canonical
        // trailing bits that a strict decoder rejects as *malformed* rather
        // than a signature mismatch. A full-6-bit interior position always
        // changes the decoded signature bytes and keeps the token well-formed,
        // so verification fails for the right reason (JWT-009 = signature).
        let (rest, sig) = token
            .rsplit_once('.')
            .expect("compact JWS has a signature segment");
        assert!(sig.len() > 2, "signature segment too short to corrupt");
        let mut sig_chars: Vec<char> = sig.chars().collect();
        // Position 1 is a full-6-bit char (not the final trailing-bit char).
        let orig = sig_chars[1];
        sig_chars[1] = if orig == 'A' { 'B' } else { 'A' };
        return format!("{rest}.{}", sig_chars.into_iter().collect::<String>());
    }
    token
}

/// Resolves the verification key by the token's header kid (JWT-001),
/// mirroring the Python/Go runners; falls back to the set's first key.
fn resolve_verification_key(token: &str, jwks: &JsonWebKeySet) -> JsonWebKey {
    let kid = token
        .split('.')
        .next()
        .and_then(|h| URL_SAFE_NO_PAD.decode(h).ok())
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|h| h.get("kid").and_then(Value::as_str).map(str::to_string));
    jwks.keys
        .iter()
        .find(|k| kid.as_deref() == Some(k.kid.as_str()))
        .or_else(|| jwks.keys.first())
        .expect("jwks fixture has at least one key")
        .clone()
}

// ── Execution & canonical-error mapping ──────────────────────────────────────

fn options_for(o: &VectorOptions) -> ValidationOptions {
    let mut b = ValidationOptions::builder();
    if !o.expected_issuer.is_empty() {
        b = b.issuer(&o.expected_issuer);
    }
    if !o.expected_audience.is_empty() {
        b = b.audience(&o.expected_audience);
    }
    if !o.expected_nonce.is_empty() {
        b = b.expected_nonce(&o.expected_nonce);
    }
    if !o.clock_skew.is_empty() {
        b = b.clock_skew(Duration::from_secs_f64(parse_go_duration(&o.clock_skew)));
    }
    if !o.required_claims.is_empty() {
        b = b.required_claims(o.required_claims.iter().map(String::as_str));
    }
    if !o.allowed_algorithms.is_empty() {
        b = b.allowed_algorithms(o.allowed_algorithms.iter().map(String::as_str));
    }
    b.build()
}

/// Asserts a rejection matches the canonical code via the crate's stable
/// [`IdentityError::Validation`] message shapes (`rust/src/jwt/mod.rs`,
/// `claims.rs::claim_err`).
fn assert_reject(label: &str, err: &IdentityError, expect: &Expect) {
    let IdentityError::Validation(msg) = err else {
        panic!("{label}: expected IdentityError::Validation, got {err:?}");
    };
    let matched = match expect.error.as_str() {
        "malformed" => msg.starts_with("malformed token"),
        "alg_none" => msg.contains("algorithm \"none\""),
        "unsupported_alg" => msg.starts_with("unsupported or disallowed algorithm"),
        "signature" => msg.starts_with("signature verification failed"),
        "key_conversion" => msg.starts_with("convert "),
        "claim_validation" => {
            assert!(
                !expect.claim.is_empty(),
                "{label}: claim_validation without claim"
            );
            msg.starts_with(&format!("claim {:?} invalid", expect.claim))
        }
        other => panic!("{label}: unknown canonical error code {other:?}"),
    };
    assert!(
        matched,
        "{label}: rejection {msg:?} does not match canonical code {:?} (claim {:?})",
        expect.error, expect.claim
    );
}

/// Asserts every claim listed in the vector's accept expectation.
fn assert_accept(label: &str, claims: &rs_identity_model::Claims, want: &Map<String, Value>) {
    for (name, want_val) in want {
        let s = want_val
            .as_str()
            .unwrap_or_else(|| panic!("{label}: expected claim {name:?} must be a string"));
        match name.as_str() {
            "iss" => assert_eq!(claims.issuer.as_deref(), Some(s), "{label}: iss"),
            "sub" => assert_eq!(claims.subject.as_deref(), Some(s), "{label}: sub"),
            "aud" => assert!(
                claims.audience.contains(s),
                "{label}: aud {:?} does not contain {s:?}",
                claims.audience.values()
            ),
            "nonce" => assert_eq!(claims.nonce.as_deref(), Some(s), "{label}: nonce"),
            other => panic!("{label}: unsupported asserted claim {other:?}"),
        }
    }
}

#[test]
fn spec_validation_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read validation.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse validation.json");
    let jwks: JsonWebKeySet =
        serde_json::from_str(&std::fs::read_to_string(JWKS_FIXTURE).expect("read jwks fixture"))
            .expect("parse jwks fixture");
    let native_anchors = rust_native_tests();

    let mut executed: Vec<String> = Vec::new();
    for case in &capability.tests {
        if case.is_native() {
            assert!(
                !case.reason.is_empty() && !case.native_test.is_empty(),
                "{}: native execution requires reason + native_test",
                case.id
            );
            // Coverage gate: the native case must name a real Rust test.
            let anchor = native_anchors.get(case.id.as_str()).unwrap_or_else(|| {
                panic!("native case {} has no Rust native-test anchor", case.id)
            });
            let (file, test_name) = anchor.split_once("::").expect("anchor format file::test");
            let file = file.strip_prefix("rust/").unwrap_or(file);
            assert!(
                Path::new(file).is_file(),
                "{}: anchor file {file} missing",
                case.id
            );
            let body = std::fs::read_to_string(file).expect("read anchor file");
            assert!(
                body.contains(test_name),
                "{}: anchor test {test_name} not found in {file}",
                case.id
            );
            continue;
        }
        assert!(
            !case.vectors.is_empty(),
            "{}: no vectors and not marked native",
            case.id
        );
        for (idx, vector) in case.vectors.iter().enumerate() {
            let label = if vector.name.is_empty() {
                format!("{}[{idx}]", case.id)
            } else {
                format!("{} ({})", case.id, vector.name)
            };
            let token = mint_token(&vector.token);
            let key = resolve_verification_key(&token, &jwks);
            let result = validate_token(&token, &key, &options_for(&vector.options));
            match vector.expect.outcome.as_str() {
                "accept" => {
                    let claims =
                        result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
                    assert_accept(&label, &claims, &vector.expect.claims);
                }
                "reject" => {
                    let err = match result {
                        Err(e) => e,
                        Ok(_) => panic!(
                            "{label}: expected reject ({}), got accept",
                            vector.expect.error
                        ),
                    };
                    assert_reject(&label, &err, &vector.expect);
                }
                other => panic!("{label}: unknown expected outcome {other:?}"),
            }
        }
        executed.push(case.id.clone());
    }

    // Coverage gate: every non-native case must have been executed.
    let missing: Vec<&str> = capability
        .tests
        .iter()
        .filter(|c| !c.is_native() && !executed.contains(&c.id))
        .map(|c| c.id.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "vector cases not executed by the Rust runner: {missing:?}"
    );

    write_coverage_report(&capability.capability, &executed, &native_anchors);
}

/// Emits the executed/native case ids for the cross-language coverage gate
/// (tools/spec_coverage_gate.py) when SPEC_COVERAGE_OUT is set. Same shape as
/// the Python and Go runners.
fn write_coverage_report(
    capability: &str,
    executed: &[String],
    native: &BTreeMap<&'static str, &'static str>,
) {
    let Ok(out) = std::env::var("SPEC_COVERAGE_OUT") else {
        return;
    };
    let report = json!({
        "language": "rust",
        "capability": capability,
        "executed": executed,
        "native": native,
    });
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
    )
    .unwrap_or_else(|e| panic!("write coverage report {out}: {e}"));
}
