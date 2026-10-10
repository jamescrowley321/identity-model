//! Rust runner for the shared pure-logic vectors (`spec/vectors/*.json`).
//!
//! A pure-logic vector names an `input.operation` and has no `http` or
//! `http_sequence`: it runs in-process and its `expect.result` is checked.
//! HTTP vectors in the same files run in `tests/spec_http_vectors.rs` against
//! the node-oidc fixture.
//! The Python and Go runners execute the same vectors.

use std::collections::HashSet;

use rs_identity_model::PkceChallenge;
use rs_identity_model::token::s256_challenge;
use serde_json::{Value, json};

const VECTORS_DIR: &str = "../spec/vectors";
/// Capabilities rs-identity-model does not implement; their vectors are
/// skipped rather than failing as "no runner".
const NOT_IMPLEMENTED: &[&str] = &["dpop"]; // #675

type OperationRunner = fn(&str, &Value, &Value);

/// The dispatch table is also the source of truth for the skip guard.
fn operation_runner(operation: &str) -> Option<OperationRunner> {
    match operation {
        "generate_code_verifier" => Some(|label, _input, result| {
            let min = result["min_length"].as_u64().expect("min_length");
            let max = result["max_length"].as_u64().expect("max_length");
            let alphabet = result["alphabet"].as_str().expect("alphabet");
            let samples = result["distinct_samples"]
                .as_u64()
                .expect("distinct_samples");
            assert!(samples >= 2, "{label}: distinct_samples = {samples}");
            let mut seen = HashSet::new();
            for _ in 0..samples {
                let verifier = PkceChallenge::generate().expect("generate").code_verifier;
                let len = verifier.len() as u64;
                assert!((min..=max).contains(&len), "{label}: verifier length {len}");
                assert!(
                    verifier.chars().all(|c| alphabet.contains(c)),
                    "{label}: verifier {verifier:?} outside the alphabet"
                );
                assert!(
                    seen.insert(verifier.clone()),
                    "{label}: verifier {verifier:?} generated twice"
                );
            }
        }),
        "s256_challenge" => Some(|label, input, result| {
            let verifier = input["code_verifier"].as_str().expect("code_verifier");
            assert_eq!(
                Some(&json!(s256_challenge(verifier))),
                result.get("code_challenge"),
                "{label}: code_challenge"
            );
        }),
        _ => None,
    }
}

fn assert_skip_has_no_runner(capability: &str, spec: &Value) {
    for case in spec["tests"].as_array().expect("tests") {
        for vector in case["vectors"].as_array().into_iter().flatten() {
            if vector.get("http").is_some() || vector.get("http_sequence").is_some() {
                continue;
            }
            if let Some(operation) = vector["input"]["operation"].as_str() {
                assert!(
                    operation_runner(operation).is_none(),
                    "{capability}: operation {operation:?} has a runner; remove it from NOT_IMPLEMENTED"
                );
            }
        }
    }
}

#[test]
#[should_panic(expected = "remove it from NOT_IMPLEMENTED")]
fn implemented_logic_cannot_be_skipped() {
    assert_skip_has_no_runner(
        "dpop",
        &json!({"tests": [{"vectors": [{"input": {"operation": "s256_challenge"}}]}]}),
    );
}

#[test]
fn spec_logic_vectors() {
    let mut files: Vec<_> = std::fs::read_dir(VECTORS_DIR)
        .expect("read spec/vectors")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut executed = 0;
    for file in files {
        let capability = file
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file name");
        let spec: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read vector file"))
                .unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        if NOT_IMPLEMENTED.contains(&capability) {
            assert_skip_has_no_runner(capability, &spec);
            continue;
        }
        let cases = spec["tests"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no tests", file.display()));
        for case in cases {
            let id = case["id"].as_str().expect("case id");
            for (idx, v) in case["vectors"].as_array().into_iter().flatten().enumerate() {
                let Some(operation) = v["input"].get("operation").and_then(Value::as_str) else {
                    continue;
                };
                // An HTTP vector that names an operation runs in spec_http_vectors.
                if v.get("http").is_some() || v.get("http_sequence").is_some() {
                    continue;
                }
                let key = v["name"]
                    .as_str()
                    .map_or_else(|| idx.to_string(), String::from);
                let label = format!("{id} ({key})");
                assert_eq!(v["expect"]["outcome"], "accept", "{label}: outcome");
                let runner = operation_runner(operation)
                    .unwrap_or_else(|| panic!("{label}: no runner for operation {operation:?}"));
                runner(&label, &v["input"], &v["expect"]["result"]);
                executed += 1;
            }
        }
    }
    assert!(executed > 0, "no pure-logic vectors executed");
}
