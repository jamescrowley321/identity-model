//! Rust executor for the shared JWKS vectors (`spec/vectors/jwks.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, its steps
//! run against one [`JwksClient`], and the resulting keys (or error), the
//! request, and the per-path request counts are asserted. The Python and Go
//! runners execute the same file.

use std::collections::BTreeMap;

use rs_identity_model::{IdentityError, JsonWebKey, JwksClient};
use serde::Deserialize;
use serde_json::Value;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/jwks.json";
const FIXTURE_ROOT: &str = "../spec/test-fixtures";

#[derive(Deserialize)]
struct Capability {
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(default)]
    vectors: Vec<HttpVector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpVector {
    #[serde(default)]
    name: String,
    input: BTreeMap<String, Value>,
    #[serde(default)]
    http: BTreeMap<String, HttpResponse>,
    #[serde(default)]
    http_sequence: BTreeMap<String, Vec<HttpResponse>>,
    expect_request: Option<ExpectRequest>,
    #[serde(default)]
    expect_calls: BTreeMap<String, usize>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpResponse {
    status: u16,
    #[serde(default)]
    body_fixture: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectRequest {
    path: String,
    method: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    outcome: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    keys: Vec<BTreeMap<String, String>>,
}

fn template(resp: &HttpResponse) -> ResponseTemplate {
    let template = ResponseTemplate::new(resp.status);
    if resp.body_fixture.is_empty() {
        return template;
    }
    let body = std::fs::read_to_string(format!("{FIXTURE_ROOT}/{}", resp.body_fixture))
        .expect("read fixture");
    template.set_body_raw(body, "application/json")
}

async fn mock_server(vector: &HttpVector) -> MockServer {
    let server = MockServer::start().await;
    for (p, resp) in &vector.http {
        Mock::given(path(p.as_str()))
            .respond_with(template(resp))
            .mount(&server)
            .await;
    }
    // Earlier-mounted mocks win, so each response but the last answers once.
    for (p, seq) in &vector.http_sequence {
        for (idx, resp) in seq.iter().enumerate() {
            let mock = Mock::given(path(p.as_str())).respond_with(template(resp));
            let mock = if idx + 1 < seq.len() {
                mock.up_to_n_times(1)
            } else {
                mock
            };
            mock.mount(&server).await;
        }
    }
    server
}

/// The key's non-empty modelled JWK members.
fn jwk_members(key: &JsonWebKey) -> BTreeMap<String, String> {
    [
        ("kty", &key.kty),
        ("kid", &key.kid),
        ("use", &key.use_),
        ("alg", &key.alg),
        ("n", &key.n),
        ("e", &key.e),
        ("crv", &key.crv),
        ("x", &key.x),
        ("y", &key.y),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| (k.to_string(), v.clone()))
    .collect()
}

async fn run_steps(
    vector: &HttpVector,
    client: &JwksClient,
    uri: &str,
) -> Result<Vec<JsonWebKey>, IdentityError> {
    let kid = vector
        .input
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Each `resolve` takes the next of `input.kids` when given, else `input.kid`.
    let mut kids = vector
        .input
        .get("kids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let steps = vector.input["steps"].as_array().expect("steps");
    let mut keys = Vec::new();
    for (idx, step) in steps.iter().enumerate() {
        let result = match step.as_str() {
            Some("fetch") => client.fetch(uri).await.map(|set| set.keys),
            Some("resolve") => {
                let kid = kids.next().unwrap_or(kid);
                client.resolve_key(uri, kid).await.map(|key| vec![key])
            }
            Some("force_refresh") => client.force_refresh(uri).await.map(|set| set.keys),
            other => panic!("unknown step {other:?}"),
        };
        keys = match result {
            Ok(keys) => keys,
            // A key-not-found miss before the last step does not end the run.
            Err(IdentityError::KeyNotFound(_)) if idx + 1 < steps.len() => Vec::new(),
            Err(e) => return Err(e),
        };
    }
    Ok(keys)
}

async fn run_vector(label: &str, vector: &HttpVector) {
    let server = mock_server(vector).await;
    let client = JwksClient::builder().allow_http(true).build();
    let result = run_steps(vector, &client, &format!("{}/jwks", server.uri())).await;

    match vector.expect.outcome.as_str() {
        "accept" => {
            let keys = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let got: Vec<_> = keys.iter().map(jwk_members).collect();
            assert_eq!(got, vector.expect.keys, "{label}: keys");
        }
        "reject" => match (vector.expect.error.as_str(), result) {
            ("malformed", Err(IdentityError::Deserialization(_)))
            | ("key_not_found", Err(IdentityError::KeyNotFound(_))) => {}
            ("empty_key_set", Err(IdentityError::Validation(msg))) => {
                assert!(msg.contains("contains no keys"), "{label}: {msg}");
            }
            (want, other) => panic!("{label}: expected {want}, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }

    let requests = server.received_requests().await.expect("recording enabled");
    if let Some(want) = &vector.expect_request {
        let got = requests
            .iter()
            .find(|r| r.url.path() == want.path)
            .unwrap_or_else(|| panic!("{label}: no request to {}", want.path));
        assert_eq!(got.method.as_str(), want.method, "{label}: method");
    }
    for (p, want) in &vector.expect_calls {
        let got = requests.iter().filter(|r| r.url.path() == p).count();
        assert_eq!(got, *want, "{label}: requests to {p}");
    }
}

#[tokio::test]
async fn spec_jwks_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read jwks.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse jwks.json");
    assert!(!capability.tests.is_empty(), "jwks.json defines no tests");

    for case in &capability.tests {
        assert!(!case.vectors.is_empty(), "{}: no vectors", case.id);
        for (idx, vector) in case.vectors.iter().enumerate() {
            let label = if vector.name.is_empty() {
                format!("{}[{idx}]", case.id)
            } else {
                format!("{} ({})", case.id, vector.name)
            };
            run_vector(&label, vector).await;
        }
    }
}
