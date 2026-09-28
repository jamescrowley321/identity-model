//! Rust executor for the shared discovery vectors (`spec/vectors/discovery.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, the calls
//! go through [`DiscoveryClient`], and the outcome, the request sent and the
//! request count are asserted. The Python and Go runners execute the same file.

use std::collections::BTreeMap;
use std::time::Duration;

use rs_identity_model::{DiscoveryClient, IdentityError, ProviderMetadata};
use serde::Deserialize;
use serde_json::Value;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/discovery.json";
const FIXTURE_ROOT: &str = "../spec/test-fixtures";
/// Placeholder base URL in fixtures, replaced with the mock server's URL.
const FIXTURE_HOST: &str = "https://server.example.com";
/// Wall-clock time one vector second maps to: the cache has no injectable
/// clock, so TTL vectors run scaled down in real time.
const SPEC_SECOND: Duration = Duration::from_millis(50);

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
    http: BTreeMap<String, HttpResponse>,
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
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    outcome: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    result: BTreeMap<String, Value>,
}

async fn mock_server(vector: &HttpVector) -> MockServer {
    let server = MockServer::start().await;
    for (p, resp) in &vector.http {
        let mut template = ResponseTemplate::new(resp.status);
        if !resp.body_fixture.is_empty() {
            let raw = std::fs::read_to_string(format!("{FIXTURE_ROOT}/{}", resp.body_fixture))
                .expect("read fixture");
            let body = raw.replace(FIXTURE_HOST, &server.uri());
            if !body.is_empty() {
                template = template.set_body_raw(body, "application/json");
            }
        }
        Mock::given(path(p.as_str()))
            .respond_with(template)
            .mount(&server)
            .await;
    }
    server
}

async fn assert_requests(label: &str, server: &MockServer, vector: &HttpVector) {
    let requests = server.received_requests().await.expect("recording enabled");
    for (p, want) in &vector.expect_calls {
        let got = requests.iter().filter(|r| r.url.path() == p).count();
        assert_eq!(got, *want, "{label}: requests to {p}");
    }
    let Some(want) = &vector.expect_request else {
        return;
    };
    let got = requests
        .iter()
        .find(|r| r.url.path() == want.path)
        .unwrap_or_else(|| panic!("{label}: no request to {}", want.path));
    assert_eq!(got.method.as_str(), want.method, "{label}: method");
    for (name, value) in &want.headers {
        let have = got
            .headers
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(have, value, "{label}: header {name}");
    }
}

fn assert_result(
    label: &str,
    base: &str,
    metadata: &ProviderMetadata,
    want: &BTreeMap<String, Value>,
) {
    let got = serde_json::to_value(metadata).expect("serialize metadata");
    let want = serde_json::to_string(want)
        .expect("serialize expected result")
        .replace(FIXTURE_HOST, base);
    let want: BTreeMap<String, Value> = serde_json::from_str(&want).expect("parse expected result");
    for (key, value) in &want {
        assert_eq!(got.get(key), Some(value), "{label}: {key}");
    }
}

fn assert_error(label: &str, err: IdentityError, want: &Expect) {
    match (want.error.as_str(), &err) {
        ("issuer_mismatch", IdentityError::Validation(msg)) => {
            assert!(msg.contains("issuer mismatch"), "{label}: {msg}");
        }
        ("http_status", IdentityError::Http(msg)) => {
            let status = format!("unexpected HTTP status {} ", want.status);
            assert!(msg.contains(&status), "{label}: {msg}");
        }
        ("parse", IdentityError::Deserialization(_)) => {}
        ("missing_fields", IdentityError::Validation(msg)) => {
            let fields = format!("missing required field(s): {}", want.fields.join(", "));
            assert!(msg.ends_with(&fields), "{label}: {msg}");
        }
        ("https_required", IdentityError::Validation(msg)) => {
            assert!(msg.contains("must use https"), "{label}: {msg}");
        }
        (code, other) => panic!("{label}: expected {code}, got {other:?}"),
    }
}

async fn run_vector(label: &str, vector: &HttpVector) {
    let server = mock_server(vector).await;

    let require_https = vector.input.get("require_https").and_then(Value::as_bool) == Some(true);
    let mut builder = DiscoveryClient::builder().allow_http(!require_https);
    if let Some(ttl) = vector
        .input
        .get("cache_ttl_seconds")
        .and_then(Value::as_u64)
    {
        builder = builder.cache_ttl(SPEC_SECOND * u32::try_from(ttl).expect("ttl fits u32"));
    }
    let client = builder.build();
    let offsets: Vec<u64> = match vector.input.get("calls_at_seconds") {
        Some(at) => serde_json::from_value(at.clone()).expect("calls_at_seconds"),
        None => vec![0],
    };

    let start = tokio::time::Instant::now();
    let mut result = Err(IdentityError::Validation("no call made".into()));
    for at in offsets {
        let offset = SPEC_SECOND * u32::try_from(at).expect("offset fits u32");
        tokio::time::sleep_until(start + offset).await;
        result = client.discover(&server.uri()).await;
        if result.is_err() {
            break;
        }
    }

    match vector.expect.outcome.as_str() {
        "accept" => {
            let metadata = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            assert_result(label, &server.uri(), &metadata, &vector.expect.result);
        }
        "reject" => match result {
            Err(err) => assert_error(label, err, &vector.expect),
            Ok(_) => panic!(
                "{label}: expected {} reject, got accept",
                vector.expect.error
            ),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
    assert_requests(label, &server, vector).await;
}

#[tokio::test]
async fn spec_discovery_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read discovery.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse discovery.json");
    assert!(
        !capability.tests.is_empty(),
        "discovery.json defines no tests"
    );

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
