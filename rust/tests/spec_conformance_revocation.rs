//! Rust executor for the shared revocation vectors (`spec/vectors/revocation.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, the call
//! goes through [`RevocationClient`], and the outcome and the request the
//! client sent are asserted. The Python and Go runners execute the same file.

use std::collections::BTreeMap;

use rs_identity_model::{DiscoveryClient, IdentityError, RevocationClient};
use serde::Deserialize;
use serde_json::Value;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/revocation.json";
const FIXTURE_ROOT: &str = "../spec/test-fixtures";
/// Placeholder base URL in fixtures, replaced with the mock server's URL.
const FIXTURE_HOST: &str = "https://server.example.com";

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
    #[serde(default)]
    form: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    outcome: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    status: u16,
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

async fn assert_request(label: &str, server: &MockServer, want: &ExpectRequest) {
    let requests = server.received_requests().await.expect("recording enabled");
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
        let have = if name.eq_ignore_ascii_case("content-type") {
            have.split(';').next().unwrap_or_default().trim()
        } else {
            have
        };
        assert_eq!(have, value, "{label}: header {name}");
    }
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&got.body)
        .into_owned()
        .collect();
    for (name, value) in &want.form {
        assert_eq!(form.get(name), Some(value), "{label}: form {name}");
    }
}

async fn run_vector(label: &str, vector: &HttpVector) {
    let server = mock_server(vector).await;
    let input = |k: &str| vector.input.get(k).and_then(Value::as_str);

    let endpoint = if vector.input.get("discover").and_then(Value::as_bool) == Some(true) {
        let metadata = DiscoveryClient::builder()
            .allow_http(true)
            .build()
            .discover(&server.uri())
            .await
            .unwrap_or_else(|e| panic!("{label}: discovery: {e}"));
        metadata
            .revocation_endpoint
            .unwrap_or_else(|| panic!("{label}: no revocation_endpoint"))
    } else {
        format!("{}/revoke", server.uri())
    };

    let client = RevocationClient::builder()
        .revocation_endpoint(endpoint)
        .client_id("cid")
        .client_secret("secret")
        .allow_http(true)
        .build()
        .expect("build revocation client");
    let result = client
        .revoke(input("token").unwrap_or_default(), input("token_type_hint"))
        .await;

    match vector.expect.outcome.as_str() {
        "accept" => result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}")),
        "reject" => match result {
            Err(IdentityError::TokenEndpoint { error, status, .. }) => {
                assert_eq!(error, vector.expect.error, "{label}: error code");
                assert_eq!(status, vector.expect.status, "{label}: status");
            }
            other => panic!("{label}: expected TokenEndpoint error, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
    if let Some(want) = &vector.expect_request {
        assert_request(label, &server, want).await;
    }
}

#[tokio::test]
async fn spec_revocation_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read revocation.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse revocation.json");
    assert!(
        !capability.tests.is_empty(),
        "revocation.json defines no tests"
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
