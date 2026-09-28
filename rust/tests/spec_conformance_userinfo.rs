//! Rust executor for the shared UserInfo vectors (`spec/vectors/userinfo.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, the call
//! goes through [`UserInfoClient`], and the request the client sent and the
//! outcome are asserted. The Python and Go runners execute the same file.

use std::collections::BTreeMap;

use rs_identity_model::{IdentityError, UserInfoClient};
use serde::Deserialize;
use serde_json::Value;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/userinfo.json";
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
    http: BTreeMap<String, HttpResponse>,
    expect_request: Option<ExpectRequest>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpResponse {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
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
    www_authenticate: Option<String>,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    custom_claims: BTreeMap<String, Value>,
}

async fn mock_server(vector: &HttpVector) -> MockServer {
    let server = MockServer::start().await;
    for (p, resp) in &vector.http {
        let mut template = ResponseTemplate::new(resp.status);
        if !resp.body_fixture.is_empty() {
            let body = std::fs::read(format!("{FIXTURE_ROOT}/{}", resp.body_fixture))
                .expect("read fixture");
            template = template
                .set_body_bytes(body)
                .insert_header("content-type", "application/json");
        }
        for (k, v) in &resp.headers {
            template = template.insert_header(k.as_str(), v.as_str());
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
        assert_eq!(have, value, "{label}: header {name}");
    }
}

async fn run_vector(label: &str, vector: &HttpVector) {
    let server = mock_server(vector).await;
    let client = UserInfoClient::builder()
        .userinfo_endpoint(format!("{}/userinfo", server.uri()))
        .allow_http(true)
        .build()
        .expect("build userinfo client");
    let token = vector
        .input
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = match vector.input.get("expected_sub").and_then(Value::as_str) {
        Some(sub) => client.fetch_with_subject(token, sub).await,
        None => client.fetch(token).await,
    };
    if let Some(want) = &vector.expect_request {
        assert_request(label, &server, want).await;
    }

    let expect = &vector.expect;
    match expect.outcome.as_str() {
        "accept" => {
            let resp = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let mut typed = serde_json::to_value(&resp).expect("serialize userinfo");
            let typed = typed.as_object_mut().expect("userinfo is an object");
            typed.retain(|k, _| !resp.extra.contains_key(k));
            for (name, want) in &expect.claims {
                assert_eq!(typed.get(name), Some(want), "{label}: typed claim {name}");
            }
            for (name, want) in &expect.custom_claims {
                assert_eq!(
                    resp.claims().get(name),
                    Some(want),
                    "{label}: claim map {name}"
                );
            }
        }
        "reject" if expect.error == "subject_mismatch" => match result {
            Err(IdentityError::Validation(msg)) => {
                assert!(msg.contains("sub mismatch"), "{label}: {msg}");
            }
            other => panic!("{label}: expected sub mismatch, got {other:?}"),
        },
        "reject" => match result {
            Err(IdentityError::UserInfo {
                status,
                www_authenticate,
                ..
            }) => {
                assert_eq!(status, expect.status, "{label}: status");
                assert_eq!(
                    www_authenticate, expect.www_authenticate,
                    "{label}: WWW-Authenticate"
                );
            }
            other => panic!("{label}: expected UserInfo error, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

#[tokio::test]
async fn spec_userinfo_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read userinfo.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse userinfo.json");
    assert!(
        !capability.tests.is_empty(),
        "userinfo.json defines no tests"
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
