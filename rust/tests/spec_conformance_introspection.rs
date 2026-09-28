//! Rust executor for the shared introspection vectors (`spec/vectors/introspection.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, the call
//! goes through [`IntrospectionClient`], and the request the client sent and
//! the outcome are asserted. The Python and Go runners execute the same file.

use std::collections::BTreeMap;

use rs_identity_model::{
    ClientAuthMethod, DiscoveryClient, IdentityError, Introspection, IntrospectionClient,
};
use serde::Deserialize;
use serde_json::{Value, json};
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/introspection.json";
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

/// An empty expected header or form value means it must be absent.
async fn assert_request(label: &str, server: &MockServer, want: &ExpectRequest) {
    let requests = server.received_requests().await.expect("recording enabled");
    let got = requests
        .iter()
        .find(|r| r.url.path() == want.path)
        .unwrap_or_else(|| panic!("{label}: no request to {}", want.path));
    assert_eq!(got.method.as_str(), want.method, "{label}: method");
    for (name, value) in &want.headers {
        if value.is_empty() {
            assert!(
                !got.headers.contains_key(name.as_str()),
                "{label}: header {name} must be absent"
            );
            continue;
        }
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
        if value.is_empty() {
            assert!(
                !form.contains_key(name),
                "{label}: form {name} must be absent"
            );
            continue;
        }
        let have = form.get(name).map(String::as_str).unwrap_or_default();
        assert_eq!(have, value, "{label}: form {name}");
    }
}

/// The typed §2.2 fields keyed by member name, so they compare against the
/// vector's claims.
fn typed_members(ir: &Introspection) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("active", json!(ir.active)),
        ("scope", json!(ir.scope)),
        ("client_id", json!(ir.client_id)),
        ("username", json!(ir.username)),
        ("token_type", json!(ir.token_type)),
        ("exp", json!(ir.exp)),
        ("iat", json!(ir.iat)),
        ("nbf", json!(ir.nbf)),
        ("sub", json!(ir.sub)),
        ("aud", json!(ir.aud.values())),
        ("iss", json!(ir.iss)),
        ("jti", json!(ir.jti)),
    ])
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
            .introspection_endpoint
            .unwrap_or_else(|| panic!("{label}: no introspection_endpoint"))
    } else {
        format!("{}/introspect", server.uri())
    };

    let auth_method = match input("client_auth") {
        Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let client = IntrospectionClient::builder()
        .introspection_endpoint(endpoint)
        .client_id("cid")
        .client_secret(input("client_secret").unwrap_or("secret"))
        .auth_method(auth_method)
        .allow_http(true)
        .build()
        .expect("build introspection client");
    let result = client
        .introspect(input("token").unwrap_or_default(), input("token_type_hint"))
        .await;
    if let Some(want) = &vector.expect_request {
        assert_request(label, &server, want).await;
    }

    let expect = &vector.expect;
    match expect.outcome.as_str() {
        "accept" => {
            let ir = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let typed = typed_members(&ir);
            for (name, want) in &expect.claims {
                assert_eq!(
                    typed.get(name.as_str()),
                    Some(want),
                    "{label}: typed member {name}"
                );
            }
            for (name, want) in &expect.custom_claims {
                assert_eq!(ir.extra.get(name), Some(want), "{label}: overflow {name}");
            }
        }
        "reject" => match result {
            // A 2xx body that is not a valid §2.2 response fails to decode.
            Err(IdentityError::Deserialization(_)) if expect.error == "malformed" => {}
            Err(IdentityError::TokenEndpoint { error, status, .. }) => {
                assert_eq!(error, expect.error, "{label}: error code");
                assert_eq!(status, expect.status, "{label}: status");
            }
            other => panic!("{label}: expected TokenEndpoint error, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

#[tokio::test]
async fn spec_introspection_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read introspection.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse introspection.json");
    assert!(
        !capability.tests.is_empty(),
        "introspection.json defines no tests"
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
