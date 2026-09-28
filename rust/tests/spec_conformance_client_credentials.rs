//! Rust executor for the shared client credentials vectors (`spec/vectors/client-credentials.json`).
//!
//! Each vector's canned responses are served by a `wiremock` server, the call
//! goes through [`TokenClient::client_credentials`], and the request the client
//! sent and the outcome are asserted. The Python and Go runners execute the
//! same file.

use std::collections::BTreeMap;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rs_identity_model::{ClientAuthMethod, IdentityError, TokenClient, TokenResponse};
use serde::Deserialize;
use serde_json::{Value, json};
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const SPEC_FILE: &str = "../spec/vectors/client-credentials.json";
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
    input: Input,
    http: BTreeMap<String, HttpResponse>,
    expect_request: Option<ExpectRequest>,
    expect: Expect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    client_auth: Option<String>,
    client_secret: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    extra_params: BTreeMap<String, String>,
    #[serde(default)]
    http_client_headers: BTreeMap<String, String>,
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
    error_description: Option<String>,
    error_uri: Option<String>,
    #[serde(default)]
    result: BTreeMap<String, Value>,
}

async fn mock_server(vector: &HttpVector) -> MockServer {
    let server = MockServer::start().await;
    for (p, resp) in &vector.http {
        let mut template = ResponseTemplate::new(resp.status);
        if !resp.body_fixture.is_empty() {
            let body = std::fs::read_to_string(format!("{FIXTURE_ROOT}/{}", resp.body_fixture))
                .expect("read fixture");
            template = template.set_body_raw(body, "application/json");
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
    // The last matching request is the one the outcome reflects.
    let got = requests
        .iter()
        .rfind(|r| r.url.path() == want.path)
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

/// The response's standard fields in their wire form, for `expect.result`.
fn result_fields(r: &TokenResponse) -> BTreeMap<&'static str, Value> {
    let mut fields = BTreeMap::from([
        ("access_token", json!(r.access_token)),
        ("token_type", json!(r.token_type)),
        ("expires_in", json!(r.expires_in)),
    ]);
    if let Some(scope) = &r.scope {
        fields.insert("scope", json!(scope));
    }
    fields
}

async fn run_vector(label: &str, vector: &HttpVector) {
    let server = mock_server(vector).await;
    let input = &vector.input;

    let auth_method = match input.client_auth.as_deref() {
        Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let mut builder = TokenClient::builder()
        .token_endpoint(format!("{}/token", server.uri()))
        .client_id("cid")
        .client_secret(input.client_secret.as_deref().unwrap_or("secret"))
        .auth_method(auth_method)
        .extra_params(input.extra_params.clone().into_iter().collect())
        .allow_http(true);
    if !input.http_client_headers.is_empty() {
        let mut headers = HeaderMap::new();
        for (k, v) in &input.http_client_headers {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                HeaderValue::from_str(v).expect("header value"),
            );
        }
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("build http client");
        builder = builder.http_client(http);
    }
    let client = builder.build().expect("build token client");
    let scope = input.scopes.join(" ");
    let result = client
        .client_credentials((!scope.is_empty()).then_some(scope.as_str()))
        .await;
    if let Some(want) = &vector.expect_request {
        assert_request(label, &server, want).await;
    }

    let expect = &vector.expect;
    match expect.outcome.as_str() {
        "accept" => {
            let response = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let got = result_fields(&response);
            for (key, value) in &expect.result {
                assert_eq!(got.get(key.as_str()), Some(value), "{label}: {key}");
            }
        }
        "reject" => match result {
            Err(IdentityError::TokenEndpoint {
                error,
                description,
                error_uri,
                status,
            }) => {
                assert_eq!(error, expect.error, "{label}: error code");
                assert_eq!(
                    description, expect.error_description,
                    "{label}: description"
                );
                assert_eq!(error_uri, expect.error_uri, "{label}: error_uri");
                assert_eq!(status, expect.status, "{label}: status");
            }
            other => panic!("{label}: expected TokenEndpoint error, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

#[tokio::test]
async fn spec_client_credentials_conformance() {
    let raw = std::fs::read_to_string(SPEC_FILE).expect("read client-credentials.json");
    let capability: Capability = serde_json::from_str(&raw).expect("parse client-credentials.json");
    assert!(
        !capability.tests.is_empty(),
        "client-credentials.json defines no tests"
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
