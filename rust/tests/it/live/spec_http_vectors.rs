//! Rust runner for the shared HTTP vectors (`spec/vectors/*.json`).
//!
//! The node-oidc fixture serves each vector's canned responses under its own
//! base URL (`infra/node-oidc-provider/vectors.js`). Per vector, the
//! capability's adapter calls the library against that base URL, the
//! fixture's `_check` must report that the client sent the expected requests,
//! and the result is compared with `expect`. The Python and Go runners execute
//! the same files.
//!
//! `#[ignore]`-gated like the other live tests: `make test-integration-rust`
//! boots the fixture and runs `cargo test -- --ignored`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rs_identity_model::{
    ClientAuthMethod, DiscoveryClient, DiscoveryError, IdentityError, Introspection,
    IntrospectionClient, JsonWebKey, JwksClient, ProviderMetadata, RevocationClient, TokenClient,
    TokenExchangeRequest, TokenResponse, UserInfoClient, UserInfoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};

const VECTORS_DIR: &str = "../spec/vectors";
/// The node-oidc fixture that serves the canned HTTP vectors.
const VECTOR_OP: &str = "http://localhost:9010";
/// Bounds each request to the fixture itself (not the library's calls).
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
/// Placeholder host in fixtures and expected results; the fixture serves it
/// rewritten to the vector's base URL.
const FIXTURE_HOST: &str = "https://server.example.com";
/// Wall-clock time one vector second maps to: the discovery cache has no
/// injectable clock, so TTL vectors run scaled down in real time.
const SPEC_SECOND: Duration = Duration::from_millis(50);
/// Capabilities with an adapter, keyed by vector file name.
const ADAPTERS: &[&str] = &[
    "authorization-code",
    "client-credentials",
    "discovery",
    "introspection",
    "jwks",
    "revocation",
    "token-exchange",
    "userinfo",
];
/// Capabilities rs-identity-model does not implement; their vectors are
/// skipped rather than failing as "no adapter".
const NOT_IMPLEMENTED: &[&str] = &["dpop"]; // #675

#[test]
fn implemented_http_capabilities_cannot_be_skipped() {
    for capability in NOT_IMPLEMENTED {
        assert!(
            !ADAPTERS.contains(capability),
            "{capability}: has an HTTP adapter; remove it from NOT_IMPLEMENTED"
        );
    }
}

/// One executable HTTP scenario. The fixture serves `http`/`http_sequence`
/// and checks `expect_request`/`expect_calls`, so the runner only reads the
/// rest; those fields are declared so an unknown field still fails loading.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpVector {
    #[serde(default)]
    name: String,
    input: BTreeMap<String, Value>,
    #[serde(default, rename = "http")]
    _http: Value,
    #[serde(default, rename = "http_sequence")]
    _http_sequence: Value,
    #[serde(default, rename = "expect_request")]
    _expect_request: Value,
    #[serde(default, rename = "expect_calls")]
    _expect_calls: Value,
    expect: Expect,
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
    www_authenticate: Option<String>,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    custom_claims: BTreeMap<String, Value>,
    #[serde(default)]
    keys: Vec<BTreeMap<String, String>>,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    result: BTreeMap<String, Value>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error_uri: Option<String>,
}

impl HttpVector {
    fn input_str(&self, key: &str) -> Option<&str> {
        self.input.get(key).and_then(Value::as_str)
    }
}

fn fixture_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(FIXTURE_TIMEOUT)
        .build()
        .expect("build fixture client")
}

/// Fails with each difference the fixture found between the requests it
/// received for `base` and the vector's `expect_request`/`expect_calls`.
async fn check_requests(label: &str, base: &str) {
    #[derive(Deserialize)]
    struct Check {
        ok: bool,
        diffs: Vec<String>,
    }
    let check: Check = fixture_client()
        .get(format!("{base}/_check"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .unwrap_or_else(|e| panic!("{label}: _check: {e}"))
        .json()
        .await
        .unwrap_or_else(|e| panic!("{label}: decode _check: {e}"));
    assert!(check.ok, "{label}: {:?}", check.diffs);
}

// --- revocation ---------------------------------------------------------------

async fn revocation_call(label: &str, base: &str, v: &HttpVector) -> Result<(), IdentityError> {
    let endpoint = if v.input.get("discover").and_then(Value::as_bool) == Some(true) {
        let metadata = DiscoveryClient::builder()
            .allow_http(true)
            .build()
            .discover(base)
            .await
            .unwrap_or_else(|e| panic!("{label}: discovery: {e}"));
        metadata
            .revocation_endpoint
            .unwrap_or_else(|| panic!("{label}: no revocation_endpoint"))
    } else {
        format!("{base}/revoke")
    };
    let client = RevocationClient::builder()
        .revocation_endpoint(endpoint)
        .client_id("cid")
        .client_secret("secret")
        .allow_http(true)
        .build()
        .expect("build revocation client");
    client
        .revoke(
            v.input_str("token").unwrap_or_default(),
            v.input_str("token_type_hint"),
        )
        .await
}

fn revocation_expect(label: &str, expect: &Expect, result: Result<(), IdentityError>) {
    match expect.outcome.as_str() {
        "accept" => result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}")),
        "reject" => match result {
            Err(IdentityError::TokenEndpoint { error, status, .. }) => {
                assert_eq!(error, expect.error, "{label}: error code");
                assert_eq!(status, expect.status, "{label}: status");
            }
            other => panic!("{label}: expected TokenEndpoint error, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

// --- token-exchange -----------------------------------------------------------

async fn token_exchange_call(base: &str, v: &HttpVector) -> Result<TokenResponse, IdentityError> {
    let input = |k: &str| v.input_str(k).unwrap_or_default().to_string();
    let mut request =
        TokenExchangeRequest::new(input("subject_token"), input("subject_token_type"));
    if v.input.contains_key("actor_token") {
        request = request.actor_token(input("actor_token"), input("actor_token_type"));
    }
    if v.input.contains_key("requested_token_type") {
        request = request.requested_token_type(input("requested_token_type"));
    }
    if v.input.contains_key("audience") {
        request = request.audience(input("audience"));
    }
    if v.input.contains_key("resource") {
        request = request.resource(input("resource"));
    }
    if v.input.contains_key("scope") {
        request = request.scope(input("scope"));
    }
    let auth_method = match v.input_str("client_auth") {
        Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let client = TokenClient::builder()
        .token_endpoint(format!("{base}/token"))
        .client_id("cid")
        .client_secret("secret")
        .auth_method(auth_method)
        .allow_http(true)
        .build()
        .expect("build token client");
    client.token_exchange(&request).await
}

/// The token response's fields, as JSON values; absent optional ones omitted.
fn token_result_fields(r: &TokenResponse) -> BTreeMap<&'static str, Value> {
    let mut fields = BTreeMap::from([
        ("access_token", json!(r.access_token)),
        ("token_type", json!(r.token_type)),
        ("expires_in", json!(r.expires_in)),
    ]);
    for (key, value) in [
        ("scope", &r.scope),
        ("refresh_token", &r.refresh_token),
        ("issued_token_type", &r.issued_token_type),
    ] {
        if let Some(v) = value {
            fields.insert(key, json!(v));
        }
    }
    fields
}

fn token_expect(label: &str, expect: &Expect, result: Result<TokenResponse, IdentityError>) {
    match expect.outcome.as_str() {
        "accept" => {
            let response = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let got = token_result_fields(&response);
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

// --- userinfo -----------------------------------------------------------------

async fn userinfo_call(base: &str, v: &HttpVector) -> Result<UserInfoResponse, IdentityError> {
    let client = UserInfoClient::builder()
        .userinfo_endpoint(format!("{base}/userinfo"))
        .allow_http(true)
        .build()
        .expect("build userinfo client");
    let token = v.input_str("token").unwrap_or_default();
    match v.input_str("expected_sub") {
        Some(sub) => client.fetch_with_subject(token, sub).await,
        None => client.fetch(token).await,
    }
}

fn userinfo_expect(label: &str, expect: &Expect, result: Result<UserInfoResponse, IdentityError>) {
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
        "reject" if expect.error == "missing_sub" => match result {
            Err(IdentityError::Validation(msg)) => {
                assert!(msg.contains("missing the sub claim"), "{label}: {msg}");
            }
            other => panic!("{label}: expected missing sub, got {other:?}"),
        },
        "reject" if !expect.error.is_empty() => {
            panic!("{label}: unknown expected error {:?}", expect.error)
        }
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

// --- authorization-code -------------------------------------------------------
//
// The HTTP vectors (the code exchange). The pure-logic PKCE vectors
// (input.operation) run in-process in conformance::spec_logic_vectors.

async fn authorization_code_call(
    base: &str,
    v: &HttpVector,
) -> Result<TokenResponse, IdentityError> {
    let mut builder = TokenClient::builder()
        .token_endpoint(format!("{base}/token"))
        .client_id("cid")
        .allow_http(true);
    if let Some(secret) = v.input_str("client_secret") {
        builder = builder.client_secret(secret);
    }
    let client = builder.build().expect("build token client");
    client
        .exchange_code(
            v.input_str("code").unwrap_or_default(),
            v.input_str("redirect_uri").unwrap_or_default(),
            v.input_str("code_verifier"),
        )
        .await
}

// --- client-credentials -------------------------------------------------------

async fn client_credentials_call(
    base: &str,
    v: &HttpVector,
) -> Result<TokenResponse, IdentityError> {
    let auth_method = match v.input_str("client_auth") {
        Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let strings = |key: &str| -> BTreeMap<String, String> {
        v.input
            .get(key)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(k, val)| (k.clone(), val.as_str().expect("string value").to_string()))
            .collect()
    };
    let mut builder = TokenClient::builder()
        .token_endpoint(format!("{base}/token"))
        .client_id("cid")
        .client_secret(v.input_str("client_secret").unwrap_or("secret"))
        .auth_method(auth_method)
        .extra_params(
            strings("extra_params")
                .into_iter()
                .collect::<HashMap<_, _>>(),
        )
        .allow_http(true);
    let default_headers = strings("http_client_headers");
    if !default_headers.is_empty() {
        let mut headers = HeaderMap::new();
        for (k, val) in &default_headers {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                HeaderValue::from_str(val).expect("header value"),
            );
        }
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("build http client");
        builder = builder.http_client(http);
    }
    let client = builder.build().expect("build token client");
    let scope = v
        .input
        .get("scopes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    client
        .client_credentials((!scope.is_empty()).then_some(scope.as_str()))
        .await
}

// --- discovery ----------------------------------------------------------------

/// One `DiscoveryClient`, called at each `input.calls_at_seconds` offset.
async fn discovery_call(base: &str, v: &HttpVector) -> Result<ProviderMetadata, DiscoveryError> {
    let require_https = v.input.get("require_https").and_then(Value::as_bool) == Some(true);
    let mut builder = DiscoveryClient::builder().allow_http(!require_https);
    if let Some(ttl) = v.input.get("cache_ttl_seconds").and_then(Value::as_u64) {
        builder = builder.cache_ttl(SPEC_SECOND * u32::try_from(ttl).expect("ttl fits u32"));
    }
    let client = builder.build();
    let offsets: Vec<u64> = match v.input.get("calls_at_seconds") {
        Some(at) => serde_json::from_value(at.clone()).expect("calls_at_seconds"),
        None => vec![0],
    };
    let start = tokio::time::Instant::now();
    let mut result = Err(DiscoveryError::Other(IdentityError::Validation(
        "no call made".into(),
    )));
    for at in offsets {
        let offset = SPEC_SECOND * u32::try_from(at).expect("offset fits u32");
        tokio::time::sleep_until(start + offset).await;
        result = client.discover(base).await;
        if result.is_err() {
            break;
        }
    }
    result
}

fn discovery_expect(
    label: &str,
    base: &str,
    expect: &Expect,
    result: Result<ProviderMetadata, DiscoveryError>,
) {
    match expect.outcome.as_str() {
        "accept" => {
            let metadata = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let got = serde_json::to_value(&metadata).expect("serialize metadata");
            let want = serde_json::to_string(&expect.result)
                .expect("serialize expected result")
                .replace(FIXTURE_HOST, base);
            let want: BTreeMap<String, Value> =
                serde_json::from_str(&want).expect("parse expected result");
            for (key, value) in &want {
                assert_eq!(got.get(key), Some(value), "{label}: {key}");
            }
        }
        "reject" => match (expect.error.as_str(), result) {
            ("issuer_mismatch", Err(DiscoveryError::IssuerMismatch { .. })) => {}
            ("unexpected_status", Err(DiscoveryError::UnexpectedStatus { status, .. })) => {
                assert_eq!(status, expect.status, "{label}: HTTP status");
            }
            ("invalid_json", Err(DiscoveryError::InvalidJson { .. })) => {}
            ("missing_fields", Err(DiscoveryError::MissingFields { fields, .. })) => {
                assert_eq!(fields, expect.fields, "{label}: missing fields");
            }
            ("https_required", Err(DiscoveryError::HttpsRequired { .. })) => {}
            (code, other) => panic!("{label}: expected {code}, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

// --- introspection ------------------------------------------------------------

async fn introspection_call(
    label: &str,
    base: &str,
    v: &HttpVector,
) -> Result<Introspection, IdentityError> {
    let endpoint = if v.input.get("discover").and_then(Value::as_bool) == Some(true) {
        let metadata = DiscoveryClient::builder()
            .allow_http(true)
            .build()
            .discover(base)
            .await
            .unwrap_or_else(|e| panic!("{label}: discovery: {e}"));
        metadata
            .introspection_endpoint
            .unwrap_or_else(|| panic!("{label}: no introspection_endpoint"))
    } else {
        format!("{base}/introspect")
    };
    let auth_method = match v.input_str("client_auth") {
        Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
        _ => ClientAuthMethod::ClientSecretBasic,
    };
    let client = IntrospectionClient::builder()
        .introspection_endpoint(endpoint)
        .client_id("cid")
        .client_secret(v.input_str("client_secret").unwrap_or("secret"))
        .auth_method(auth_method)
        .allow_http(true)
        .build()
        .expect("build introspection client");
    client
        .introspect(
            v.input_str("token").unwrap_or_default(),
            v.input_str("token_type_hint"),
        )
        .await
}

/// The typed RFC 7662 §2.2 members, as JSON values.
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

fn introspection_expect(
    label: &str,
    expect: &Expect,
    result: Result<Introspection, IdentityError>,
) {
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

// --- jwks ---------------------------------------------------------------------

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

/// Runs `input.steps` against one `JwksClient`.
async fn jwks_call(base: &str, v: &HttpVector) -> Result<Vec<JsonWebKey>, IdentityError> {
    let client = JwksClient::builder().allow_http(true).build();
    let uri = format!("{base}/jwks");
    let kid = v.input_str("kid").unwrap_or_default();
    // Each `resolve` takes the next of `input.kids` when given, else `input.kid`.
    let mut kids = v
        .input
        .get("kids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let steps = v.input["steps"].as_array().expect("steps");
    let mut keys = Vec::new();
    for (idx, step) in steps.iter().enumerate() {
        let result = match step.as_str() {
            Some("fetch") => client.fetch(&uri).await.map(|set| set.keys),
            Some("resolve") => {
                let kid = kids.next().unwrap_or(kid);
                client.resolve_key(&uri, kid).await.map(|key| vec![key])
            }
            Some("force_refresh") => client.force_refresh(&uri).await.map(|set| set.keys),
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

fn jwks_expect(label: &str, expect: &Expect, result: Result<Vec<JsonWebKey>, IdentityError>) {
    match expect.outcome.as_str() {
        "accept" => {
            let keys = result.unwrap_or_else(|e| panic!("{label}: expected accept, got: {e}"));
            let got: Vec<_> = keys.iter().map(jwk_members).collect();
            assert_eq!(got, expect.keys, "{label}: keys");
        }
        "reject" => match (expect.error.as_str(), result) {
            ("malformed", Err(IdentityError::Deserialization(_)))
            | ("key_not_found", Err(IdentityError::KeyNotFound(_))) => {}
            ("empty_key_set", Err(IdentityError::Validation(msg))) => {
                assert!(msg.contains("contains no keys"), "{label}: {msg}");
            }
            (want, other) => panic!("{label}: expected {want}, got {other:?}"),
        },
        other => panic!("{label}: unknown expected outcome {other:?}"),
    }
}

// --- runner -------------------------------------------------------------------

/// Calls the capability's adapter, checks the requests, then the outcome.
async fn run_vector(capability: &str, label: &str, base: &str, v: &HttpVector) {
    match capability {
        "authorization-code" => {
            let result = authorization_code_call(base, v).await;
            check_requests(label, base).await;
            token_expect(label, &v.expect, result);
        }
        "client-credentials" => {
            let result = client_credentials_call(base, v).await;
            check_requests(label, base).await;
            token_expect(label, &v.expect, result);
        }
        "discovery" => {
            let result = discovery_call(base, v).await;
            check_requests(label, base).await;
            discovery_expect(label, base, &v.expect, result);
        }
        "introspection" => {
            let result = introspection_call(label, base, v).await;
            check_requests(label, base).await;
            introspection_expect(label, &v.expect, result);
        }
        "jwks" => {
            let result = jwks_call(base, v).await;
            check_requests(label, base).await;
            jwks_expect(label, &v.expect, result);
        }
        "revocation" => {
            let result = revocation_call(label, base, v).await;
            check_requests(label, base).await;
            revocation_expect(label, &v.expect, result);
        }
        "token-exchange" => {
            let result = token_exchange_call(base, v).await;
            check_requests(label, base).await;
            token_expect(label, &v.expect, result);
        }
        "userinfo" => {
            let result = userinfo_call(base, v).await;
            check_requests(label, base).await;
            userinfo_expect(label, &v.expect, result);
        }
        other => panic!("{label}: {other}.json has HTTP vectors but no adapter"),
    }
}

#[tokio::test]
#[ignore = "needs the node-oidc fixture: make test-integration-rust"]
async fn spec_http_vectors() {
    implemented_http_capabilities_cannot_be_skipped();
    fixture_client()
        .get(format!("{VECTOR_OP}/.well-known/openid-configuration"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .unwrap_or_else(|e| panic!("node-oidc fixture not reachable at {VECTOR_OP}: {e}"));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let run = format!("{}-{nanos}", std::process::id());

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
        if NOT_IMPLEMENTED.contains(&capability) {
            continue;
        }
        let spec: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read vector file"))
                .unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        let cases = spec["tests"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no tests", file.display()));
        for case in cases {
            let id = case["id"].as_str().expect("case id");
            let vectors = case["vectors"].as_array().cloned().unwrap_or_default();
            if ADAPTERS.contains(&capability) {
                assert!(!vectors.is_empty(), "{id}: case has no vectors");
            }
            for (idx, raw) in vectors.into_iter().enumerate() {
                if raw.get("http").is_none() && raw.get("http_sequence").is_none() {
                    // In an adapted file, a vector that is not HTTP must be
                    // pure logic; anything else is a dropped HTTP vector.
                    assert!(
                        !ADAPTERS.contains(&capability) || raw["input"].get("operation").is_some(),
                        "{id}[{idx}]: neither an HTTP nor a pure-logic vector"
                    );
                    continue;
                }
                let v: HttpVector = serde_json::from_value(raw)
                    .unwrap_or_else(|e| panic!("{id}[{idx}]: decode vector: {e}"));
                let key = if v.name.is_empty() {
                    idx.to_string()
                } else {
                    v.name.clone()
                };
                let label = format!("{id} ({key})");
                let base = format!("{VECTOR_OP}/v/{run}/{capability}/{id}/{key}");
                run_vector(capability, &label, &base, &v).await;
                executed += 1;
            }
        }
    }
    assert!(executed > 0, "no HTTP vectors executed");
}

#[test]
fn discovery_diagnostics_cannot_substitute_for_failure_details() {
    let cases = [
        (
            serde_json::json!({"outcome": "reject", "error": "unexpected_status", "status": 500}),
            IdentityError::Http(
                "unexpected HTTP status 404 from endpoint with unexpected HTTP status 500 injected"
                    .into(),
            ),
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "issuer_mismatch"}),
            IdentityError::Validation("unrelated failure: issuer mismatch".into()),
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "https_required"}),
            IdentityError::Validation("unrelated failure: must use https".into()),
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "missing_fields", "fields": ["jwks_uri"]}),
            IdentityError::Validation(
                "unrelated failure: missing required field(s): jwks_uri".into(),
            ),
        ),
    ];
    for (expected, error) in cases {
        let expected: Expect = serde_json::from_value(expected).unwrap();
        assert!(
            std::panic::catch_unwind(|| discovery_expect(
                "regression",
                "http://localhost",
                &expected,
                Err(DiscoveryError::Other(error))
            ))
            .is_err(),
            "diagnostic text passed as {}",
            expected.error
        );
    }
}

#[test]
fn discovery_structured_details_accept_arbitrary_diagnostics() {
    let cases = [
        (
            serde_json::json!({"outcome": "reject", "error": "unexpected_status", "status": 404}),
            DiscoveryError::UnexpectedStatus {
                status: 404,
                endpoint: "changed diagnostic context with status 500".into(),
            },
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "issuer_mismatch"}),
            DiscoveryError::IssuerMismatch {
                requested: "https://a.example".into(),
                actual: "https://b.example".into(),
            },
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "https_required"}),
            DiscoveryError::HttpsRequired {
                issuer: "http://localhost".into(),
            },
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "missing_fields", "fields": ["jwks_uri"]}),
            DiscoveryError::MissingFields {
                fields: vec!["jwks_uri".into()],
                endpoint: "changed diagnostic context".into(),
            },
        ),
        (
            serde_json::json!({"outcome": "reject", "error": "invalid_json"}),
            DiscoveryError::InvalidJson {
                endpoint: "changed diagnostic context".into(),
                reason: "entirely different prose".into(),
            },
        ),
    ];
    for (expected, error) in cases {
        let expected = serde_json::from_value(expected).unwrap();
        discovery_expect("regression", "http://localhost", &expected, Err(error));
    }
}

#[test]
fn discovery_checks_exact_status_and_fields() {
    let status: Expect = serde_json::from_value(
        serde_json::json!({"outcome": "reject", "error": "unexpected_status", "status": 500}),
    )
    .unwrap();
    let error = DiscoveryError::UnexpectedStatus {
        status: 404,
        endpoint: "unexpected HTTP status 500 ".into(),
    };
    assert!(
        std::panic::catch_unwind(|| discovery_expect(
            "regression",
            "http://localhost",
            &status,
            Err(error)
        ))
        .is_err()
    );
    let fields: Expect = serde_json::from_value(
        serde_json::json!({"outcome": "reject", "error": "missing_fields", "fields": ["jwks_uri"]}),
    )
    .unwrap();
    for observed in [
        vec![],
        vec!["issuer".into()],
        vec!["jwks_uri".into(), "token_endpoint".into()],
    ] {
        let error = DiscoveryError::MissingFields {
            fields: observed,
            endpoint: "missing required field(s): jwks_uri".into(),
        };
        assert!(
            std::panic::catch_unwind(|| discovery_expect(
                "regression",
                "http://localhost",
                &fields,
                Err(error)
            ))
            .is_err()
        );
    }
}
