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

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rs_identity_model::{
    DiscoveryClient, IdentityError, JsonWebKey, JwksClient, RevocationClient, UserInfoClient,
    UserInfoResponse,
};
use serde::Deserialize;
use serde_json::Value;

const VECTORS_DIR: &str = "../spec/vectors";
/// The node-oidc fixture that serves the canned HTTP vectors.
const VECTOR_OP: &str = "http://localhost:9010";
/// Bounds each request to the fixture itself (not the library's calls).
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);
/// Capabilities with an adapter, keyed by vector file name.
const ADAPTERS: &[&str] = &["jwks", "revocation", "userinfo"];

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
        let spec: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read vector file"))
                .unwrap_or_else(|e| panic!("parse {}: {e}", file.display()));
        for case in spec["tests"].as_array().into_iter().flatten() {
            let id = case["id"].as_str().expect("case id");
            let vectors = case["vectors"].as_array().cloned().unwrap_or_default();
            if ADAPTERS.contains(&capability) {
                assert!(!vectors.is_empty(), "{id}: case has no vectors");
            }
            for (idx, raw) in vectors.into_iter().enumerate() {
                if raw.get("http").is_none() && raw.get("http_sequence").is_none() {
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
