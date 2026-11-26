use std::collections::HashMap;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn test_state() -> AppState {
    let log_dir = std::env::temp_dir().join(format!("rp-rust-app-tests-{}", std::process::id()));
    AppState::new(Config {
        rp_base_url: "http://localhost:8891".into(),
        log_dir,
        allow_http: true,
        http: rs_identity_model::secure_client_builder()
            .build()
            .expect("client"),
    })
}

async fn send(
    state: &AppState,
    request: Request<Body>,
) -> (StatusCode, HashMap<String, String>, String) {
    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_owned()))
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).expect("request")
}

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

async fn recorded(state: &AppState, test_id: &str) -> (StatusCode, Value) {
    let (status, _, body) = send(state, get(&format!("/results/{test_id}"))).await;
    (status, serde_json::from_str(&body).expect("json body"))
}

/// A mock OP serving a discovery document that declares `declared_issuer`;
/// returns the server and the issuer the harness is asked to use.
async fn mock_op(declared_issuer: Option<&str>) -> (MockServer, String) {
    let server = MockServer::start().await;
    let issuer = format!("{}/", server.uri());
    let base = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": declared_issuer.unwrap_or(&issuer),
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "userinfo_endpoint": format!("{base}/userinfo"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })))
        .mount(&server)
        .await;
    (server, issuer)
}

#[tokio::test]
async fn health_names_the_op_facing_base_url() {
    let state = test_state();
    let (status, _, body) = send(&state, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json"),
        json!({"status": "ok", "service": "conformance-rp-rust", "op_facing_base_url": "http://localhost:8891"})
    );
}

#[tokio::test]
async fn results_are_404_until_recorded() {
    let state = test_state();
    assert_eq!(
        recorded(&state, "nothing").await,
        (StatusCode::NOT_FOUND, json!({"error": "not_found"}))
    );
}

#[tokio::test]
async fn clear_cache_answers_ok() {
    let state = test_state();
    let request = Request::post("/clear-cache")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = send(&state, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json"),
        json!({"status": "ok", "cleared": ["discovery", "jwks"]})
    );
}

#[tokio::test]
async fn discover_records_success() {
    let state = test_state();
    let (_server, issuer) = mock_op(None).await;
    let uri = format!(
        "/discover?{}",
        query(&[
            ("issuer", &issuer),
            ("test_id", "t-ok"),
            ("test_name", "disco"),
            ("profile", "config-rp")
        ])
    );
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        recorded(&state, "t-ok").await,
        (
            StatusCode::OK,
            json!({"test_id": "t-ok", "status": "success"})
        )
    );
}

#[tokio::test]
async fn discover_issuer_mismatch_is_refused_and_typed() {
    let state = test_state();
    let (_server, issuer) = mock_op(Some("https://attacker.example/")).await;
    let uri = format!(
        "/discover?{}",
        query(&[("issuer", &issuer), ("test_id", "t-mm")])
    );
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (status, body) = recorded(&state, "t-mm").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.get("status"), Some(&json!("error")));
    let error = body.get("error").and_then(Value::as_str).expect("error");
    assert_eq!(error.split(':').next(), Some("issuer_mismatch"), "{error}");
}

#[tokio::test]
async fn authorize_issuer_mismatch_is_refused_and_typed() {
    let state = test_state();
    let (_server, issuer) = mock_op(Some("https://attacker.example/")).await;
    let uri = format!(
        "/authorize?{}",
        query(&[
            ("issuer", &issuer),
            ("client_id", "c"),
            ("client_secret", "s"),
            ("test_id", "t-amm")
        ])
    );
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (_, body) = recorded(&state, "t-amm").await;
    let error = body.get("error").and_then(Value::as_str).expect("error");
    assert_eq!(error.split(':').next(), Some("issuer_mismatch"), "{error}");
}

/// Starts a flow and returns the authorization request's query parameters.
async fn start_flow(state: &AppState, issuer: &str, test_id: &str) -> HashMap<String, String> {
    let uri = format!(
        "/authorize?{}",
        query(&[
            ("issuer", issuer),
            ("client_id", "conformance-rp"),
            ("client_secret", "secret"),
            ("test_id", test_id),
            ("test_name", "oidcc-client-test"),
            ("profile", "basic-rp"),
            ("use_pkce", "false"),
            ("skip_userinfo", "false"),
        ])
    );
    let (status, headers, _) = send(state, get(&uri)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers.get(header::LOCATION.as_str()).expect("location");
    url::Url::parse(location)
        .expect("absolute URL")
        .query_pairs()
        .into_owned()
        .collect()
}

#[tokio::test]
async fn authorize_redirects_with_state_nonce_and_pkce() {
    let state = test_state();
    let (_server, issuer) = mock_op(None).await;
    let params = start_flow(&state, &issuer, "t-auth").await;
    let expected = HashMap::from([
        ("response_type", "code"),
        ("client_id", "conformance-rp"),
        ("redirect_uri", "http://localhost:8891/callback"),
        ("scope", DEFAULT_SCOPE),
        ("code_challenge_method", "S256"),
    ]);
    for (key, value) in expected {
        assert_eq!(params.get(key).map(String::as_str), Some(value), "{key}");
    }
    for key in ["state", "nonce", "code_challenge"] {
        assert!(
            params.get(key).is_some_and(|v| !v.is_empty()),
            "{key} missing"
        );
    }
    assert_ne!(params.get("state"), params.get("nonce"));
    // Nothing recorded until the flow completes.
    assert_eq!(recorded(&state, "t-auth").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn op_error_response_is_rejected_for_the_flow() {
    let state = test_state();
    let (_server, issuer) = mock_op(None).await;
    let params = start_flow(&state, &issuer, "t-err").await;
    let flow_state = params.get("state").expect("state");
    let uri = format!(
        "/callback?{}",
        query(&[
            ("state", flow_state),
            ("error", "access_denied"),
            ("error_description", "no")
        ])
    );
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        recorded(&state, "t-err").await,
        (
            StatusCode::OK,
            json!({"test_id": "t-err", "status": "error", "error": "authorization_error: access_denied no"})
        )
    );
}

#[tokio::test]
async fn form_post_callback_reaches_the_flow() {
    let state = test_state();
    let (_server, issuer) = mock_op(None).await;
    let params = start_flow(&state, &issuer, "t-form").await;
    let flow_state = params.get("state").expect("state");
    let request = Request::post("/callback")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(query(&[("state", flow_state)])))
        .expect("request");
    let (status, _, _) = send(&state, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        recorded(&state, "t-form").await,
        (
            StatusCode::OK,
            json!({"test_id": "t-form", "status": "error", "error": "missing_code: callback has no code"})
        )
    );
}

#[tokio::test]
async fn unknown_state_is_filed_under_the_last_flow() {
    let state = test_state();
    let (_server, issuer) = mock_op(None).await;
    start_flow(&state, &issuer, "t-state").await;
    let uri = format!("/callback?{}", query(&[("state", "forged"), ("code", "c")]));
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, body) = recorded(&state, "t-state").await;
    assert_eq!(body.get("status"), Some(&json!("error")));
    let error = body.get("error").and_then(Value::as_str).expect("error");
    assert_eq!(error.split(':').next(), Some("state_validation"), "{error}");
}

#[test]
fn unattributed_rejection_never_turns_a_verdict_into_a_pass() {
    let reason = Reason::StateValidation;
    assert_eq!(
        merge_unattributed(None, "t", reason, "x"),
        Some(json!({"test_id": "t", "status": "error", "error": "state_validation: x"}))
    );
    let earlier = json!({"test_id": "t", "status": "error", "error": "invalid_issuer: y"});
    assert_eq!(merge_unattributed(Some(&earlier), "t", reason, "x"), None);
    let success = json!({"test_id": "t", "status": "success"});
    assert_eq!(
        merge_unattributed(Some(&success), "t", reason, "x"),
        Some(
            json!({"test_id": "t", "status": "conflict", "error": "state_validation: x (after a recorded success)"})
        )
    );
}

#[test]
fn nonce_is_appended_to_the_authorization_url() {
    let url = with_nonce("https://op.example/authorize?client_id=c&state=s", "n 1").expect("url");
    let pairs: Vec<(String, String)> = url::Url::parse(&url)
        .expect("url")
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("client_id".to_owned(), "c".to_owned()),
            ("state".to_owned(), "s".to_owned()),
            ("nonce".to_owned(), "n 1".to_owned()),
        ]
    );
}

#[test]
fn random_tokens_are_distinct_and_url_safe() {
    let a = random_token().expect("token");
    let b = random_token().expect("token");
    assert_ne!(a, b);
    assert!(
        a.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "{a}"
    );
}

#[test]
fn html_is_escaped() {
    assert_eq!(
        escape(r#"<a href="x">&'"#),
        "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;"
    );
}

#[tokio::test]
async fn unknown_state_without_a_test_id_records_nothing() {
    let state = test_state();
    let uri = format!("/callback?{}", query(&[("state", "forged"), ("code", "c")]));
    // No flow yet, then a flow the runner started without a test_id.
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_server, issuer) = mock_op(None).await;
    start_flow(&state, &issuer, "").await;
    let (status, _, _) = send(&state, get(&uri)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(state.results().is_empty());
}
