//! The RP harness routes, speaking the protocol `conformance/run_tests.py`
//! drives (see `conformance/adding-conformance-profiles.md`, "Harness protocol").

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs_identity_model::{
    Claims, DiscoveryClient, IdTokenValidationOptions, IdentityError, JwksClient, PkceChallenge,
    ProviderMetadata, TokenClient, UserInfoClient, ValidationOptions, authorization_url,
    validate_id_token,
};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::classify::{Reason, TokenFacts, classify_discovery, classify_id_token};
use crate::rplog::{ActiveTest, RpLog};

/// Scopes requested by every flow (the Python harness's default).
const DEFAULT_SCOPE: &str = "openid profile email address phone";
const SUCCESS: &str = "success";
const ERROR: &str = "error";
/// The runner fails a module whose rejection could not be tied to its flow
/// after that flow had already succeeded.
const CONFLICT: &str = "conflict";

/// Static harness settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Browser-facing base URL; the redirect URI is `<rp_base_url>/callback`.
    pub rp_base_url: String,
    /// Base directory of the per-test RP logs.
    pub log_dir: PathBuf,
    /// Lets the library talk to `http://` endpoints (unit tests only).
    pub allow_http: bool,
    /// The HTTP client every library client is built with.
    pub http: reqwest::Client,
}

/// The library clients whose caches `/clear-cache` drops. Both logins of a
/// rotation module run between two clears, so they share one JWKS client.
struct Clients {
    discovery: Arc<DiscoveryClient>,
    jwks: Arc<JwksClient>,
}

impl Clients {
    fn new(config: &Config) -> Self {
        Self {
            discovery: Arc::new(
                DiscoveryClient::builder()
                    .http_client(config.http.clone())
                    .allow_http(config.allow_http)
                    .build(),
            ),
            jwks: Arc::new(
                JwksClient::builder()
                    .http_client(config.http.clone())
                    .allow_http(config.allow_http)
                    .build(),
            ),
        }
    }
}

/// Per-flow state between `/authorize` and `/callback`.
struct Session {
    issuer: String,
    state: String,
    nonce: String,
    code_verifier: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    skip_userinfo: bool,
    test_id: String,
    test: ActiveTest,
}

struct Inner {
    config: Config,
    log: RpLog,
    clients: RwLock<Clients>,
    sessions: Mutex<Vec<Session>>,
    results: Mutex<HashMap<String, Value>>,
    /// The most recent flow's test, for rejections that carry no session key.
    last_flow: Mutex<Option<(String, ActiveTest)>>,
}

/// Shared harness state.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    pub fn new(config: Config) -> Self {
        let clients = Clients::new(&config);
        let log = RpLog::new(config.log_dir.clone());
        Self(Arc::new(Inner {
            config,
            log,
            clients: RwLock::new(clients),
            sessions: Mutex::new(Vec::new()),
            results: Mutex::new(HashMap::new()),
            last_flow: Mutex::new(None),
        }))
    }

    fn discovery(&self) -> Arc<DiscoveryClient> {
        let clients = self
            .0
            .clients
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&clients.discovery)
    }

    fn jwks(&self) -> Arc<JwksClient> {
        let clients = self
            .0
            .clients
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&clients.jwks)
    }

    fn clear_caches(&self) {
        let fresh = Clients::new(&self.0.config);
        *self
            .0
            .clients
            .write()
            .unwrap_or_else(PoisonError::into_inner) = fresh;
    }

    fn results(&self) -> std::sync::MutexGuard<'_, HashMap<String, Value>> {
        self.0
            .results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, test_id: &str, outcome: Value) {
        if !test_id.is_empty() {
            self.results().insert(test_id.to_owned(), outcome);
        }
    }

    fn record_success(&self, test_id: &str) {
        self.record(test_id, json!({"test_id": test_id, "status": SUCCESS}));
    }

    fn record_error(&self, test_id: &str, reason: Reason, detail: &str) {
        self.record(test_id, error_record(test_id, reason, detail));
    }

    /// Files a rejection made before the flow's session was known under the
    /// most recent flow's test (the runner drives one module at a time).
    fn record_unattributed(&self, reason: Reason, detail: &str) {
        let last = self
            .0
            .last_flow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some((test_id, test)) = last.filter(|(test_id, _)| !test_id.is_empty()) else {
            return;
        };
        self.0
            .log
            .error(&test, &format!("REJECTED: {}: {detail}", reason.as_str()));
        let mut results = self.results();
        if let Some(record) = merge_unattributed(results.get(&test_id), &test_id, reason, detail) {
            results.insert(test_id, record);
        }
    }

    fn take_session(&self, state: &str) -> Option<Session> {
        let mut sessions = self
            .0
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let index = sessions
            .iter()
            .position(|s| bool::from(s.state.as_bytes().ct_eq(state.as_bytes())))?;
        Some(sessions.swap_remove(index))
    }
}

fn error_record(test_id: &str, reason: Reason, detail: &str) -> Value {
    json!({
        "test_id": test_id,
        "status": ERROR,
        "error": format!("{}: {detail}", reason.as_str()),
    })
}

/// The record for a rejection that carries no session key, or `None` to keep
/// the existing one: the first rejection stands, and a rejection after a
/// recorded success becomes a `conflict` so it can never pass the module.
fn merge_unattributed(
    existing: Option<&Value>,
    test_id: &str,
    reason: Reason,
    detail: &str,
) -> Option<Value> {
    match existing
        .and_then(|v| v.get("status"))
        .and_then(Value::as_str)
    {
        None => Some(error_record(test_id, reason, detail)),
        Some(SUCCESS) => Some(json!({
            "test_id": test_id,
            "status": CONFLICT,
            "error": format!("{}: {detail} (after a recorded success)", reason.as_str()),
        })),
        Some(_) => None,
    }
}

/// The harness router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/health", get(health))
        .route("/clear-cache", post(clear_cache))
        .route("/discover", get(discover))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback_get).post(callback_post))
        .route("/results/{test_id}", get(result))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "conformance-rp-rust",
        "op_facing_base_url": state.0.config.rp_base_url,
    }))
}

async fn clear_cache(State(state): State<AppState>) -> Json<Value> {
    state.clear_caches();
    state
        .0
        .log
        .info(&ActiveTest::default(), "Cleared discovery and JWKS caches");
    Json(json!({"status": "ok", "cleared": ["discovery", "jwks"]}))
}

async fn result(State(state): State<AppState>, Path(test_id): Path<String>) -> Response {
    match state.results().get(&test_id) {
        Some(outcome) => Json(outcome.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct DiscoverParams {
    issuer: String,
    #[serde(default)]
    test_id: String,
    #[serde(default)]
    test_name: String,
    #[serde(default)]
    profile: String,
}

async fn discover(State(state): State<AppState>, Query(params): Query<DiscoverParams>) -> Response {
    let test = ActiveTest::new(&params.profile, &params.test_name);
    match discover_issuer(&state, &test, &params.test_id, &params.issuer).await {
        Ok(metadata) => {
            state.record_success(&params.test_id);
            state.0.log.info(
                &test,
                &format!(
                    "ACCEPTED: discovery document fetched and validated for issuer {:?}",
                    metadata.issuer
                ),
            );
            Json(json!({"status": "ok", "issuer": metadata.issuer})).into_response()
        }
        Err(response) => response,
    }
}

/// Discovers `issuer` (exact issuer match, OIDC Discovery 1.0 §4.3). A failure
/// is recorded for `test_id` and answered 502: the RP refused the flow.
async fn discover_issuer(
    state: &AppState,
    test: &ActiveTest,
    test_id: &str,
    issuer: &str,
) -> Result<ProviderMetadata, Response> {
    state.discovery().discover(issuer).await.map_err(|error| {
        let reason = classify_discovery(&error);
        let detail = error.to_string();
        state
            .0
            .log
            .error(test, &format!("REJECTED: {}: {detail}", reason.as_str()));
        state.record_error(test_id, reason, &detail);
        page(
            StatusCode::BAD_GATEWAY,
            "Discovery Failed",
            &format!("{}: {detail}", reason.as_str()),
        )
    })
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_owned()
}

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    test_id: String,
    #[serde(default)]
    test_name: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    skip_userinfo: String,
    #[serde(default = "default_scope")]
    scope: String,
}

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let test = ActiveTest::new(&params.profile, &params.test_name);
    let log = &state.0.log;
    // A new flow starts with no recorded outcome, so a flow that never reaches
    // the callback cannot be read as an earlier flow's result.
    state.results().remove(&params.test_id);
    *state
        .0
        .last_flow
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some((params.test_id.clone(), test.clone()));

    let metadata = match discover_issuer(&state, &test, &params.test_id, &params.issuer).await {
        Ok(metadata) => metadata,
        Err(response) => return response,
    };

    let redirect_uri = format!("{}/callback", state.0.config.rp_base_url);
    let flow = random_token().and_then(|s| Ok((s, random_token()?, PkceChallenge::generate()?)));
    let (flow_state, nonce, pkce) = match flow {
        Ok(flow) => flow,
        Err(error) => {
            return refuse(
                &state,
                &test,
                &params.test_id,
                Reason::DiscoveryFailed,
                &error.to_string(),
            );
        }
    };
    let url = authorization_url(
        &metadata,
        &params.client_id,
        &redirect_uri,
        &params.scope,
        &flow_state,
        &pkce,
    )
    .and_then(|url| with_nonce(&url, &nonce));
    let url = match url {
        Ok(url) => url,
        Err(error) => {
            return refuse(
                &state,
                &test,
                &params.test_id,
                Reason::DiscoveryFailed,
                &error.to_string(),
            );
        }
    };

    state
        .0
        .sessions
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Session {
            issuer: params.issuer.clone(),
            state: flow_state,
            nonce,
            code_verifier: pkce.code_verifier,
            client_id: params.client_id,
            client_secret: params.client_secret,
            redirect_uri,
            skip_userinfo: params.skip_userinfo.eq_ignore_ascii_case("true"),
            test_id: params.test_id,
            test: test.clone(),
        });
    log.info(
        &test,
        &format!(
            "ACCEPTED: discovery issuer {:?} matches expected; redirecting to OP",
            params.issuer
        ),
    );
    log.info(&test, &format!("Redirecting to OP: {url}"));
    Redirect::to(&url).into_response()
}

/// A flow the harness refused before reaching the OP (502).
fn refuse(
    state: &AppState,
    test: &ActiveTest,
    test_id: &str,
    reason: Reason,
    detail: &str,
) -> Response {
    state
        .0
        .log
        .error(test, &format!("REJECTED: {}: {detail}", reason.as_str()));
    state.record_error(test_id, reason, detail);
    page(
        StatusCode::BAD_GATEWAY,
        "Flow Refused",
        &format!("{}: {detail}", reason.as_str()),
    )
}

/// 32 random bytes, base64url-encoded (state and nonce).
fn random_token() -> rs_identity_model::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| IdentityError::Configuration(format!("random source failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Appends the OIDC `nonce` (Core 1.0 §3.1.2.1) the library's URL builder
/// does not take.
fn with_nonce(url: &str, nonce: &str) -> rs_identity_model::Result<String> {
    let mut parsed = url::Url::parse(url)
        .map_err(|e| IdentityError::Configuration(format!("invalid authorization URL: {e}")))?;
    parsed.query_pairs_mut().append_pair("nonce", nonce);
    Ok(parsed.into())
}

async fn callback_get(
    State(state): State<AppState>,
    Query(params): Query<Vec<(String, String)>>,
) -> Response {
    handle_callback(&state, &params).await
}

async fn callback_post(
    State(state): State<AppState>,
    Form(params): Form<Vec<(String, String)>>,
) -> Response {
    handle_callback(&state, &params).await
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Outcome of one callback step: either carry on, or the response to send
/// after the rejection was recorded.
type Step<T> = Result<T, Response>;

async fn handle_callback(state: &AppState, params: &[(String, String)]) -> Response {
    let Some(session) = param(params, "state").and_then(|s| state.take_session(s)) else {
        let detail = format!("unknown or missing state {:?}", param(params, "state"));
        state.record_unattributed(Reason::StateValidation, &detail);
        return page(StatusCode::BAD_REQUEST, "State Validation Failed", &detail);
    };
    match complete_flow(state, &session, params).await {
        Ok(body) => {
            state.record_success(&session.test_id);
            body
        }
        Err(response) => response,
    }
}

async fn complete_flow(
    state: &AppState,
    session: &Session,
    params: &[(String, String)],
) -> Step<Response> {
    let log = &state.0.log;
    let test = &session.test;
    let reject = |status: StatusCode, reason: Reason, detail: &str| -> Response {
        log.error(test, &format!("REJECTED: {}: {detail}", reason.as_str()));
        state.record_error(&session.test_id, reason, detail);
        page(
            status,
            "Flow Rejected",
            &format!("{}: {detail}", reason.as_str()),
        )
    };

    if let Some(error) = param(params, "error") {
        let description = param(params, "error_description").unwrap_or_default();
        return Err(reject(
            StatusCode::BAD_REQUEST,
            Reason::AuthorizationError,
            &format!("{error} {description}"),
        ));
    }
    let Some(code) = param(params, "code") else {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            Reason::MissingCode,
            "callback has no code",
        ));
    };

    let metadata = discover_issuer(state, test, &session.test_id, &session.issuer).await?;

    let token_client = TokenClient::builder()
        .client_id(&session.client_id)
        .client_secret(&session.client_secret)
        .token_endpoint(&metadata.token_endpoint)
        .http_client(state.0.config.http.clone())
        .allow_http(state.0.config.allow_http)
        .build()
        .map_err(|e| {
            reject(
                StatusCode::BAD_GATEWAY,
                Reason::TokenExchange,
                &e.to_string(),
            )
        })?;
    let tokens = token_client
        .exchange_code(code, &session.redirect_uri, Some(&session.code_verifier))
        .await
        .map_err(|e| {
            reject(
                StatusCode::BAD_REQUEST,
                Reason::TokenExchange,
                &e.to_string(),
            )
        })?;
    let Some(id_token) = tokens.id_token.as_deref() else {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            Reason::MissingIdToken,
            "token response has no id_token",
        ));
    };

    let claims = validate(state, session, &metadata, id_token)
        .await
        .map_err(|(reason, detail)| reject(StatusCode::BAD_REQUEST, reason, &detail))?;
    log.info(
        test,
        "ACCEPTED: id_token validated by rs-identity-model (signature, issuer, audience, expiry, nonce, ID-Token profile)",
    );

    let subject = claims.subject.clone().unwrap_or_default();
    let mut userinfo = Value::Null;
    if let (false, Some(endpoint)) = (session.skip_userinfo, metadata.userinfo_endpoint.as_deref())
    {
        let fetched = match UserInfoClient::builder()
            .userinfo_endpoint(endpoint)
            .http_client(state.0.config.http.clone())
            .allow_http(state.0.config.allow_http)
            .build()
        {
            Ok(client) => {
                client
                    .fetch_with_subject(&tokens.access_token, &subject)
                    .await
            }
            Err(error) => Err(error),
        };
        // OIDC Core 1.0 §5.3.2: a UserInfo response whose sub differs from the
        // ID token's is fatal, as is any response the RP cannot use.
        let response = fetched.map_err(|e| {
            reject(
                StatusCode::BAD_REQUEST,
                Reason::UserinfoValidation,
                &e.to_string(),
            )
        })?;
        userinfo = serde_json::to_value(&response).unwrap_or(Value::Null);
    }

    log.info(
        test,
        &format!(
            "ACCEPTED: authentication successful for issuer={:?}, sub={subject:?}",
            session.issuer
        ),
    );
    Ok(success_page(&claims, &userinfo))
}

/// Validates the ID token (OIDC Core 1.0 §3.1.3.7): signature against the
/// OP's JWKS, `iss`, `aud` = `client_id`, `exp`/`iat`, `nonce` and the
/// ID-Token profile. A rejection comes back classified.
async fn validate(
    state: &AppState,
    session: &Session,
    metadata: &ProviderMetadata,
    id_token: &str,
) -> Result<Claims, (Reason, String)> {
    let jwks = state.jwks();
    let base = ValidationOptions::builder()
        .issuer(&metadata.issuer)
        .audience(&session.client_id)
        .build();
    let profile = IdTokenValidationOptions::builder()
        .client_id(&session.client_id)
        .nonce(&session.nonce)
        .build();
    match validate_id_token(id_token, &jwks, &metadata.jwks_uri, &base, &profile).await {
        Ok(claims) => Ok(claims),
        Err(error) => {
            let mut facts = TokenFacts::inspect(id_token);
            if let (IdentityError::Validation(_), Some(alg)) = (&error, facts.alg.as_deref()) {
                let kid = TokenFacts::header_kid(id_token);
                facts.key_resolved = jwks
                    .resolve_signing_key(&metadata.jwks_uri, &kid, alg)
                    .await
                    .is_ok();
            }
            Err((classify_id_token(&error, &facts), error.to_string()))
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn page(status: StatusCode, title: &str, detail: &str) -> Response {
    (
        status,
        Html(format!(
            "<h1>{}</h1><p>{}</p>",
            escape(title),
            escape(detail)
        )),
    )
        .into_response()
}

/// Shows the ID token and UserInfo claims, so the suite sees the RP used them.
/// Every value comes from the OP and is escaped.
fn success_page(claims: &Claims, userinfo: &Value) -> Response {
    let mut body = String::from("<h1>Authentication Successful</h1>");
    for (label, value) in [("Subject", &claims.subject), ("Issuer", &claims.issuer)] {
        let value = value.as_deref().unwrap_or("N/A");
        body.push_str(&format!("<p>{label}: {}</p>", escape(value)));
    }
    if let Some(map) = userinfo.as_object() {
        body.push_str("<h2>UserInfo Claims</h2>");
        for (key, value) in map {
            body.push_str(&format!(
                "<p>{}: {}</p>",
                escape(key),
                escape(&value.to_string())
            ));
        }
    }
    (StatusCode::OK, Html(body)).into_response()
}

#[cfg(test)]
mod tests;
