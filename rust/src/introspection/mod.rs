//! OAuth 2.0 token introspection client (RFC 7662).
//!
//! [`IntrospectionClient`] POSTs a token to the protected introspection
//! endpoint as `application/x-www-form-urlencoded` (RFC 7662 §2.1),
//! authenticates the introspecting client with `client_secret_basic` (default)
//! or `client_secret_post` (RFC 6749 §2.3), and returns the typed
//! [`Introspection`] response — whose only guaranteed member is `active`, with
//! all other members reachable, unknown ones via [`Introspection::extra`]
//! (RFC 7662 §2.2). A non-2xx OAuth error response — typically HTTP 401
//! `invalid_client` — becomes an [`IdentityError::TokenEndpoint`]
//! (RFC 7662 §2.3, RFC 6749 §5.2). Resolve the endpoint from the
//! `introspection_endpoint` field of the discovery document (RFC 8414 §2).
//!
//! This mirrors the Go reference (`go/pkg/introspection`) and satisfies
//! `spec/vectors/introspection.json` (`INTR-001`..`INTR-006`); see also
//! `spec/capabilities.md`.
//!
//! ```no_run
//! # async fn run() -> rs_identity_model::Result<()> {
//! use rs_identity_model::IntrospectionClient;
//!
//! let client = IntrospectionClient::builder()
//!     .client_id("rs-client")
//!     .client_secret("rs-secret")
//!     .introspection_endpoint("https://issuer.example.com/introspect")
//!     .build()?;
//! let result = client.introspect("the-token", Some("access_token")).await?;
//! println!("active = {}", result.active);
//! # Ok(())
//! # }
//! ```

mod response;

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client as HttpClient;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};

use crate::client_auth::{OAuthErrorBody, basic_auth_header, body_snippet, read_capped_body};
use crate::token::ClientAuthMethod;
use crate::{IdentityError, Result};

pub use response::{Introspection, IntrospectionAudience};

/// Default per-request timeout so a hung endpoint cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Placeholder printed in place of secret material in `Debug` output.
const REDACTED: &str = "<redacted>";

/// Form parameters owned by the request and client-authentication logic. They
/// can never be set or overridden via [`IntrospectionClientBuilder::extra_param`],
/// so caller-supplied extras cannot contradict the request's identity or the
/// token being introspected.
const RESERVED_PARAMS: &[&str] = &["token", "token_type_hint", "client_id", "client_secret"];

/// An async OAuth 2.0 token introspection client (RFC 7662).
///
/// Construct one with [`IntrospectionClient::builder`]. A single client should
/// be reused across calls so the underlying connection pool is shared.
pub struct IntrospectionClient {
    http: HttpClient,
    introspection_endpoint: String,
    client_id: String,
    client_secret: String,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

// A hand-written Debug that never prints the client secret; its presence is
// implied by the confidential-client shape, so only a marker is shown.
impl std::fmt::Debug for IntrospectionClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionClient")
            .field("introspection_endpoint", &self.introspection_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("auth_method", &self.auth_method)
            .field("extra_params", &self.extra_params)
            .field("timeout", &self.timeout)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl IntrospectionClient {
    /// Returns a builder for configuring an [`IntrospectionClient`].
    pub fn builder() -> IntrospectionClientBuilder {
        IntrospectionClientBuilder::new()
    }

    /// Performs an OAuth 2.0 token introspection request (RFC 7662 §2.1,
    /// INTR-001): POSTs `token` to the introspection endpoint as
    /// `application/x-www-form-urlencoded`, authenticates the introspecting
    /// client, and returns the typed [`Introspection`].
    ///
    /// `token_type_hint` is the optional `token_type_hint` parameter
    /// (RFC 7662 §2.1), typically `"access_token"` or `"refresh_token"`. It is a
    /// per-call argument because it varies with the token being introspected;
    /// the server MAY use it to optimise lookup but MUST NOT fail if it is wrong
    /// (INTR-004). Pass `None` (or an empty string) to omit it.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::TokenEndpoint`] — a non-2xx OAuth error response,
    ///   typically HTTP 401 `invalid_client` (INTR-005).
    /// - [`IdentityError::Http`] — a transport failure or non-OAuth error body.
    /// - [`IdentityError::Deserialization`] — a 2xx body that is not a valid
    ///   introspection response (e.g. missing the required `active` member).
    /// - [`IdentityError::Configuration`] — a non-https endpoint without
    ///   `allow_http`.
    pub async fn introspect(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<Introspection> {
        // Require an https endpoint unless http was explicitly allowed.
        let scheme = self.introspection_endpoint.to_ascii_lowercase();
        let scheme_ok =
            scheme.starts_with("https://") || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Configuration(format!(
                "introspection endpoint {:?} must use https (enable allow_http for development)",
                self.introspection_endpoint
            )));
        }

        let mut form: Vec<(String, String)> = vec![("token".to_string(), token.to_string())];
        // token_type_hint is optional; an empty hint is treated as unset.
        if let Some(hint) = token_type_hint
            && !hint.is_empty()
        {
            form.push(("token_type_hint".to_string(), hint.to_string()));
        }

        // Client authentication (RFC 7662 §2.1, RFC 6749 §2.3). A Basic header
        // is built for the request; post credentials go in the form body. The
        // builder guarantees both credentials are non-empty.
        let mut basic_header: Option<String> = None;
        match self.auth_method {
            ClientAuthMethod::ClientSecretPost => {
                form.push(("client_id".to_string(), self.client_id.clone()));
                form.push(("client_secret".to_string(), self.client_secret.clone()));
            }
            ClientAuthMethod::ClientSecretBasic => {
                basic_header = Some(basic_auth_header(&self.client_id, &self.client_secret));
            }
        }

        // Extra params are applied last but never override reserved request or
        // client-auth parameters (whether or not already present — on the Basic
        // path client_id is absent from the body yet must not be injectable).
        for (key, value) in &self.extra_params {
            if RESERVED_PARAMS.contains(&key.as_str()) || form.iter().any(|(k, _)| k == key) {
                continue;
            }
            form.push((key.clone(), value.clone()));
        }

        let mut request = self
            .http
            .post(&self.introspection_endpoint)
            .timeout(self.timeout)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&form);
        if let Some(header) = basic_header {
            request = request.header(AUTHORIZATION, header);
        }

        let response = request.send().await.map_err(|e| {
            IdentityError::Http(format!("post {}: {e}", self.introspection_endpoint))
        })?;

        let status = response.status();
        let body = read_capped_body(response).await?;

        // Status before decode: a non-2xx response is an OAuth error
        // (RFC 7662 §2.3, RFC 6749 §5.2, INTR-005).
        if !status.is_success() {
            if let Ok(err) = serde_json::from_slice::<OAuthErrorBody>(&body)
                && !err.error.is_empty()
            {
                return Err(IdentityError::TokenEndpoint {
                    error: err.error,
                    description: err.error_description,
                    error_uri: err.error_uri,
                    status: status.as_u16(),
                });
            }
            return Err(IdentityError::Http(format!(
                "introspection request to {} failed: HTTP {} with non-OAuth body: {}",
                self.introspection_endpoint,
                status.as_u16(),
                body_snippet(&body)
            )));
        }

        serde_json::from_slice(&body).map_err(|e| {
            IdentityError::Deserialization(format!(
                "parse introspection response from {}: {e}",
                self.introspection_endpoint
            ))
        })
    }
}

/// Builder for [`IntrospectionClient`]. Obtain one via
/// [`IntrospectionClient::builder`].
#[derive(Default)]
pub struct IntrospectionClientBuilder {
    http: Option<HttpClient>,
    introspection_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

// Redacting Debug: the builder holds the client secret before the client is
// built, so it must not print it either.
impl std::fmt::Debug for IntrospectionClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionClientBuilder")
            .field("introspection_endpoint", &self.introspection_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| REDACTED),
            )
            .field("auth_method", &self.auth_method)
            .field("extra_params", &self.extra_params)
            .field("timeout", &self.timeout)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl IntrospectionClientBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the client identifier (required).
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the client secret (required). The introspection endpoint is
    /// protected, so both `client_id` and `client_secret` MUST be supplied
    /// (RFC 7662 §2.1).
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Sets the introspection endpoint URL (required). Resolve it from the
    /// `introspection_endpoint` field of the discovery document (RFC 8414 §2,
    /// INTR-006).
    pub fn introspection_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.introspection_endpoint = Some(endpoint.into());
        self
    }

    /// Selects the client authentication method (RFC 6749 §2.3). The default is
    /// [`ClientAuthMethod::ClientSecretBasic`].
    pub fn auth_method(mut self, method: ClientAuthMethod) -> Self {
        self.auth_method = method;
        self
    }

    /// Adds a single extra form parameter for provider-specific extensions.
    /// Reserved request/auth parameters (`token`, `token_type_hint`,
    /// `client_id`, `client_secret`) are never overridden.
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.insert(key.into(), value.into());
        self
    }

    /// Adds multiple extra form parameters. See [`extra_param`].
    ///
    /// [`extra_param`]: IntrospectionClientBuilder::extra_param
    pub fn extra_params(mut self, params: HashMap<String, String>) -> Self {
        self.extra_params.extend(params);
        self
    }

    /// Uses `client` for introspection requests instead of a default
    /// [`reqwest::Client`], letting callers share a connection pool or supply
    /// custom transport configuration.
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Bounds each introspection request with a per-request timeout. A
    /// non-positive duration is ignored and the default (30s) is retained.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits an `http://` introspection endpoint, which is otherwise rejected.
    /// Intended for local development and integration tests against non-TLS
    /// providers; do not enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Builds the [`IntrospectionClient`].
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if `client_id`, `client_secret`, or
    /// `introspection_endpoint` is missing or empty. Both credentials are
    /// required because the introspection endpoint is protected (RFC 7662 §2.1);
    /// a half-credential would only fail server-side.
    pub fn build(self) -> Result<IntrospectionClient> {
        let client_id = self.client_id.unwrap_or_default();
        if client_id.is_empty() {
            return Err(IdentityError::Configuration(
                "client_id is required".to_string(),
            ));
        }
        let client_secret = self.client_secret.unwrap_or_default();
        if client_secret.is_empty() {
            return Err(IdentityError::Configuration(
                "client_secret is required: the introspection endpoint requires client authentication with both client_id and client_secret (RFC 7662 §2.1)"
                    .to_string(),
            ));
        }
        let introspection_endpoint = self.introspection_endpoint.unwrap_or_default();
        if introspection_endpoint.is_empty() {
            return Err(IdentityError::Configuration(
                "introspection_endpoint is required".to_string(),
            ));
        }
        Ok(IntrospectionClient {
            http: self.http.unwrap_or_else(crate::http::secure_client),
            introspection_endpoint,
            client_id,
            client_secret,
            auth_method: self.auth_method,
            extra_params: self.extra_params,
            timeout: if self.timeout.is_zero() {
                DEFAULT_TIMEOUT
            } else {
                self.timeout
            },
            allow_http: self.allow_http,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderMetadata;
    use wiremock::matchers::{body_string_contains, header, header_exists, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const ACTIVE_BODY: &str = r#"{"active":true,"scope":"read","client_id":"rs-client","token_type":"Bearer","exp":1419356238,"extension_field":"twenty-seven"}"#;

    /// Parses a request's form body into key/value pairs.
    fn form_of(req: &Request) -> HashMap<String, String> {
        url::form_urlencoded::parse(&req.body)
            .into_owned()
            .collect()
    }

    fn client(endpoint: &str) -> IntrospectionClientBuilder {
        IntrospectionClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .introspection_endpoint(endpoint)
            .allow_http(true)
    }

    async fn mount(server: &MockServer, template: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    // INTR-001: an active token yields active=true with standard metadata and
    // the request is a POST carrying `token`; unknown members stay reachable.
    #[tokio::test]
    async fn active_token_returns_typed_response() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(ACTIVE_BODY),
        )
        .await;

        let ir = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect("introspection succeeds");

        assert!(ir.active);
        assert_eq!(ir.scope.as_deref(), Some("read"));
        assert_eq!(ir.client_id.as_deref(), Some("rs-client"));
        assert_eq!(ir.token_type.as_deref(), Some("Bearer"));
        assert_eq!(ir.exp, Some(1419356238));
        assert_eq!(
            ir.extra.get("extension_field").and_then(|v| v.as_str()),
            Some("twenty-seven")
        );

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        assert_eq!(req.method.to_string(), "POST");
        assert_eq!(
            req.headers.get("content-type").unwrap().to_str().unwrap(),
            "application/x-www-form-urlencoded"
        );
        let form = form_of(req);
        assert_eq!(form.get("token").map(String::as_str), Some("the-token"));
    }

    // INTR-002: an inactive token yields active=false and requires no other
    // member.
    #[tokio::test]
    async fn inactive_token_returns_active_false() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(r#"{"active":false}"#),
        )
        .await;

        let ir = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("garbage", None)
            .await
            .expect("introspection succeeds");
        assert!(!ir.active);
        assert_eq!(ir.username, None);
    }

    // INTR-003 (default): client_secret_basic sends a Basic header whose
    // credentials are form-urlencoded, and no credentials appear in the body.
    #[tokio::test]
    async fn client_secret_basic_is_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ACTIVE_BODY))
            .mount(&server)
            .await;

        client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect("introspection succeeds");

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
        // "rs-client":"rs-secret" have no reserved chars, so this equals
        // base64("rs-client:rs-secret").
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        assert_eq!(
            auth,
            format!("Basic {}", BASE64_STANDARD.encode("rs-client:rs-secret"))
        );
        let form = form_of(req);
        assert!(!form.contains_key("client_id"), "no client_id in body");
        assert!(
            !form.contains_key("client_secret"),
            "no client_secret in body"
        );
    }

    // INTR-003 (post): client_secret_post places credentials in the body and
    // sets no Basic header.
    #[tokio::test]
    async fn client_secret_post_uses_body() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(ACTIVE_BODY),
        )
        .await;

        client(&format!("{}/introspect", server.uri()))
            .auth_method(ClientAuthMethod::ClientSecretPost)
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect("introspection succeeds");

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        assert!(
            req.headers.get("authorization").is_none(),
            "no Basic header"
        );
        let form = form_of(req);
        assert_eq!(form.get("client_id").map(String::as_str), Some("rs-client"));
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("rs-secret")
        );
    }

    // INTR-004: the hint is sent as token_type_hint; token is always present.
    #[tokio::test]
    async fn token_type_hint_is_sent() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(ACTIVE_BODY),
        )
        .await;

        client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", Some("refresh_token"))
            .await
            .expect("introspection succeeds");

        let requests = server.received_requests().await.unwrap();
        let form = form_of(requests.last().unwrap());
        assert_eq!(form.get("token").map(String::as_str), Some("the-token"));
        assert_eq!(
            form.get("token_type_hint").map(String::as_str),
            Some("refresh_token")
        );
    }

    // INTR-004: a wrong hint MUST NOT fail the request — the server returns a
    // normal response regardless of hint correctness.
    #[tokio::test]
    async fn wrong_token_type_hint_still_succeeds() {
        let server = MockServer::start().await;
        // Only respond when the (wrong) hint was actually sent, proving it did
        // not abort the request client-side.
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(body_string_contains("token_type_hint=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ACTIVE_BODY))
            .mount(&server)
            .await;

        let ir = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            // The token is really an access token; the hint is deliberately wrong.
            .introspect("the-token", Some("refresh_token"))
            .await
            .expect("wrong hint must not fail the request");
        assert!(ir.active);
    }

    // INTR-005: a 401 with an OAuth error body maps to TokenEndpoint carrying
    // error, description, and the HTTP status.
    #[tokio::test]
    async fn error_response_maps_to_token_endpoint() {
        let server = MockServer::start().await;
        let body =
            r#"{"error":"invalid_client","error_description":"Client authentication failed"}"#;
        mount(&server, ResponseTemplate::new(401).set_body_string(body)).await;

        let err = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect_err("401 must fail");

        match err {
            IdentityError::TokenEndpoint {
                error,
                description,
                status,
                ..
            } => {
                assert_eq!(error, "invalid_client");
                assert_eq!(description.as_deref(), Some("Client authentication failed"));
                assert_eq!(status, 401);
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    // A non-2xx response without a recognisable OAuth body is a plain Http error.
    #[tokio::test]
    async fn non_oauth_error_body_maps_to_http() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(500).set_body_string("upstream boom"),
        )
        .await;

        let err = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect_err("500 must fail");
        assert!(matches!(err, IdentityError::Http(_)), "{err:?}");
    }

    // A 2xx body missing the required `active` member is a Deserialization error.
    #[tokio::test]
    async fn missing_active_is_deserialization_error() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(r#"{"scope":"read"}"#),
        )
        .await;

        let err = client(&format!("{}/introspect", server.uri()))
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect_err("missing active must fail");
        assert!(matches!(err, IdentityError::Deserialization(_)), "{err:?}");
    }

    // INTR-006: the endpoint is resolved from the discovery document's
    // introspection_endpoint and used verbatim.
    #[tokio::test]
    async fn endpoint_resolved_from_discovery() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(ACTIVE_BODY),
        )
        .await;

        // A discovery document advertising introspection_endpoint (parity with
        // spec/test-fixtures/introspection/discovery-with-introspection.json).
        let disco = format!(
            r#"{{
                "issuer": "{base}",
                "authorization_endpoint": "{base}/authorize",
                "token_endpoint": "{base}/token",
                "introspection_endpoint": "{base}/introspect",
                "jwks_uri": "{base}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }}"#,
            base = server.uri()
        );
        let meta: ProviderMetadata = serde_json::from_str(&disco).expect("parse discovery");
        let endpoint = meta
            .introspection_endpoint
            .expect("introspection_endpoint present");

        let ir = client(&endpoint)
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect("introspection succeeds");
        assert!(ir.active);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.last().unwrap().url.path(), "/introspect");
    }

    // Extra params appear in the body, but reserved params cannot be injected.
    #[tokio::test]
    async fn extra_params_applied_reserved_guarded() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ACTIVE_BODY))
            .mount(&server)
            .await;

        client(&format!("{}/introspect", server.uri()))
            .extra_param("resource", "urn:test:api")
            // reserved: must be ignored, not override the introspected token.
            .extra_param("token", "hacked")
            .extra_param("client_id", "attacker")
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect("introspection succeeds");

        let requests = server.received_requests().await.unwrap();
        let form = form_of(requests.last().unwrap());
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("urn:test:api")
        );
        assert_eq!(
            form.get("token").map(String::as_str),
            Some("the-token"),
            "reserved token must not be overridden"
        );
        assert!(
            !form.contains_key("client_id"),
            "reserved client_id must not be injectable on the Basic path"
        );
    }

    // The default https-only gate rejects an http endpoint.
    #[tokio::test]
    async fn https_required_by_default() {
        let err = IntrospectionClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .introspection_endpoint("http://insecure.example/introspect")
            .build()
            .unwrap()
            .introspect("the-token", None)
            .await
            .expect_err("http endpoint must be rejected");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }

    // RFC 7662 §2.1: the builder rejects a half-credential (missing secret) and
    // other missing required fields.
    #[test]
    fn builder_requires_id_secret_and_endpoint() {
        let missing_secret = IntrospectionClient::builder()
            .client_id("rs-client")
            .introspection_endpoint("https://issuer.example/introspect")
            .build();
        assert!(matches!(
            missing_secret,
            Err(IdentityError::Configuration(_))
        ));

        let missing_id = IntrospectionClient::builder()
            .client_secret("rs-secret")
            .introspection_endpoint("https://issuer.example/introspect")
            .build();
        assert!(matches!(missing_id, Err(IdentityError::Configuration(_))));

        let missing_endpoint = IntrospectionClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .build();
        assert!(matches!(
            missing_endpoint,
            Err(IdentityError::Configuration(_))
        ));

        let ok = IntrospectionClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .introspection_endpoint("https://issuer.example/introspect")
            .build();
        assert!(ok.is_ok());
    }

    // The client and its builder never print the client secret in Debug output.
    #[test]
    fn debug_redacts_client_secret() {
        let builder = IntrospectionClient::builder()
            .client_id("rs-client")
            .client_secret("s3cr3t-value")
            .introspection_endpoint("https://issuer.example/introspect");
        assert!(!format!("{builder:?}").contains("s3cr3t-value"));

        let client = builder.build().unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("s3cr3t-value"), "client leaked secret: {dbg}");
        assert!(dbg.contains(REDACTED), "no redaction marker: {dbg}");
        assert!(dbg.contains("rs-client"), "client_id should stay visible");
    }
}
