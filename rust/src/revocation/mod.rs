//! OAuth 2.0 token revocation client (RFC 7009).
//!
//! [`RevocationClient`] POSTs a token to the protected revocation endpoint as
//! `application/x-www-form-urlencoded` (RFC 7009 §2.1), authenticates the
//! revoking client with `client_secret_basic` (default) or `client_secret_post`
//! (RFC 6749 §2.3), and reports success or a typed error. A revocation success
//! carries **no** response body: the server returns HTTP 200 regardless of
//! whether the token was valid, expired, already revoked, or unknown, and MUST
//! NOT differentiate between those cases so a client cannot probe token state
//! (§2.1). [`RevocationClient::revoke`] therefore returns `Ok(())` for any 2xx
//! response without parsing a body. A non-2xx OAuth error response — typically
//! HTTP 401 `invalid_client` or HTTP 400 `unsupported_token_type` — becomes an
//! [`IdentityError::TokenEndpoint`] (§2.2.1, RFC 6749 §5.2). Resolve the
//! endpoint from the `revocation_endpoint` field of the discovery document
//! (RFC 8414 §2).
//!
//! This mirrors the Go reference (`go/pkg/revocation`) and satisfies
//! `spec/conformance/revocation.json` (`REV-001`..`REV-005`); see also
//! `spec/capabilities.md`.
//!
//! ```no_run
//! # async fn run() -> rs_identity_model::Result<()> {
//! use rs_identity_model::RevocationClient;
//!
//! let client = RevocationClient::builder()
//!     .client_id("rs-client")
//!     .client_secret("rs-secret")
//!     .revocation_endpoint("https://issuer.example.com/revoke")
//!     .build()?;
//! // Revoking an unknown or already-invalid token also succeeds (§2.1).
//! client.revoke("the-token", Some("refresh_token")).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client as HttpClient;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};

use crate::client_auth::{OAuthErrorBody, basic_auth_header, body_snippet, read_capped_body};
use crate::token::ClientAuthMethod;
use crate::{IdentityError, Result};

/// Default per-request timeout so a hung endpoint cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Placeholder printed in place of secret material in `Debug` output.
const REDACTED: &str = "<redacted>";

/// Form parameters owned by the request and client-authentication logic. They
/// can never be set or overridden via [`RevocationClientBuilder::extra_param`],
/// so caller-supplied extras cannot contradict the request's identity or the
/// token being revoked.
const RESERVED_PARAMS: &[&str] = &["token", "token_type_hint", "client_id", "client_secret"];

/// An async OAuth 2.0 token revocation client (RFC 7009).
///
/// Construct one with [`RevocationClient::builder`]. A single client should be
/// reused across calls so the underlying connection pool is shared.
pub struct RevocationClient {
    http: HttpClient,
    revocation_endpoint: String,
    client_id: String,
    client_secret: String,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

// A hand-written Debug that never prints the client secret; its presence is
// implied by the confidential-client shape, so only a marker is shown.
impl std::fmt::Debug for RevocationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationClient")
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("auth_method", &self.auth_method)
            .field("extra_params", &self.extra_params)
            .field("timeout", &self.timeout)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl RevocationClient {
    /// Returns a builder for configuring a [`RevocationClient`].
    pub fn builder() -> RevocationClientBuilder {
        RevocationClientBuilder::new()
    }

    /// Performs an OAuth 2.0 token revocation request (RFC 7009 §2.1, REV-001):
    /// POSTs `token` to the revocation endpoint as
    /// `application/x-www-form-urlencoded`, authenticates the revoking client,
    /// and reports success.
    ///
    /// The server returns HTTP 200 regardless of whether the token was valid,
    /// expired, already revoked, or unknown, and MUST NOT differentiate between
    /// those cases (§2.1). `revoke` therefore returns `Ok(())` for any 2xx
    /// response without parsing a body — revoking an unknown or already-invalid
    /// token succeeds by design (§2.2).
    ///
    /// `token_type_hint` is the optional `token_type_hint` parameter
    /// (RFC 7009 §2.1), typically `"access_token"` or `"refresh_token"`. It is a
    /// per-call argument because it varies with the token being revoked; the
    /// server MAY use it to optimise lookup but MUST accept the request even if
    /// it is wrong (REV-002). Pass `None` (or an empty string) to omit it.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::TokenEndpoint`] — a non-2xx OAuth error response,
    ///   typically HTTP 401 `invalid_client` (REV-004) or HTTP 400
    ///   `unsupported_token_type` (REV-003).
    /// - [`IdentityError::Http`] — a transport failure or non-OAuth error body.
    /// - [`IdentityError::Configuration`] — an empty `token`, or a non-https
    ///   endpoint without `allow_http`.
    pub async fn revoke(&self, token: &str, token_type_hint: Option<&str>) -> Result<()> {
        // Require an https endpoint unless http was explicitly allowed.
        let scheme = self.revocation_endpoint.to_ascii_lowercase();
        let scheme_ok =
            scheme.starts_with("https://") || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Configuration(format!(
                "revocation endpoint {:?} must use https (enable allow_http for development)",
                self.revocation_endpoint
            )));
        }

        // token is REQUIRED (RFC 7009 §2.1). An empty token would be sent as-is
        // and the server's anti-scanning HTTP 200 (§2.1) would make revoke
        // return Ok, misleading the caller into believing something was revoked.
        // Reject it locally like the half-credential guard in the builder.
        if token.is_empty() {
            return Err(IdentityError::Configuration(
                "token is required (RFC 7009 §2.1)".to_string(),
            ));
        }

        let mut form: Vec<(String, String)> = vec![("token".to_string(), token.to_string())];
        // token_type_hint is optional; an empty hint is treated as unset.
        if let Some(hint) = token_type_hint
            && !hint.is_empty()
        {
            form.push(("token_type_hint".to_string(), hint.to_string()));
        }

        // Client authentication (RFC 7009 §2.1, RFC 6749 §2.3). A Basic header
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
            .post(&self.revocation_endpoint)
            .timeout(self.timeout)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .form(&form);
        if let Some(header) = basic_header {
            request = request.header(AUTHORIZATION, header);
        }

        let response = request
            .send()
            .await
            .map_err(|e| IdentityError::Http(format!("post {}: {e}", self.revocation_endpoint)))?;

        let status = response.status();
        // Drain a bounded amount so the connection can be reused. A revocation
        // success (§2.2) carries no meaningful body; the error path reuses the
        // buffered body below.
        let body = read_capped_body(response).await?;

        // Any 2xx is success regardless of token validity (§2.1/§2.2, REV-001).
        if status.is_success() {
            return Ok(());
        }

        // Non-2xx is an OAuth error (RFC 7009 §2.2.1, RFC 6749 §5.2, REV-003/004).
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
        Err(IdentityError::Http(format!(
            "revocation request to {} failed: HTTP {} with non-OAuth body: {}",
            self.revocation_endpoint,
            status.as_u16(),
            body_snippet(&body)
        )))
    }
}

/// Builder for [`RevocationClient`]. Obtain one via [`RevocationClient::builder`].
#[derive(Default)]
pub struct RevocationClientBuilder {
    http: Option<HttpClient>,
    revocation_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

// Redacting Debug: the builder holds the client secret before the client is
// built, so it must not print it either.
impl std::fmt::Debug for RevocationClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationClientBuilder")
            .field("revocation_endpoint", &self.revocation_endpoint)
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

impl RevocationClientBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the client identifier (required).
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the client secret (required). The revocation endpoint is protected,
    /// so both `client_id` and `client_secret` MUST be supplied (RFC 7009 §2.1).
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Sets the revocation endpoint URL (required). Resolve it from the
    /// `revocation_endpoint` field of the discovery document (RFC 8414 §2,
    /// REV-005).
    pub fn revocation_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(endpoint.into());
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
    /// [`extra_param`]: RevocationClientBuilder::extra_param
    pub fn extra_params(mut self, params: HashMap<String, String>) -> Self {
        self.extra_params.extend(params);
        self
    }

    /// Uses `client` for revocation requests instead of a default
    /// [`reqwest::Client`], letting callers share a connection pool or supply
    /// custom transport configuration.
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Bounds each revocation request with a per-request timeout. A non-positive
    /// duration is ignored and the default (30s) is retained.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits an `http://` revocation endpoint, which is otherwise rejected.
    /// Intended for local development and integration tests against non-TLS
    /// providers; do not enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Builds the [`RevocationClient`].
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if `client_id`, `client_secret`, or
    /// `revocation_endpoint` is missing or empty. Both credentials are required
    /// because the revocation endpoint is protected (RFC 7009 §2.1); a
    /// half-credential would only fail server-side.
    pub fn build(self) -> Result<RevocationClient> {
        let client_id = self.client_id.unwrap_or_default();
        if client_id.is_empty() {
            return Err(IdentityError::Configuration(
                "client_id is required".to_string(),
            ));
        }
        let client_secret = self.client_secret.unwrap_or_default();
        if client_secret.is_empty() {
            return Err(IdentityError::Configuration(
                "client_secret is required: the revocation endpoint requires client authentication with both client_id and client_secret (RFC 7009 §2.1)"
                    .to_string(),
            ));
        }
        let revocation_endpoint = self.revocation_endpoint.unwrap_or_default();
        if revocation_endpoint.is_empty() {
            return Err(IdentityError::Configuration(
                "revocation_endpoint is required".to_string(),
            ));
        }
        Ok(RevocationClient {
            http: self.http.unwrap_or_else(crate::http::secure_client),
            revocation_endpoint,
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

    /// Parses a request's form body into key/value pairs.
    fn form_of(req: &Request) -> HashMap<String, String> {
        url::form_urlencoded::parse(&req.body)
            .into_owned()
            .collect()
    }

    fn client(endpoint: &str) -> RevocationClientBuilder {
        RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .revocation_endpoint(endpoint)
            .allow_http(true)
    }

    async fn mount(server: &MockServer, template: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    // REV-001: a 200 with an empty body succeeds and the request is a POST
    // carrying `token` as form-urlencoded.
    #[tokio::test]
    async fn success_empty_body_returns_ok() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds");

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

    // REV-001: a 200 with an empty JSON object body also succeeds (parity with
    // spec/test-fixtures/revocation/revoke-success-empty-object.json).
    #[tokio::test]
    async fn success_empty_object_returns_ok() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200).set_body_string("{}")).await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds with empty JSON object");
    }

    // REV-001: any 2xx status (here 204 No Content) is a success.
    #[tokio::test]
    async fn success_204_returns_ok() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(204)).await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds on 204");
    }

    // REV-001 (anti-scanning §2.1): revoking an unknown/already-invalid token is
    // indistinguishable from revoking a valid one — both yield the same 200 Ok.
    #[tokio::test]
    async fn unknown_token_succeeds_like_valid() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let rc = client(&format!("{}/revoke", server.uri())).build().unwrap();
        rc.revoke("a-valid-token", None)
            .await
            .expect("valid token revocation succeeds");
        rc.revoke("an-unknown-token", None)
            .await
            .expect("unknown token revocation also succeeds (no scanning oracle)");
    }

    // REV-002: the hint is sent as token_type_hint; token is always present.
    #[tokio::test]
    async fn token_type_hint_is_sent() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", Some("refresh_token"))
            .await
            .expect("revocation succeeds");

        let requests = server.received_requests().await.unwrap();
        let form = form_of(requests.last().unwrap());
        assert_eq!(form.get("token").map(String::as_str), Some("the-token"));
        assert_eq!(
            form.get("token_type_hint").map(String::as_str),
            Some("refresh_token")
        );
    }

    // REV-002: a wrong hint MUST NOT fail the request — the server accepts it
    // regardless of hint correctness.
    #[tokio::test]
    async fn wrong_token_type_hint_still_succeeds() {
        let server = MockServer::start().await;
        // Only respond when the (wrong) hint was actually sent, proving it did
        // not abort the request client-side.
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token_type_hint=access_token"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            // The token is really a refresh token; the hint is deliberately wrong.
            .revoke("the-token", Some("access_token"))
            .await
            .expect("wrong hint must not fail the request");
    }

    // REV-003: a 400 with an OAuth error body maps to TokenEndpoint carrying
    // unsupported_token_type and the HTTP status (parity with
    // spec/test-fixtures/revocation/error-unsupported-token-type.json).
    #[tokio::test]
    async fn unsupported_token_type_maps_to_token_endpoint() {
        let server = MockServer::start().await;
        let body = r#"{"error":"unsupported_token_type","error_description":"The authorization server does not support revocation of the presented token type"}"#;
        mount(&server, ResponseTemplate::new(400).set_body_string(body)).await;

        let err = client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect_err("400 must fail");

        match err {
            IdentityError::TokenEndpoint {
                error,
                description,
                status,
                ..
            } => {
                assert_eq!(error, "unsupported_token_type");
                assert_eq!(
                    description.as_deref(),
                    Some(
                        "The authorization server does not support revocation of the presented token type"
                    )
                );
                assert_eq!(status, 400);
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    // REV-004: a 401 with an OAuth error body maps to TokenEndpoint carrying
    // invalid_client and the HTTP status (parity with
    // spec/test-fixtures/revocation/error-invalid-client.json).
    #[tokio::test]
    async fn invalid_client_maps_to_token_endpoint() {
        let server = MockServer::start().await;
        let body =
            r#"{"error":"invalid_client","error_description":"Client authentication failed"}"#;
        mount(&server, ResponseTemplate::new(401).set_body_string(body)).await;

        let err = client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
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

    // REV-005: the endpoint is resolved from the discovery document's
    // revocation_endpoint and used verbatim.
    #[tokio::test]
    async fn endpoint_resolved_from_discovery() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        // A discovery document advertising revocation_endpoint (parity with
        // spec/test-fixtures/revocation/discovery-with-revocation.json).
        let disco = format!(
            r#"{{
                "issuer": "{base}",
                "authorization_endpoint": "{base}/authorize",
                "token_endpoint": "{base}/token",
                "revocation_endpoint": "{base}/revoke",
                "jwks_uri": "{base}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }}"#,
            base = server.uri()
        );
        let meta: ProviderMetadata = serde_json::from_str(&disco).expect("parse discovery");
        let endpoint = meta
            .revocation_endpoint
            .expect("revocation_endpoint present");

        client(&endpoint)
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.last().unwrap().url.path(), "/revoke");
    }

    // client_secret_basic (default) sends a Basic header whose credentials are
    // form-urlencoded, and no credentials appear in the body.
    #[tokio::test]
    async fn client_secret_basic_is_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds");

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

    // client_secret_post places credentials in the body and sets no Basic header.
    #[tokio::test]
    async fn client_secret_post_uses_body() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        client(&format!("{}/revoke", server.uri()))
            .auth_method(ClientAuthMethod::ClientSecretPost)
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds");

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

    // Extra params appear in the body, but reserved params cannot be injected.
    #[tokio::test]
    async fn extra_params_applied_reserved_guarded() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        client(&format!("{}/revoke", server.uri()))
            .extra_param("resource", "urn:test:api")
            // reserved: must be ignored, not override the revoked token.
            .extra_param("token", "hacked")
            .extra_param("client_id", "attacker")
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect("revocation succeeds");

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

    // A non-2xx response without a recognisable OAuth body is a plain Http error.
    #[tokio::test]
    async fn non_oauth_error_body_maps_to_http() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(500).set_body_string("upstream boom"),
        )
        .await;

        let err = client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect_err("500 must fail");
        assert!(matches!(err, IdentityError::Http(_)), "{err:?}");
    }

    // The default https-only gate rejects an http endpoint.
    #[tokio::test]
    async fn https_required_by_default() {
        let err = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .revocation_endpoint("http://insecure.example/revoke")
            .build()
            .unwrap()
            .revoke("the-token", None)
            .await
            .expect_err("http endpoint must be rejected");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }

    // RFC 7009 §2.1: an empty token is rejected locally so the anti-scanning 200
    // cannot make revoke falsely report success (DEC-004).
    #[tokio::test]
    async fn empty_token_is_rejected() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let err = client(&format!("{}/revoke", server.uri()))
            .build()
            .unwrap()
            .revoke("", None)
            .await
            .expect_err("empty token must be rejected");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");

        // No request should have reached the server.
        let requests = server.received_requests().await.unwrap();
        assert!(requests.is_empty(), "empty token must not hit the network");
    }

    // RFC 7009 §2.1: the builder rejects a half-credential (missing secret) and
    // other missing required fields.
    #[test]
    fn builder_requires_id_secret_and_endpoint() {
        let missing_secret = RevocationClient::builder()
            .client_id("rs-client")
            .revocation_endpoint("https://issuer.example/revoke")
            .build();
        assert!(matches!(
            missing_secret,
            Err(IdentityError::Configuration(_))
        ));

        let missing_id = RevocationClient::builder()
            .client_secret("rs-secret")
            .revocation_endpoint("https://issuer.example/revoke")
            .build();
        assert!(matches!(missing_id, Err(IdentityError::Configuration(_))));

        let missing_endpoint = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .build();
        assert!(matches!(
            missing_endpoint,
            Err(IdentityError::Configuration(_))
        ));

        let ok = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .revocation_endpoint("https://issuer.example/revoke")
            .build();
        assert!(ok.is_ok());
    }

    // The client and its builder never print the client secret in Debug output.
    #[test]
    fn debug_redacts_client_secret() {
        let builder = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("s3cr3t-value")
            .revocation_endpoint("https://issuer.example/revoke");
        assert!(!format!("{builder:?}").contains("s3cr3t-value"));

        let client = builder.build().unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("s3cr3t-value"), "client leaked secret: {dbg}");
        assert!(dbg.contains(REDACTED), "no redaction marker: {dbg}");
        assert!(dbg.contains("rs-client"), "client_id should stay visible");
    }
}
