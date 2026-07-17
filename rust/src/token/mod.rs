//! Token endpoint client: client credentials, authorization code, PKCE.
//!
//! [`TokenClient`] performs the OAuth 2.0 client credentials grant
//! (RFC 6749 §4.4) and the authorization code grant (RFC 6749 §4.1.3), the
//! latter with optional PKCE (RFC 7636). Client authentication is
//! `client_secret_basic` (default) or `client_secret_post` (RFC 6749 §2.3).
//! Successful responses decode into a typed [`TokenResponse`] (RFC 6749 §5.1);
//! error responses become an [`IdentityError::TokenEndpoint`] (RFC 6749 §5.2).
//!
//! [`PkceChallenge`] and [`authorization_url`] implement the PKCE transform and
//! authorization request (RFC 7636 §4.1–§4.3).
//!
//! Behavioural contract: `spec/conformance/client-credentials.json`
//! (`CC-001`..`CC-006`) and `spec/conformance/authorization-code.json`
//! (`ACG-001`..`ACG-006`); see also `spec/capabilities.md`.
//!
//! ```no_run
//! # async fn run() -> identity_model::Result<()> {
//! use identity_model::TokenClient;
//!
//! let client = TokenClient::builder()
//!     .client_id("my-client")
//!     .client_secret("my-secret")
//!     .token_endpoint("https://issuer.example.com/token")
//!     .build()?;
//! let token = client.client_credentials(Some("api")).await?;
//! println!("access_token = {}", token.access_token);
//! # Ok(())
//! # }
//! ```

mod pkce;
mod response;

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::Client as HttpClient;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};

use crate::{IdentityError, Result};

pub use pkce::{
    CHALLENGE_METHOD_S256, PkceChallenge, authorization_url, s256_challenge, valid_code_verifier,
};
pub use response::TokenResponse;

/// The `client_credentials` grant type (RFC 6749 §4.4).
const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";
/// The `authorization_code` grant type (RFC 6749 §4.1.3).
const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";

/// Default per-request timeout so a hung endpoint cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Caps the token response read into memory (memory-exhaustion DoS guard).
/// Token responses are small.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Parameters owned by the grant and client-authentication logic. They can
/// never be set or overridden via [`TokenClientBuilder::extra_param`], so that
/// caller-supplied extras cannot contradict the request's identity or grant
/// shape.
const RESERVED_PARAMS: &[&str] = &[
    "grant_type",
    "client_id",
    "client_secret",
    "code",
    "redirect_uri",
    "code_verifier",
    "scope",
];

/// How client credentials are presented to the token endpoint (RFC 6749 §2.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// Send `client_id` and `client_secret` in an HTTP Basic `Authorization`
    /// header (RFC 6749 §2.3.1). This is the default.
    #[default]
    ClientSecretBasic,
    /// Send `client_id` and `client_secret` as form parameters in the request
    /// body (RFC 6749 §2.3.1).
    ClientSecretPost,
}

/// An async OAuth 2.0 token endpoint client.
///
/// Construct one with [`TokenClient::builder`]. A single client should be
/// reused across calls so the underlying connection pool is shared.
pub struct TokenClient {
    http: HttpClient,
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

impl TokenClient {
    /// Returns a builder for configuring a [`TokenClient`].
    pub fn builder() -> TokenClientBuilder {
        TokenClientBuilder::new()
    }

    /// Performs the OAuth 2.0 client credentials grant (RFC 6749 §4.4, CC-001):
    /// POSTs `grant_type=client_credentials` to the token endpoint and returns
    /// the typed [`TokenResponse`].
    ///
    /// Authentication uses the configured [`ClientAuthMethod`]
    /// (`client_secret_basic` by default). When `scope` is `Some`, it is sent
    /// as a single space-delimited `scope` parameter (CC-005).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::TokenEndpoint`] — a non-2xx OAuth error response
    ///   (CC-004).
    /// - [`IdentityError::Http`] — a transport failure or non-OAuth error body.
    /// - [`IdentityError::Deserialization`] — a 2xx body that is not a valid
    ///   token response.
    pub async fn client_credentials(&self, scope: Option<&str>) -> Result<TokenResponse> {
        let mut form: Vec<(String, String)> = vec![(
            "grant_type".to_string(),
            GRANT_CLIENT_CREDENTIALS.to_string(),
        )];
        if let Some(scope) = scope {
            form.push(("scope".to_string(), scope.to_string()));
        }
        self.do_request(form, self.client_secret.as_deref()).await
    }

    /// Performs the OAuth 2.0 authorization code grant (RFC 6749 §4.1.3,
    /// ACG-001): POSTs `grant_type=authorization_code` with `code`,
    /// `redirect_uri`, and (when configured) `client_id` to the token endpoint
    /// and returns the typed [`TokenResponse`].
    ///
    /// When `code_verifier` is `Some`, it is validated against RFC 7636 §4.1
    /// and sent as the `code_verifier` parameter (ACG-004). A configured client
    /// secret still authenticates the request via the configured method; a
    /// public client (no secret) is identified by `client_id` in the body.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Validation`] — a `code_verifier` outside the 43–128
    ///   unreserved-character range.
    /// - [`IdentityError::TokenEndpoint`] — a non-2xx OAuth error response
    ///   (ACG-005).
    /// - [`IdentityError::Http`] / [`IdentityError::Deserialization`] — as for
    ///   [`client_credentials`](TokenClient::client_credentials).
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        if let Some(verifier) = code_verifier
            && !valid_code_verifier(verifier)
        {
            return Err(IdentityError::Validation(
                "code_verifier must be 43-128 unreserved characters".to_string(),
            ));
        }

        let mut form: Vec<(String, String)> = vec![
            (
                "grant_type".to_string(),
                GRANT_AUTHORIZATION_CODE.to_string(),
            ),
            ("code".to_string(), code.to_string()),
        ];
        if !redirect_uri.is_empty() {
            form.push(("redirect_uri".to_string(), redirect_uri.to_string()));
        }
        if let Some(verifier) = code_verifier {
            form.push(("code_verifier".to_string(), verifier.to_string()));
        }
        self.do_request(form, self.client_secret.as_deref()).await
    }

    /// Applies client authentication and extra parameters, POSTs `form` as
    /// `application/x-www-form-urlencoded`, and decodes the response: a 2xx body
    /// into [`TokenResponse`], otherwise an OAuth error body into
    /// [`IdentityError::TokenEndpoint`] (status checked before decode).
    async fn do_request(
        &self,
        mut form: Vec<(String, String)>,
        client_secret: Option<&str>,
    ) -> Result<TokenResponse> {
        // Require an https endpoint unless http was explicitly allowed.
        let scheme = self.token_endpoint.to_ascii_lowercase();
        let scheme_ok =
            scheme.starts_with("https://") || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Configuration(format!(
                "token endpoint {:?} must use https (enable allow_http for development)",
                self.token_endpoint
            )));
        }

        // Client authentication (RFC 6749 §2.3). A Basic header is built for the
        // request; post/public credentials go in the form body.
        let mut basic_header: Option<String> = None;
        match client_secret {
            // Public client: identify via client_id in the body.
            None => {
                if !self.client_id.is_empty() {
                    form.push(("client_id".to_string(), self.client_id.clone()));
                }
            }
            Some(secret) => match self.auth_method {
                ClientAuthMethod::ClientSecretPost => {
                    form.push(("client_id".to_string(), self.client_id.clone()));
                    form.push(("client_secret".to_string(), secret.to_string()));
                }
                ClientAuthMethod::ClientSecretBasic => {
                    basic_header = Some(basic_auth_header(&self.client_id, secret));
                }
            },
        }

        // Extra params are applied last but never override reserved grant or
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
            .post(&self.token_endpoint)
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
            .map_err(|e| IdentityError::Http(format!("post {}: {e}", self.token_endpoint)))?;

        let status = response.status();
        let body = read_capped_body(response).await?;

        // Status before decode: a non-2xx response is an OAuth error
        // (RFC 6749 §5.2, CC-004 / ACG-005).
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
                "token request to {} failed: HTTP {} with non-OAuth body: {}",
                self.token_endpoint,
                status.as_u16(),
                body_snippet(&body)
            )));
        }

        let token: TokenResponse = serde_json::from_slice(&body).map_err(|e| {
            IdentityError::Deserialization(format!(
                "parse token response from {}: {e}",
                self.token_endpoint
            ))
        })?;
        if token.access_token.is_empty() {
            return Err(IdentityError::Http(format!(
                "token response from {} is missing access_token",
                self.token_endpoint
            )));
        }
        Ok(token)
    }
}

/// A typed OAuth 2.0 error response body (RFC 6749 §5.2), used only to decode
/// the endpoint reply before mapping to [`IdentityError::TokenEndpoint`].
#[derive(serde::Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error_uri: Option<String>,
}

/// Builds an HTTP Basic `Authorization` header value from `client_id` and
/// `client_secret`.
///
/// RFC 6749 §2.3.1 requires the credentials to be form-urlencoded before the
/// Basic base64 encoding so reserved characters survive; `reqwest`'s
/// `basic_auth` does NOT url-encode, so the header is built manually to match
/// the Go reference and the RFC.
fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let credentials = format!(
        "{}:{}",
        form_urlencode(client_id),
        form_urlencode(client_secret)
    );
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

/// `application/x-www-form-urlencoded` encoding of a single value
/// (RFC 6749 §2.3.1).
fn form_urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reads a response body in chunks, rejecting one that exceeds
/// [`MAX_BODY_BYTES`] before it is fully buffered.
async fn read_capped_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| IdentityError::Http(format!("read token response: {e}")))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(IdentityError::Http(format!(
                "token response exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Returns a short, single-line view of an unexpected response body for error
/// messages.
fn body_snippet(body: &[u8]) -> String {
    const MAX: usize = 200;
    let text = String::from_utf8_lossy(body);
    let text = text.trim().replace('\n', " ");
    if text.chars().count() > MAX {
        format!("{}…", text.chars().take(MAX).collect::<String>())
    } else {
        text
    }
}

/// Builder for [`TokenClient`]. Obtain one via [`TokenClient::builder`].
#[derive(Default)]
pub struct TokenClientBuilder {
    http: Option<HttpClient>,
    token_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_method: ClientAuthMethod,
    extra_params: HashMap<String, String>,
    timeout: Duration,
    allow_http: bool,
}

impl TokenClientBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the client identifier (required).
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the client secret. Omit for a public client (authorization code
    /// grant), which is then identified by `client_id` in the request body.
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Sets the token endpoint URL (required).
    pub fn token_endpoint(mut self, token_endpoint: impl Into<String>) -> Self {
        self.token_endpoint = Some(token_endpoint.into());
        self
    }

    /// Selects the client authentication method (RFC 6749 §2.3). The default is
    /// [`ClientAuthMethod::ClientSecretBasic`].
    pub fn auth_method(mut self, method: ClientAuthMethod) -> Self {
        self.auth_method = method;
        self
    }

    /// Adds a single extra form parameter for provider-specific extensions
    /// (e.g. `resource` or `audience`). Reserved grant/auth parameters are
    /// never overridden.
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.insert(key.into(), value.into());
        self
    }

    /// Adds multiple extra form parameters. See [`extra_param`].
    ///
    /// [`extra_param`]: TokenClientBuilder::extra_param
    pub fn extra_params(mut self, params: HashMap<String, String>) -> Self {
        self.extra_params.extend(params);
        self
    }

    /// Uses `client` for token requests instead of a default
    /// [`reqwest::Client`], letting callers share a connection pool or supply
    /// custom transport configuration (CC-006).
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Bounds each token request with a per-request timeout. A non-positive
    /// duration is ignored and the default (30s) is retained.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits an `http://` token endpoint, which is otherwise rejected.
    /// Intended for local development and integration tests against non-TLS
    /// providers; do not enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Builds the [`TokenClient`].
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if `client_id` or `token_endpoint` is
    /// missing or empty (AC-6).
    pub fn build(self) -> Result<TokenClient> {
        let client_id = self.client_id.unwrap_or_default();
        if client_id.is_empty() {
            return Err(IdentityError::Configuration(
                "client_id is required".to_string(),
            ));
        }
        let token_endpoint = self.token_endpoint.unwrap_or_default();
        if token_endpoint.is_empty() {
            return Err(IdentityError::Configuration(
                "token_endpoint is required".to_string(),
            ));
        }
        Ok(TokenClient {
            http: self.http.unwrap_or_default(),
            token_endpoint,
            client_id,
            client_secret: self.client_secret,
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
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    /// A minimal successful token response body.
    const SUCCESS_BODY: &str =
        r#"{"access_token":"at-abc","token_type":"Bearer","expires_in":3600}"#;

    /// Mounts a single POST handler on `/token` returning `template`.
    async fn mount_token(server: &MockServer, template: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    /// Parses a request's form body into key/value pairs.
    fn form_of(req: &Request) -> HashMap<String, String> {
        url::form_urlencoded::parse(&req.body)
            .into_owned()
            .collect()
    }

    fn client(endpoint: &str) -> TokenClientBuilder {
        TokenClient::builder()
            .client_id("client-1")
            .client_secret("s3cr3t")
            .token_endpoint(endpoint)
            .allow_http(true)
    }

    // CC-001: a client credentials grant returns a typed response.
    #[tokio::test]
    async fn client_credentials_returns_typed_response() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        )
        .await;

        let token = client(&format!("{}/token", server.uri()))
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect("grant succeeds");

        assert_eq!(token.access_token, "at-abc");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, 3600);
    }

    // CC-002: client_secret_basic is the default — a Basic header is sent and no
    // credentials appear in the body.
    #[tokio::test]
    async fn client_secret_basic_is_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_BODY))
            .mount(&server)
            .await;

        client(&format!("{}/token", server.uri()))
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect("grant succeeds");

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
        // "client-1":"s3cr3t" form-urlencoded then base64: no reserved chars,
        // so it equals base64("client-1:s3cr3t").
        assert_eq!(
            auth,
            format!("Basic {}", BASE64_STANDARD.encode("client-1:s3cr3t"))
        );
        let form = form_of(req);
        assert!(!form.contains_key("client_id"), "no client_id in body");
        assert!(
            !form.contains_key("client_secret"),
            "no client_secret in body"
        );
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
    }

    // CC-003: client_secret_post places credentials in the body and sets no
    // Basic header.
    #[tokio::test]
    async fn client_secret_post_uses_body() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        )
        .await;

        client(&format!("{}/token", server.uri()))
            .auth_method(ClientAuthMethod::ClientSecretPost)
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect("grant succeeds");

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        assert!(
            req.headers.get("authorization").is_none(),
            "no Basic header"
        );
        let form = form_of(req);
        assert_eq!(form.get("client_id").map(String::as_str), Some("client-1"));
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("s3cr3t")
        );
    }

    // CC-004 / ACG-005: a non-2xx OAuth error body maps to TokenEndpoint.
    #[tokio::test]
    async fn error_response_maps_to_token_endpoint() {
        let server = MockServer::start().await;
        let body = r#"{"error":"invalid_client","error_description":"bad secret","error_uri":"https://err.example/1"}"#;
        mount_token(&server, ResponseTemplate::new(401).set_body_string(body)).await;

        let err = client(&format!("{}/token", server.uri()))
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect_err("error response must fail");

        match err {
            IdentityError::TokenEndpoint {
                error,
                description,
                error_uri,
                status,
            } => {
                assert_eq!(error, "invalid_client");
                assert_eq!(description.as_deref(), Some("bad secret"));
                assert_eq!(error_uri.as_deref(), Some("https://err.example/1"));
                assert_eq!(status, 401);
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    // A non-2xx response without a recognisable OAuth body is a plain Http error.
    #[tokio::test]
    async fn non_oauth_error_body_maps_to_http() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(500).set_body_string("upstream boom"),
        )
        .await;

        let err = client(&format!("{}/token", server.uri()))
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect_err("500 must fail");

        assert!(matches!(err, IdentityError::Http(_)), "{err:?}");
    }

    // CC-005: WithScopes sends a single space-delimited scope parameter.
    #[tokio::test]
    async fn scope_is_space_delimited() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        )
        .await;

        client(&format!("{}/token", server.uri()))
            .build()
            .unwrap()
            .client_credentials(Some("a b"))
            .await
            .expect("grant succeeds");

        let requests = server.received_requests().await.unwrap();
        let form = form_of(requests.last().unwrap());
        assert_eq!(form.get("scope").map(String::as_str), Some("a b"));
    }

    // CC-006: extra params appear in the body and the supplied http client is
    // used; reserved params cannot be overridden.
    #[tokio::test]
    async fn extra_params_applied_reserved_guarded() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        )
        .await;

        let custom = reqwest::Client::builder().build().unwrap();
        client(&format!("{}/token", server.uri()))
            .http_client(custom)
            .extra_param("resource", "urn:test:api")
            // reserved: must be ignored, not override the grant type.
            .extra_param("grant_type", "hacked")
            .build()
            .unwrap()
            .client_credentials(None)
            .await
            .expect("grant succeeds");

        let requests = server.received_requests().await.unwrap();
        let form = form_of(requests.last().unwrap());
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("urn:test:api")
        );
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials"),
            "reserved grant_type must not be overridden"
        );
    }

    // ACG-001 / ACG-004: exchange_code sends grant, code, redirect_uri, and
    // code_verifier.
    #[tokio::test]
    async fn exchange_code_sends_expected_form() {
        let server = MockServer::start().await;
        mount_token(
            &server,
            ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        )
        .await;

        // Public client: build without a secret.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        TokenClient::builder()
            .client_id("public-client")
            .token_endpoint(format!("{}/token", server.uri()))
            .allow_http(true)
            .build()
            .unwrap()
            .exchange_code("auth-code-1", "https://app.example/cb", Some(verifier))
            .await
            .expect("exchange succeeds");

        let requests = server.received_requests().await.unwrap();
        let req = requests.last().unwrap();
        assert!(
            req.headers.get("authorization").is_none(),
            "public client has no Basic header"
        );
        let form = form_of(req);
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code-1"));
        assert_eq!(
            form.get("redirect_uri").map(String::as_str),
            Some("https://app.example/cb")
        );
        assert_eq!(
            form.get("code_verifier").map(String::as_str),
            Some(verifier)
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("public-client")
        );
    }

    // AC-2: an invalid code_verifier is rejected before any request is sent.
    #[tokio::test]
    async fn exchange_code_rejects_invalid_verifier() {
        let client = TokenClient::builder()
            .client_id("public-client")
            .token_endpoint("https://issuer.example/token")
            .build()
            .unwrap();
        let err = client
            .exchange_code("code", "https://app/cb", Some("too-short"))
            .await
            .expect_err("short verifier must error");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // AC-6: the builder rejects missing required fields.
    #[test]
    fn builder_requires_client_id_and_endpoint() {
        let missing_id = TokenClient::builder()
            .token_endpoint("https://issuer.example/token")
            .build();
        assert!(matches!(missing_id, Err(IdentityError::Configuration(_))));

        let missing_endpoint = TokenClient::builder().client_id("c").build();
        assert!(matches!(
            missing_endpoint,
            Err(IdentityError::Configuration(_))
        ));

        let ok = TokenClient::builder()
            .client_id("c")
            .token_endpoint("https://issuer.example/token")
            .build();
        assert!(ok.is_ok());
    }

    // The default (https-only) endpoint gate rejects an http endpoint.
    #[tokio::test]
    async fn https_required_by_default() {
        let client = TokenClient::builder()
            .client_id("c")
            .client_secret("s")
            .token_endpoint("http://insecure.example/token")
            .build()
            .unwrap();
        let err = client
            .client_credentials(None)
            .await
            .expect_err("http endpoint must be rejected");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }

    // CC-002: Basic credentials with reserved characters are form-urlencoded
    // before base64 (RFC 6749 §2.3.1).
    #[test]
    fn basic_auth_header_urlencodes_credentials() {
        let header = basic_auth_header("id with space", "p@ss:word");
        let expected = format!(
            "Basic {}",
            BASE64_STANDARD.encode("id+with+space:p%40ss%3Aword")
        );
        assert_eq!(header, expected);
    }
}
