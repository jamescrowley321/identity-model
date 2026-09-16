//! OAuth 2.0 Token Revocation (RFC 7009).
//!
//! Revoking a token tells the authorization server to invalidate it and, at the
//! server's discretion, related tokens issued from the same grant. The request
//! is a client-authenticated `application/x-www-form-urlencoded` POST carrying
//! the `token` to revoke and an optional `token_type_hint`.
//!
//! ## The response tells you nothing about the token
//!
//! RFC 7009 §2.2 requires the server to answer HTTP 200 whether the token was
//! valid, already expired, already revoked, or never existed. That is a privacy
//! property, not an oversight: a response that differed would let an attacker
//! probe the endpoint to learn which token values are live. This client mirrors
//! it — [`RevocationClient::revoke`] returns `Ok(())` for any 200, and callers
//! must not read success as evidence that the token existed (`REV-001`).
//!
//! ## Example
//!
//! ```no_run
//! # use rs_identity_model::revocation::RevocationClient;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = RevocationClient::builder()
//!     .client_id("my-client")
//!     .client_secret("my-secret")
//!     .revocation_endpoint("https://issuer.example.com/oauth2/revoke")
//!     .build()?;
//!
//! client.revoke("the-token", Some("refresh_token")).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Conformance: `spec/vectors/revocation.json` (`REV-001` … `REV-005`).

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

impl std::fmt::Debug for RevocationClient {
    /// Redacts `client_secret` so a client cannot leak credentials into logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationClient")
            .field("revocation_endpoint", &self.revocation_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("auth_method", &self.auth_method)
            .field("extra_params", &self.extra_params)
            .field("timeout", &self.timeout)
            .field("allow_http", &self.allow_http)
            .finish()
    }
}

impl RevocationClient {
    /// Returns a builder for configuring a [`RevocationClient`].
    pub fn builder() -> RevocationClientBuilder {
        RevocationClientBuilder::new()
    }

    /// Revokes a token (RFC 7009 §2.1, `REV-001`).
    ///
    /// POSTs `token` to the revocation endpoint as
    /// `application/x-www-form-urlencoded` and authenticates the client.
    ///
    /// `token_type_hint` is the optional `token_type_hint` parameter, typically
    /// `"access_token"` or `"refresh_token"` (`REV-002`). The server MAY use it
    /// to optimise lookup but MUST still accept the request if it is wrong, so
    /// an incorrect hint is not an error. Pass `None` (or an empty string) to
    /// omit it.
    ///
    /// # Success says nothing about the token
    ///
    /// Any HTTP 200 yields `Ok(())`, whether the body is empty or an empty JSON
    /// object, and regardless of whether the token was valid, expired, already
    /// revoked, or unknown (RFC 7009 §2.2). Treating `Ok(())` as proof the token
    /// existed would reintroduce exactly the token-scanning oracle the RFC
    /// closes.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::TokenEndpoint`] — a non-2xx OAuth error response, such
    ///   as HTTP 400 `unsupported_token_type` (`REV-003`) or HTTP 401
    ///   `invalid_client` (`REV-004`).
    /// - [`IdentityError::Http`] — a transport failure or a non-OAuth error body.
    /// - [`IdentityError::Configuration`] — a non-https endpoint without
    ///   `allow_http`.
    pub async fn revoke(&self, token: &str, token_type_hint: Option<&str>) -> Result<()> {
        // An empty token is a caller bug, not a revocation. RFC 7009 §2.1 makes
        // `token` REQUIRED, and a server that treats "" as simply unknown answers
        // 200 (§2.2) — so posting it would hand the caller Ok(()) for a request
        // that revoked nothing. Fail here rather than let that read as success.
        if token.is_empty() {
            return Err(IdentityError::Configuration(
                "token is required: refusing to send an empty revocation request, which a server would answer 200 and the caller would read as a successful revocation"
                    .to_string(),
            ));
        }

        // Require an https endpoint unless http was explicitly allowed. The
        // token is in the request body, so a cleartext post would disclose it.
        let scheme = self.revocation_endpoint.to_ascii_lowercase();
        let scheme_ok =
            scheme.starts_with("https://") || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Configuration(format!(
                "revocation endpoint {:?} must use https (enable allow_http for development)",
                self.revocation_endpoint
            )));
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

        // A 2xx is success regardless of body content (RFC 7009 §2.2), so return
        // before touching the body. Reading it first would let a truncated
        // chunked response or a connection reset — both common on endpoints that
        // answer 200 and immediately close — turn a revocation the server has
        // already performed into an Err, telling the caller the token is still
        // live. The body carries no meaning on success: servers send nothing, an
        // empty JSON object, or whitespace.
        if status.is_success() {
            return Ok(());
        }

        // Only an error response is worth reading.
        let body = read_capped_body(response).await?;

        // Non-2xx is an OAuth error (RFC 7009 §2.2.1, RFC 6749 §5.2) —
        // REV-003 unsupported_token_type, REV-004 invalid_client.
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

/// Builder for [`RevocationClient`]. Obtain one via
/// [`RevocationClient::builder`].
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

impl std::fmt::Debug for RevocationClientBuilder {
    /// Redacts `client_secret` so a half-built client cannot leak credentials.
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
            .finish()
    }
}

impl RevocationClientBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the OAuth client identifier. Required.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the OAuth client secret. Required — RFC 7009 §2.1 requires the
    /// revocation endpoint to authenticate the client.
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Sets the revocation endpoint URL. Required.
    ///
    /// This is the `revocation_endpoint` member of the authorization server's
    /// metadata document (RFC 8414 §2, `REV-005`), so it can be taken straight
    /// from [`crate::discovery::ProviderMetadata::revocation_endpoint`] rather
    /// than configured by hand.
    pub fn revocation_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.revocation_endpoint = Some(endpoint.into());
        self
    }

    /// Selects the client-authentication method. Defaults to
    /// `client_secret_basic`.
    pub fn auth_method(mut self, method: ClientAuthMethod) -> Self {
        self.auth_method = method;
        self
    }

    /// Adds one extra form parameter. Reserved parameters are ignored — see
    /// [`RevocationClient::revoke`].
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.insert(key.into(), value.into());
        self
    }

    /// Adds several extra form parameters.
    pub fn extra_params(mut self, params: HashMap<String, String>) -> Self {
        self.extra_params.extend(params);
        self
    }

    /// Supplies a pre-configured HTTP client.
    ///
    /// Defaults to a **non-redirecting** client. The token travels in the request
    /// body, and following a redirect either drops it (301/302/303, where the
    /// POST is rewritten to a GET) and reports a false success, or replays it —
    /// with `client_secret` on the `client_secret_post` path — to the redirect
    /// target (307/308). A caller who overrides this takes on that risk.
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Sets the per-request timeout. Zero means the 30-second default.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Permits a plain-http revocation endpoint. Development only: the token
    /// being revoked travels in the request body.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if `client_id`, `client_secret`, or
    /// `revocation_endpoint` is missing or empty.
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
            http: self.http.unwrap_or_else(crate::http::no_redirect_client),
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
    use wiremock::matchers::{header, header_exists, method, path};
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

    // REV-001: a 200 with an empty body is success, and the request is a POST
    // carrying `token` as form-encoded content.
    #[tokio::test]
    async fn revoke_posts_token_and_succeeds_on_empty_200() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect("empty 200 is success");

        let req = &server.received_requests().await.unwrap()[0];
        assert_eq!(req.method.as_str(), "POST");
        let form = form_of(req);
        assert_eq!(form.get("token").map(String::as_str), Some("tok-1"));
        assert!(!form.contains_key("token_type_hint"));
    }

    // REV-001: an empty JSON object is equally a success. Some servers send
    // `{}` rather than a zero-length body; neither carries meaning.
    #[tokio::test]
    async fn empty_json_object_body_is_success() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_raw("{}", "application/json"),
        )
        .await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect("empty JSON object is success");
    }

    // REV-001, the privacy property: the result MUST NOT differ between a valid
    // token and an expired, already-revoked, or entirely unknown one. If this
    // ever regresses, the endpoint becomes a token-scanning oracle.
    #[tokio::test]
    async fn response_is_identical_for_unknown_and_valid_tokens() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;
        let endpoint = format!("{}/revoke", server.uri());
        let c = client(&endpoint).build().unwrap();

        for token in ["a-live-token", "an-expired-token", "never-existed-at-all"] {
            assert!(
                c.revoke(token, None).await.is_ok(),
                "revoking {token:?} must be indistinguishable from any other token"
            );
        }
    }

    // REV-002: the hint is sent as token_type_hint, alongside token.
    #[tokio::test]
    async fn token_type_hint_is_sent() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", Some("refresh_token"))
            .await
            .unwrap();

        let form = form_of(&server.received_requests().await.unwrap()[0]);
        assert_eq!(form.get("token").map(String::as_str), Some("tok-1"));
        assert_eq!(
            form.get("token_type_hint").map(String::as_str),
            Some("refresh_token")
        );
    }

    // REV-002: an empty hint is treated as unset rather than sent blank.
    #[tokio::test]
    async fn empty_hint_is_omitted() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", Some(""))
            .await
            .unwrap();

        let form = form_of(&server.received_requests().await.unwrap()[0]);
        assert!(!form.contains_key("token_type_hint"));
    }

    // REV-002: a wrong hint MUST NOT fail the request — the server may ignore
    // it and revoke anyway.
    #[tokio::test]
    async fn incorrect_hint_still_succeeds() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("an-access-token", Some("refresh_token"))
            .await
            .expect("an incorrect hint must not fail the request");
    }

    // REV-003: HTTP 400 unsupported_token_type surfaces as a typed error
    // carrying the code, description, uri, and status.
    #[tokio::test]
    async fn unsupported_token_type_is_typed() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(400).set_body_raw(
                r#"{"error":"unsupported_token_type","error_description":"cannot revoke this type","error_uri":"https://issuer.example/e"}"#,
                "application/json",
            ),
        )
        .await;

        let endpoint = format!("{}/revoke", server.uri());
        let err = client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect_err("400 must surface as an error");

        match err {
            IdentityError::TokenEndpoint {
                error,
                description,
                error_uri,
                status,
            } => {
                assert_eq!(error, "unsupported_token_type");
                assert_eq!(description.as_deref(), Some("cannot revoke this type"));
                assert_eq!(error_uri.as_deref(), Some("https://issuer.example/e"));
                assert_eq!(status, 400);
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    // REV-004: HTTP 401 invalid_client surfaces as a typed error.
    #[tokio::test]
    async fn invalid_client_is_typed() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(401)
                .set_body_raw(r#"{"error":"invalid_client"}"#, "application/json"),
        )
        .await;

        let endpoint = format!("{}/revoke", server.uri());
        let err = client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect_err("401 must surface as an error");

        match err {
            IdentityError::TokenEndpoint { error, status, .. } => {
                assert_eq!(error, "invalid_client");
                assert_eq!(status, 401);
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    // REV-005: the endpoint comes straight off the discovery document.
    #[tokio::test]
    async fn endpoint_resolves_from_discovery() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;
        let endpoint = format!("{}/revoke", server.uri());

        let metadata: ProviderMetadata = serde_json::from_str(&format!(
            r#"{{"issuer":"{}","revocation_endpoint":"{}"}}"#,
            server.uri(),
            endpoint
        ))
        .expect("metadata parses");

        let resolved = metadata
            .revocation_endpoint
            .as_deref()
            .expect("revocation_endpoint present in discovery");
        assert_eq!(resolved, endpoint);

        client(resolved)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect("discovery-resolved endpoint works");
    }

    // client_secret_basic is the default and sends an Authorization header
    // rather than credentials in the body.
    #[tokio::test]
    async fn client_secret_basic_is_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(header_exists(AUTHORIZATION))
            .and(header(CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .unwrap();

        let form = form_of(&server.received_requests().await.unwrap()[0]);
        assert!(!form.contains_key("client_secret"));
    }

    // client_secret_post places credentials in the body instead.
    #[tokio::test]
    async fn client_secret_post_uses_body() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .auth_method(ClientAuthMethod::ClientSecretPost)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .unwrap();

        let req = &server.received_requests().await.unwrap()[0];
        assert!(req.headers.get(AUTHORIZATION).is_none());
        let form = form_of(req);
        assert_eq!(form.get("client_id").map(String::as_str), Some("rs-client"));
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some("rs-secret")
        );
    }

    // Extra params cannot overwrite the token, the hint, or client credentials
    // — on the Basic path client_id is absent from the body and must stay so.
    #[tokio::test]
    async fn extra_params_cannot_override_reserved() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        client(&endpoint)
            .extra_param("token", "attacker-token")
            .extra_param("client_id", "attacker")
            .extra_param("resource", "https://api.example")
            .build()
            .unwrap()
            .revoke("tok-1", Some("access_token"))
            .await
            .unwrap();

        let form = form_of(&server.received_requests().await.unwrap()[0]);
        assert_eq!(form.get("token").map(String::as_str), Some("tok-1"));
        assert!(!form.contains_key("client_id"));
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("https://api.example")
        );
    }

    // A non-OAuth error body still fails, but as a transport-level error that
    // quotes a snippet rather than pretending it parsed.
    #[tokio::test]
    async fn non_oauth_error_body_is_http_error() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(500).set_body_raw("<html>boom</html>", "text/html"),
        )
        .await;

        let endpoint = format!("{}/revoke", server.uri());
        let err = client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect_err("500 must fail");
        assert!(matches!(err, IdentityError::Http(_)), "got {err:?}");
    }

    // A plain-http endpoint is refused unless allow_http was set: the token
    // travels in the body.
    #[tokio::test]
    async fn http_endpoint_refused_without_allow_http() {
        let err = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("rs-secret")
            .revocation_endpoint("http://issuer.example/revoke")
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect_err("plain http must be refused");
        assert!(
            matches!(err, IdentityError::Configuration(_)),
            "got {err:?}"
        );
    }

    // Adversarial (mirrors the Go reference's TestRevoke_RejectsEmptyToken):
    // token is REQUIRED by RFC 7009 §2.1. An empty one must be rejected locally,
    // because a lenient server answers the anti-scanning 200 for it and the
    // caller would read that as a successful revocation. Asserting the server
    // was never called is the point — an error raised after the request would
    // still have leaked a malformed request to the provider.
    #[tokio::test]
    async fn empty_token_is_rejected_before_the_network() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(200)).await;

        let endpoint = format!("{}/revoke", server.uri());
        let err = client(&endpoint)
            .build()
            .unwrap()
            .revoke("", Some("access_token"))
            .await
            .expect_err("an empty token must not be sent");

        match &err {
            IdentityError::Configuration(msg) => {
                assert!(
                    msg.contains("token is required"),
                    "unexpected message: {msg}"
                )
            }
            other => panic!("expected Configuration, got {other:?}"),
        }
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "empty-token revocation must be rejected before the network, but the server was called"
        );
    }

    // A 2xx is decided on before the body is touched, so a body that cannot be
    // read cannot turn a revocation the server already performed into an error.
    // Modelled on a provider that answers 200 and drops the connection: the
    // response promises more bytes than it delivers.
    #[tokio::test]
    async fn success_does_not_depend_on_reading_the_body() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200)
                .set_body_raw("", "application/json")
                .append_header("content-length", "512"),
        )
        .await;

        let endpoint = format!("{}/revoke", server.uri());
        let result = client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await;

        assert!(
            result.is_ok(),
            "a 2xx must succeed without depending on the body: {result:?}"
        );
    }

    // A redirect is not followed. On a 302 reqwest would rewrite the POST to a
    // GET and drop the body, so the final 200 would report success for a request
    // whose token never arrived — a silent false success on a live token.
    #[tokio::test]
    async fn redirect_is_not_followed_and_is_an_error() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(
                ResponseTemplate::new(302)
                    .append_header("location", format!("{}/elsewhere", upstream.uri()).as_str()),
            )
            .mount(&server)
            .await;

        let endpoint = format!("{}/revoke", server.uri());
        let err = client(&endpoint)
            .build()
            .unwrap()
            .revoke("tok-1", None)
            .await
            .expect_err("a 3xx must not be reported as a successful revocation");
        assert!(matches!(err, IdentityError::Http(_)), "got {err:?}");

        assert!(
            upstream.received_requests().await.unwrap().is_empty(),
            "the redirect target must never be contacted — the token is in the body"
        );
    }

    #[test]
    fn build_requires_credentials_and_endpoint() {
        assert!(RevocationClient::builder().build().is_err());
        assert!(
            RevocationClient::builder()
                .client_id("id")
                .revocation_endpoint("https://e/revoke")
                .build()
                .is_err(),
            "client_secret is required"
        );
        assert!(
            RevocationClient::builder()
                .client_id("id")
                .client_secret("s")
                .build()
                .is_err(),
            "revocation_endpoint is required"
        );
    }

    #[test]
    fn debug_redacts_client_secret() {
        let c = RevocationClient::builder()
            .client_id("rs-client")
            .client_secret("super-secret")
            .revocation_endpoint("https://issuer.example/revoke")
            .build()
            .unwrap();
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(rendered.contains(REDACTED));

        let b = RevocationClient::builder().client_secret("super-secret");
        assert!(!format!("{b:?}").contains("super-secret"));
    }
}
