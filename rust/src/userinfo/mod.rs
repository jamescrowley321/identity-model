//! UserInfo endpoint client: fetch profile claims, verify `sub` consistency.
//!
//! [`UserInfoClient`] GETs the OIDC UserInfo endpoint (OIDC Core 1.0 §5.3) with
//! an `Authorization: Bearer {access_token}` header (RFC 6750 §2.1) and decodes
//! the JSON reply into a typed [`UserInfoResponse`] (§5.1), preserving any
//! non-standard claims in the response's overflow map. A non-2xx reply becomes
//! an [`IdentityError::UserInfo`] carrying the status and any `WWW-Authenticate`
//! challenge; [`UserInfoClient::fetch_with_subject`] additionally rejects a
//! `sub` that does not match the ID token's `sub` (§5.3.2).
//!
//! Behavioural contract: `spec/conformance/userinfo.json` (`UI-001`..`UI-008`);
//! see also `spec/capabilities.md`.
//!
//! ```no_run
//! # async fn run() -> identity_model::Result<()> {
//! use identity_model::UserInfoClient;
//!
//! let client = UserInfoClient::builder()
//!     .userinfo_endpoint("https://issuer.example.com/userinfo")
//!     .build()?;
//! let claims = client.fetch("the-access-token").await?;
//! println!("sub = {}", claims.sub);
//! # Ok(())
//! # }
//! ```

mod response;

use std::time::Duration;

use reqwest::Client as HttpClient;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};

use crate::{IdentityError, Result};

pub use response::{Address, UserInfoResponse};

/// Default per-request timeout so a hung endpoint cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Caps the UserInfo response read into memory (memory-exhaustion DoS guard).
/// UserInfo responses are small.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// An async OIDC UserInfo endpoint client.
///
/// Construct one with [`UserInfoClient::builder`]. A single client should be
/// reused across calls so the underlying connection pool is shared.
pub struct UserInfoClient {
    http: HttpClient,
    userinfo_endpoint: String,
    timeout: Duration,
    allow_http: bool,
}

impl UserInfoClient {
    /// Returns a builder for configuring a [`UserInfoClient`].
    pub fn builder() -> UserInfoClientBuilder {
        UserInfoClientBuilder::new()
    }

    /// Fetches the end-user's claims from the UserInfo endpoint (UI-001): GETs
    /// the endpoint with an `Authorization: Bearer {access_token}` header and
    /// returns the typed [`UserInfoResponse`], including any custom claims in
    /// its overflow map (UI-007).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::UserInfo`] — a non-2xx response (UI-004/005/006).
    /// - [`IdentityError::Http`] — a transport failure or over-large body.
    /// - [`IdentityError::Deserialization`] — a 2xx body that is not valid JSON.
    /// - [`IdentityError::Validation`] — a response with no `sub`, or a signed
    ///   `application/jwt` response (unsupported).
    /// - [`IdentityError::Configuration`] — an empty token or non-https endpoint.
    pub async fn fetch(&self, access_token: &str) -> Result<UserInfoResponse> {
        self.fetch_inner(access_token, None).await
    }

    /// Like [`fetch`](UserInfoClient::fetch) but additionally requires that the
    /// UserInfo `sub` equals `expected_sub` — the `sub` of the ID token the
    /// access token was issued alongside (OIDC Core 1.0 §5.3.2, UI-002/UI-003).
    ///
    /// A mismatch is a token-substitution risk and returns
    /// [`IdentityError::Validation`] with the message
    /// `"sub mismatch between ID token and UserInfo"`.
    pub async fn fetch_with_subject(
        &self,
        access_token: &str,
        expected_sub: &str,
    ) -> Result<UserInfoResponse> {
        self.fetch_inner(access_token, Some(expected_sub)).await
    }

    /// Shared fetch: validates the endpoint and token, issues the GET, checks
    /// the status before decoding, and enforces subject consistency when
    /// `expected_sub` is supplied.
    async fn fetch_inner(
        &self,
        access_token: &str,
        expected_sub: Option<&str>,
    ) -> Result<UserInfoResponse> {
        // Require an https endpoint unless http was explicitly allowed.
        let scheme = self.userinfo_endpoint.to_ascii_lowercase();
        let scheme_ok =
            scheme.starts_with("https://") || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Configuration(format!(
                "userinfo endpoint {:?} must use https (enable allow_http for development)",
                self.userinfo_endpoint
            )));
        }
        if access_token.is_empty() {
            return Err(IdentityError::Configuration(
                "access token is required".to_string(),
            ));
        }

        let response = self
            .http
            .get(&self.userinfo_endpoint)
            .timeout(self.timeout)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| IdentityError::Http(format!("get {}: {e}", self.userinfo_endpoint)))?;

        // Capture status and headers before the body read consumes the response.
        let status = response.status();
        let www_authenticate = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = read_capped_body(response).await?;

        // Status before decode: a non-2xx response is an error. A
        // Bearer-protected resource describes the failure in WWW-Authenticate
        // (RFC 6750 §3, UI-004/005/006).
        if !status.is_success() {
            return Err(IdentityError::UserInfo {
                status: status.as_u16(),
                www_authenticate,
                body: body_snippet(&body),
            });
        }

        // A signed or encrypted UserInfo response is served as application/jwt
        // (§5.3.2). This client handles only the JSON serialization; surface a
        // descriptive error rather than parsing opaque JWT bytes as JSON.
        if let Some(ct) = content_type.as_deref()
            && media_type_is_jwt(ct)
        {
            return Err(IdentityError::Validation(
                "signed/encrypted UserInfo (application/jwt) is not supported".to_string(),
            ));
        }

        let userinfo: UserInfoResponse = serde_json::from_slice(&body).map_err(|e| {
            IdentityError::Deserialization(format!(
                "parse userinfo response from {}: {e}",
                self.userinfo_endpoint
            ))
        })?;
        if userinfo.sub.is_empty() {
            return Err(IdentityError::Validation(
                "userinfo response is missing the sub claim".to_string(),
            ));
        }

        // Subject consistency (OIDC Core 1.0 §5.3.2): the UserInfo sub MUST
        // match the ID token sub to defend against token substitution.
        if let Some(expected) = expected_sub
            && userinfo.sub != expected
        {
            return Err(IdentityError::Validation(
                "sub mismatch between ID token and UserInfo".to_string(),
            ));
        }

        Ok(userinfo)
    }
}

/// Reports whether a `Content-Type` header value has the `application/jwt`
/// media type, ignoring any parameters (e.g. `application/jwt; charset=utf-8`)
/// and surrounding whitespace.
fn media_type_is_jwt(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(|mt| mt.trim().eq_ignore_ascii_case("application/jwt"))
        .unwrap_or(false)
}

/// Reads a response body in chunks, rejecting one that exceeds
/// [`MAX_BODY_BYTES`] before it is fully buffered.
async fn read_capped_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| IdentityError::Http(format!("read userinfo response: {e}")))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(IdentityError::Http(format!(
                "userinfo response exceeds {MAX_BODY_BYTES} bytes"
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

/// Builder for [`UserInfoClient`]. Obtain one via [`UserInfoClient::builder`].
#[derive(Default)]
pub struct UserInfoClientBuilder {
    http: Option<HttpClient>,
    userinfo_endpoint: Option<String>,
    timeout: Duration,
    allow_http: bool,
}

impl UserInfoClientBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the UserInfo endpoint URL (required), typically the
    /// `userinfo_endpoint` from discovery metadata.
    pub fn userinfo_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.userinfo_endpoint = Some(endpoint.into());
        self
    }

    /// Uses `client` for the request instead of a default [`reqwest::Client`],
    /// letting callers share a connection pool or supply custom transport
    /// configuration (UI-008).
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Bounds each request with a per-request timeout. A non-positive duration
    /// is ignored and the default (30s) is retained (UI-008).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits an `http://` UserInfo endpoint, which is otherwise rejected.
    /// Intended for local development and integration tests against non-TLS
    /// providers; do not enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Builds the [`UserInfoClient`].
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if `userinfo_endpoint` is missing or
    /// empty.
    pub fn build(self) -> Result<UserInfoClient> {
        let userinfo_endpoint = self.userinfo_endpoint.unwrap_or_default();
        if userinfo_endpoint.is_empty() {
            return Err(IdentityError::Configuration(
                "userinfo_endpoint is required".to_string(),
            ));
        }
        Ok(UserInfoClient {
            http: self.http.unwrap_or_default(),
            userinfo_endpoint,
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const STANDARD_CLAIMS: &str =
        include_str!("../../../spec/test-fixtures/userinfo/standard-claims.json");

    fn client(endpoint: &str) -> UserInfoClient {
        UserInfoClient::builder()
            .userinfo_endpoint(endpoint)
            .allow_http(true)
            .build()
            .unwrap()
    }

    // UI-001: fetch carries an Authorization: Bearer header and returns typed
    // standard claims.
    #[tokio::test]
    async fn fetch_sends_bearer_and_returns_typed_claims() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("authorization", "Bearer at-xyz"))
            .and(header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(STANDARD_CLAIMS))
            .mount(&server)
            .await;

        let resp = client(&format!("{}/userinfo", server.uri()))
            .fetch("at-xyz")
            .await
            .expect("fetch succeeds");

        assert_eq!(resp.sub, "248289761001");
        assert_eq!(resp.name.as_deref(), Some("Jane Doe"));
        assert_eq!(resp.email.as_deref(), Some("janedoe@example.com"));
        assert_eq!(resp.email_verified, Some(true));
        assert!(resp.address.is_some());
        assert_eq!(resp.updated_at, Some(1_700_000_000));
    }

    // UI-007: custom claims are reachable via claims(); standard stay typed.
    #[tokio::test]
    async fn fetch_preserves_custom_claims() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(STANDARD_CLAIMS))
            .mount(&server)
            .await;

        let resp = client(&format!("{}/userinfo", server.uri()))
            .fetch("tok")
            .await
            .expect("fetch succeeds");

        assert_eq!(
            resp.claims().get("department").and_then(|v| v.as_str()),
            Some("Engineering")
        );
        assert!(!resp.claims().contains_key("email"));
    }

    // UI-002: subject validation passes when the sub matches.
    #[tokio::test]
    async fn fetch_with_matching_subject_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(STANDARD_CLAIMS))
            .mount(&server)
            .await;

        let resp = client(&format!("{}/userinfo", server.uri()))
            .fetch_with_subject("tok", "248289761001")
            .await
            .expect("matching sub succeeds");
        assert_eq!(resp.sub, "248289761001");
    }

    // UI-003: a subject mismatch is a Validation error with the exact message.
    #[tokio::test]
    async fn fetch_with_mismatched_subject_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(STANDARD_CLAIMS))
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch_with_subject("tok", "someone-else")
            .await
            .expect_err("mismatch must error");
        match err {
            IdentityError::Validation(msg) => {
                assert_eq!(msg, "sub mismatch between ID token and UserInfo");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // UI-004: a 401 with a WWW-Authenticate challenge maps to a typed error
    // carrying the status and challenge.
    #[tokio::test]
    async fn handles_401_with_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
                    .set_body_string("unauthorized"),
            )
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch("bogus")
            .await
            .expect_err("401 must fail");
        match err {
            IdentityError::UserInfo {
                status,
                www_authenticate,
                ..
            } => {
                assert_eq!(status, 401);
                assert_eq!(
                    www_authenticate.as_deref(),
                    Some("Bearer error=\"invalid_token\"")
                );
            }
            other => panic!("expected UserInfo, got {other:?}"),
        }
    }

    // UI-005: a 403 maps to a typed error carrying the 403 status.
    #[tokio::test]
    async fn handles_403() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch("tok")
            .await
            .expect_err("403 must fail");
        match err {
            IdentityError::UserInfo { status, .. } => assert_eq!(status, 403),
            other => panic!("expected UserInfo, got {other:?}"),
        }
    }

    // UI-006: a 500 with a non-JSON body maps to a typed error carrying the
    // 500 status and a body snippet.
    #[tokio::test]
    async fn handles_500_non_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch("tok")
            .await
            .expect_err("500 must fail");
        match err {
            IdentityError::UserInfo { status, body, .. } => {
                assert_eq!(status, 500);
                assert!(body.contains("upstream boom"), "body snippet: {body}");
            }
            other => panic!("expected UserInfo, got {other:?}"),
        }
    }

    // A 200 body missing sub is a Validation error.
    #[tokio::test]
    async fn missing_sub_is_validation_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"No Sub"}"#))
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch("tok")
            .await
            .expect_err("missing sub must fail");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // A signed (application/jwt) UserInfo response is rejected as unsupported.
    #[tokio::test]
    async fn rejects_application_jwt_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("eyJ.signed.jwt".as_bytes(), "application/jwt"),
            )
            .mount(&server)
            .await;

        let err = client(&format!("{}/userinfo", server.uri()))
            .fetch("tok")
            .await
            .expect_err("application/jwt must be rejected");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // UI-008: a custom http client is used and a short timeout bounds a slow
    // endpoint.
    #[tokio::test]
    async fn timeout_bounds_slow_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(STANDARD_CLAIMS)
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;

        let custom = reqwest::Client::builder().build().unwrap();
        let client = UserInfoClient::builder()
            .userinfo_endpoint(format!("{}/userinfo", server.uri()))
            .http_client(custom)
            .timeout(Duration::from_millis(50))
            .allow_http(true)
            .build()
            .unwrap();

        let err = client
            .fetch("tok")
            .await
            .expect_err("slow endpoint times out");
        assert!(matches!(err, IdentityError::Http(_)), "{err:?}");
    }

    // The builder requires a userinfo endpoint.
    #[test]
    fn builder_requires_endpoint() {
        assert!(matches!(
            UserInfoClient::builder().build(),
            Err(IdentityError::Configuration(_))
        ));
    }

    // An empty access token is rejected before any request is sent.
    #[tokio::test]
    async fn empty_access_token_is_rejected() {
        let err = UserInfoClient::builder()
            .userinfo_endpoint("https://issuer.example/userinfo")
            .build()
            .unwrap()
            .fetch("")
            .await
            .expect_err("empty token must fail");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }

    // The default (https-only) gate rejects an http endpoint.
    #[tokio::test]
    async fn https_required_by_default() {
        let err = UserInfoClient::builder()
            .userinfo_endpoint("http://insecure.example/userinfo")
            .build()
            .unwrap()
            .fetch("tok")
            .await
            .expect_err("http endpoint must be rejected");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }
}
