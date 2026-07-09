//! Async OIDC Discovery client: fetch, validate, and cache provider metadata.

use std::time::Duration;

use reqwest::Client as HttpClient;
use reqwest::header::ACCEPT;

use crate::{IdentityError, Result};

use super::cache::Cache;
use super::metadata::ProviderMetadata;

/// The discovery document path appended to the issuer (OIDC Discovery 1.0 §4.1).
const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// Default lifetime of a cached discovery document.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default per-request timeout so a hung server cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Caps the discovery response read into memory. A discovery document is a small
/// JSON object; this guards against an issuer streaming an unbounded body
/// (memory-exhaustion DoS).
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// An async client that fetches, validates, and caches OIDC provider metadata.
///
/// Construct one with [`DiscoveryClient::new`] for the defaults (24h cache TTL,
/// 30s request timeout, HTTPS-only issuers) or [`DiscoveryClient::builder`] to
/// customise them. A single client should be reused across calls so its cache
/// and the underlying connection pool are shared.
///
/// ```no_run
/// # async fn run() -> identity_model::Result<()> {
/// use identity_model::DiscoveryClient;
///
/// let client = DiscoveryClient::new();
/// let metadata = client.discover("https://accounts.example.com").await?;
/// println!("jwks_uri = {}", metadata.jwks_uri);
/// # Ok(())
/// # }
/// ```
pub struct DiscoveryClient {
    http: HttpClient,
    cache: Cache,
    cache_ttl: Duration,
    timeout: Duration,
    allow_http: bool,
}

impl DiscoveryClient {
    /// Returns a client with the default configuration.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Returns a builder for customising the client's cache TTL, request
    /// timeout, HTTP client, and HTTPS enforcement.
    pub fn builder() -> DiscoveryClientBuilder {
        DiscoveryClientBuilder::new()
    }

    /// Fetches, validates, and caches the OIDC provider metadata for
    /// `issuer_url`.
    ///
    /// The request targets `{issuer_url}/.well-known/openid-configuration`. A
    /// fresh cache entry is served without any HTTP request (DISC-004); the
    /// entry is refreshed once its TTL elapses (DISC-005). The issuer scheme
    /// must be `https` unless [`DiscoveryClientBuilder::allow_http`] was set
    /// (DISC-010).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Validation`] — non-HTTPS issuer (DISC-010), a missing
    ///   required field (DISC-008), or an issuer that does not match the
    ///   document (DISC-003).
    /// - [`IdentityError::Http`] — a transport failure or a non-2xx response
    ///   (DISC-006).
    /// - [`IdentityError::Deserialization`] — a body that is not valid JSON
    ///   metadata (DISC-007).
    pub async fn discover(&self, issuer_url: &str) -> Result<ProviderMetadata> {
        let issuer = issuer_url.trim().trim_end_matches('/').to_string();
        if issuer.is_empty() {
            return Err(IdentityError::Validation("issuer URL is empty".to_string()));
        }

        // DISC-004: a fresh cache entry is served without any HTTP request.
        if let Some(metadata) = self.cache.get(&issuer).await {
            return Ok(metadata);
        }

        // DISC-010: require an https issuer unless http was explicitly allowed
        // (for local development / integration against non-TLS providers).
        let is_https = issuer.starts_with("https://");
        let scheme_ok = is_https || (self.allow_http && issuer.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Validation(format!(
                "issuer {issuer:?} must use https (enable allow_http for development)"
            )));
        }

        let metadata = self.fetch_and_validate(&issuer).await?;
        self.cache
            .put(issuer, metadata.clone(), self.cache_ttl)
            .await;
        Ok(metadata)
    }

    /// Performs the HTTP request, parses the body, and validates the document.
    /// Contains no caching logic.
    async fn fetch_and_validate(&self, issuer: &str) -> Result<ProviderMetadata> {
        let endpoint = format!("{issuer}{WELL_KNOWN_PATH}");

        let mut response = self
            .http
            .get(&endpoint)
            .header(ACCEPT, "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| IdentityError::Http(format!("fetch {endpoint}: {e}")))?;

        // DISC-006: a non-2xx response is a transport error carrying the status.
        let status = response.status();
        if !status.is_success() {
            return Err(IdentityError::Http(format!(
                "unexpected HTTP status {} from {endpoint}",
                status.as_u16()
            )));
        }

        // Read the body in chunks so an oversized response is rejected before it
        // is fully buffered, bounding memory regardless of Content-Length.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| IdentityError::Http(format!("read body from {endpoint}: {e}")))?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(IdentityError::Deserialization(format!(
                    "discovery document from {endpoint} exceeds {MAX_BODY_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        // DISC-007: a non-JSON body is a deserialization error.
        let metadata: ProviderMetadata = serde_json::from_slice(&body).map_err(|e| {
            IdentityError::Deserialization(format!("parse discovery document from {endpoint}: {e}"))
        })?;

        // DISC-002 / DISC-008: every required field must be present.
        let missing = metadata.missing_required_fields();
        if !missing.is_empty() {
            return Err(IdentityError::Validation(format!(
                "discovery document from {endpoint} is missing required field(s): {}",
                missing.join(", ")
            )));
        }

        // DISC-003: the document's issuer must match the requested issuer.
        // Trailing slashes are trimmed on both sides so they normalise
        // symmetrically (a trailing-slash-only difference is not a mismatch).
        if metadata.issuer.trim_end_matches('/') != issuer {
            return Err(IdentityError::Validation(format!(
                "issuer mismatch: requested {issuer:?} but document declares {:?}",
                metadata.issuer
            )));
        }

        Ok(metadata)
    }
}

impl Default for DiscoveryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`DiscoveryClient`]. Obtain one via [`DiscoveryClient::builder`].
pub struct DiscoveryClientBuilder {
    http: Option<HttpClient>,
    cache_ttl: Duration,
    timeout: Duration,
    allow_http: bool,
}

impl DiscoveryClientBuilder {
    /// Returns a builder seeded with the default configuration.
    fn new() -> Self {
        Self {
            http: None,
            cache_ttl: DEFAULT_CACHE_TTL,
            timeout: DEFAULT_TIMEOUT,
            allow_http: false,
        }
    }

    /// Sets how long a fetched document is cached before the next call
    /// re-fetches it. A non-positive duration is ignored and the default (24h)
    /// is retained.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        if !ttl.is_zero() {
            self.cache_ttl = ttl;
        }
        self
    }

    /// Bounds each discovery request with a per-request timeout. A non-positive
    /// duration is ignored and the default (30s) is retained.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits `http://` issuer URLs, which are otherwise rejected (DISC-010).
    /// Intended for local development and integration tests against non-TLS
    /// providers; do not enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Uses `client` for discovery requests instead of a default
    /// [`reqwest::Client`], letting callers share a connection pool or supply
    /// custom transport configuration.
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Builds the [`DiscoveryClient`].
    pub fn build(self) -> DiscoveryClient {
        DiscoveryClient {
            http: self.http.unwrap_or_default(),
            cache: Cache::new(),
            cache_ttl: self.cache_ttl,
            timeout: self.timeout,
            allow_http: self.allow_http,
        }
    }
}

impl Default for DiscoveryClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A valid discovery document whose issuer is `issuer`, including an
    /// unmodelled extension field (DISC-009).
    fn valid_doc(issuer: &str) -> String {
        format!(
            r#"{{
                "issuer": "{issuer}",
                "authorization_endpoint": "{issuer}/auth",
                "token_endpoint": "{issuer}/token",
                "userinfo_endpoint": "{issuer}/userinfo",
                "jwks_uri": "{issuer}/jwks",
                "response_types_supported": ["code", "id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256", "ES256"],
                "code_challenge_methods_supported": ["S256"],
                "x_custom_extension_field": "should-be-ignored-not-rejected"
            }}"#
        )
    }

    /// Mounts a single GET handler on the discovery path returning `template`.
    async fn mount(server: &MockServer, template: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(WELL_KNOWN_PATH))
            .respond_with(template)
            .mount(server)
            .await;
    }

    // DISC-001 / DISC-002: fetch a valid document; every required field parses
    // with the correct type and is accessible.
    #[tokio::test]
    async fn fetches_and_parses_valid_document() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(valid_doc(&issuer)),
        )
        .await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        let meta = client.discover(&issuer).await.expect("discovery succeeds");

        assert_eq!(meta.issuer, issuer);
        assert_eq!(meta.authorization_endpoint, format!("{issuer}/auth"));
        assert_eq!(meta.token_endpoint, format!("{issuer}/token"));
        assert_eq!(meta.jwks_uri, format!("{issuer}/jwks"));
        assert_eq!(meta.response_types_supported, vec!["code", "id_token"]);
        assert_eq!(meta.subject_types_supported, vec!["public"]);
        assert_eq!(
            meta.id_token_signing_alg_values_supported,
            vec!["RS256", "ES256"]
        );
        assert_eq!(
            meta.userinfo_endpoint.as_deref(),
            Some(format!("{issuer}/userinfo").as_str())
        );
    }

    // DISC-003: a document whose issuer differs from the requested issuer is a
    // validation error.
    #[tokio::test]
    async fn rejects_issuer_mismatch() {
        let server = MockServer::start().await;
        let body = valid_doc("https://attacker.example.com");
        mount(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        let err = client
            .discover(&server.uri())
            .await
            .expect_err("issuer mismatch must error");

        match err {
            IdentityError::Validation(msg) => assert!(msg.contains("issuer mismatch"), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // DISC-004: a second discover() within the TTL makes no HTTP request.
    #[tokio::test]
    async fn caches_within_ttl() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(valid_doc(&issuer)),
        )
        .await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        client.discover(&issuer).await.expect("first fetch");
        client.discover(&issuer).await.expect("cache hit");

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "second call must be served from cache");
    }

    // DISC-005: once the TTL expires, discover() re-fetches.
    #[tokio::test]
    async fn refreshes_after_ttl_expiry() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(valid_doc(&issuer)),
        )
        .await;

        let client = DiscoveryClient::builder()
            .allow_http(true)
            .cache_ttl(Duration::from_millis(10))
            .build();
        client.discover(&issuer).await.expect("first fetch");
        tokio::time::sleep(Duration::from_millis(30)).await;
        client
            .discover(&issuer)
            .await
            .expect("refetch after expiry");

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2, "expired entry must be refetched");
    }

    // DISC-006: a non-2xx response is an HTTP error carrying the status.
    #[tokio::test]
    async fn maps_http_status_errors() {
        for status in [404u16, 500] {
            let server = MockServer::start().await;
            mount(&server, ResponseTemplate::new(status)).await;

            let client = DiscoveryClient::builder().allow_http(true).build();
            let err = client
                .discover(&server.uri())
                .await
                .expect_err("non-2xx must error");

            match err {
                IdentityError::Http(msg) => {
                    assert!(msg.contains(&status.to_string()), "{msg}")
                }
                other => panic!("expected Http for {status}, got {other:?}"),
            }
        }
    }

    // DISC-007: a non-JSON body is a deserialization error.
    #[tokio::test]
    async fn maps_invalid_json() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string("not-json"),
        )
        .await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        let err = client
            .discover(&server.uri())
            .await
            .expect_err("invalid JSON must error");

        assert!(
            matches!(err, IdentityError::Deserialization(_)),
            "expected Deserialization, got {err:?}"
        );
    }

    // DISC-008: a document missing a required field is a validation error that
    // names the field.
    #[tokio::test]
    async fn reports_missing_required_field() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        // A valid document with jwks_uri removed.
        let body = format!(
            r#"{{
                "issuer": "{issuer}",
                "authorization_endpoint": "{issuer}/auth",
                "token_endpoint": "{issuer}/token",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }}"#
        );
        mount(&server, ResponseTemplate::new(200).set_body_string(body)).await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        let err = client
            .discover(&issuer)
            .await
            .expect_err("missing field must error");

        match err {
            IdentityError::Validation(msg) => assert!(msg.contains("jwks_uri"), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // DISC-009: unknown fields are ignored (captured in `extra`), not rejected.
    #[tokio::test]
    async fn ignores_unknown_fields() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(valid_doc(&issuer)),
        )
        .await;

        let client = DiscoveryClient::builder().allow_http(true).build();
        let meta = client
            .discover(&issuer)
            .await
            .expect("parses despite extra");

        assert!(meta.extra.contains_key("x_custom_extension_field"));
        assert!(
            !meta.jwks_uri.is_empty(),
            "required fields remain accessible"
        );
    }

    // DISC-010: an http issuer is rejected by default and permitted with
    // allow_http; no HTTP request is made for the rejected case.
    #[tokio::test]
    async fn requires_https_by_default() {
        let client = DiscoveryClient::new();
        let err = client
            .discover("http://insecure.example.com")
            .await
            .expect_err("http issuer must be rejected");

        match err {
            IdentityError::Validation(msg) => assert!(msg.contains("https"), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
