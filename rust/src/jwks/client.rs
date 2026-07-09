//! Async JWKS client: fetch, cache, and resolve JSON Web Keys by `kid`.

use std::time::Duration;

use reqwest::Client as HttpClient;
use reqwest::header::ACCEPT;

use crate::{IdentityError, Result};

use super::cache::Cache;
use super::key::{JsonWebKey, JsonWebKeySet};

/// Default lifetime of a cached JWK Set.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default per-request timeout so a hung server cannot block indefinitely.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default minimum interval between automatic forced refreshes for a given
/// `jwks_uri`. Because `kid` is taken from an untrusted token header, an
/// attacker presenting tokens with random `kid` values would otherwise drive an
/// unbounded number of outbound JWKS fetches (request amplification / DoS).
/// Within the cooldown a `kid` miss returns [`IdentityError::KeyNotFound`]
/// without re-fetching. Mirrors `go/pkg/jwks` `defaultRefreshCooldown`.
const DEFAULT_REFRESH_COOLDOWN: Duration = Duration::from_secs(5);

/// Caps the JWKS response read into memory. A key set is a small JSON object;
/// this guards against a provider streaming an unbounded body
/// (memory-exhaustion DoS).
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// An async client that fetches, validates, caches, and resolves JSON Web Keys.
///
/// Construct one with [`JwksClient::new`] for the defaults (24h cache TTL, 30s
/// request timeout, HTTPS-only URIs) or [`JwksClient::builder`] to customise
/// them. A single client should be reused across calls so its cache and the
/// underlying connection pool are shared.
///
/// ```no_run
/// # async fn run() -> identity_model::Result<()> {
/// use identity_model::JwksClient;
///
/// let client = JwksClient::new();
/// let key_set = client.fetch("https://accounts.example.com/jwks").await?;
/// let key = key_set.resolve_key("rsa-sig-key")?;
/// println!("alg = {}", key.alg);
/// # Ok(())
/// # }
/// ```
pub struct JwksClient {
    http: HttpClient,
    cache: Cache,
    cache_ttl: Duration,
    timeout: Duration,
    allow_http: bool,
    refresh_cooldown: Duration,
}

impl JwksClient {
    /// Returns a client with the default configuration.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Returns a builder for customising the client's cache TTL, request
    /// timeout, HTTP client, and HTTPS enforcement.
    pub fn builder() -> JwksClientBuilder {
        JwksClientBuilder::new()
    }

    /// Fetches, validates, and caches the JWK Set at `jwks_uri` (JWKS-001).
    ///
    /// A fresh cache entry is served without any HTTP request (JWKS-005); the
    /// entry is refreshed once its TTL elapses. The URI scheme must be `https`
    /// unless [`JwksClientBuilder::allow_http`] was set.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Validation`] — an empty or non-HTTPS `jwks_uri`, an
    ///   empty key set, or a key missing required parameters (JWKS-002/007).
    /// - [`IdentityError::Http`] — a transport failure or a non-2xx response.
    /// - [`IdentityError::Deserialization`] — a body that is not a valid JWK Set
    ///   (JWKS-007).
    pub async fn fetch(&self, jwks_uri: &str) -> Result<JsonWebKeySet> {
        let uri = jwks_uri.trim().to_string();
        if uri.is_empty() {
            return Err(IdentityError::Validation("jwks_uri is empty".to_string()));
        }

        // JWKS-005: a fresh cache entry is served without any HTTP request.
        if let Some(key_set) = self.cache.get(&uri).await {
            return Ok(key_set);
        }

        // Require an https URI unless http was explicitly allowed (for local
        // development / integration against non-TLS providers). URL schemes are
        // case-insensitive (RFC 3986 §3.1), so compare on a lowercased copy.
        let scheme = uri.to_ascii_lowercase();
        let is_https = scheme.starts_with("https://");
        let scheme_ok = is_https || (self.allow_http && scheme.starts_with("http://"));
        if !scheme_ok {
            return Err(IdentityError::Validation(format!(
                "jwks_uri {uri:?} must use https (enable allow_http for development)"
            )));
        }

        let key_set = self.fetch_and_parse(&uri).await?;
        self.cache.put(uri, key_set.clone(), self.cache_ttl).await;
        Ok(key_set)
    }

    /// Invalidates the cached set for `jwks_uri` and re-fetches it from the
    /// provider (JWKS-006), returning the fresh set. Callers invoke it after a
    /// signature verification failure that may indicate key rotation.
    ///
    /// An explicit `force_refresh` is never throttled, but it starts the
    /// cooldown window that gates subsequent automatic refreshes in
    /// [`JwksClient::resolve_key`].
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`JwksClient::fetch`].
    pub async fn force_refresh(&self, jwks_uri: &str) -> Result<JsonWebKeySet> {
        let uri = jwks_uri.trim().to_string();
        self.cache.invalidate(&uri).await;
        let key_set = self.fetch(&uri).await?;
        self.cache.mark_refresh(&uri).await;
        Ok(key_set)
    }

    /// Resolves the key with `kid` at `jwks_uri`, forcing one refresh and
    /// retrying on a miss before erroring (JWKS-003/004).
    ///
    /// This handles key rotation: a token signed with a freshly published key
    /// whose `kid` is not yet cached triggers a re-fetch. To resolve against an
    /// already-fetched set without a network round-trip, use
    /// [`JsonWebKeySet::resolve_key`].
    ///
    /// The automatic refresh is rate-limited per `jwks_uri` by the refresh
    /// cooldown (see [`JwksClientBuilder::refresh_cooldown`]): because `kid`
    /// comes from an untrusted token header, an attacker presenting tokens with
    /// random `kid` values would otherwise drive unbounded outbound fetches.
    /// Within the cooldown a miss returns [`IdentityError::KeyNotFound`] without
    /// re-fetching.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::KeyNotFound`] — no key with `kid` even after a refresh.
    /// - The fetch errors of [`JwksClient::fetch`].
    pub async fn resolve_key(&self, jwks_uri: &str, kid: &str) -> Result<JsonWebKey> {
        let key_set = self.fetch(jwks_uri).await?;
        if let Some(key) = key_set.find(kid) {
            return Ok(key.clone());
        }
        // JWKS-004: the kid may belong to a freshly rotated key, so force one
        // refresh and retry. Throttle the automatic refresh per jwks_uri
        // (keyed on the trimmed URI, matching the cache key) so random unknown
        // kids cannot amplify traffic against the provider.
        let uri = jwks_uri.trim();
        if self
            .cache
            .refresh_throttled(uri, self.refresh_cooldown)
            .await
        {
            return Err(IdentityError::KeyNotFound(kid.to_string()));
        }
        let refreshed = self.force_refresh(uri).await?;
        refreshed.resolve_key(kid).cloned()
    }

    /// Performs the HTTP request and parses the body. Contains no caching logic.
    async fn fetch_and_parse(&self, uri: &str) -> Result<JsonWebKeySet> {
        let mut response = self
            .http
            .get(uri)
            .header(ACCEPT, "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| IdentityError::Http(format!("fetch {uri}: {e}")))?;

        // A non-2xx response is a transport error carrying the status.
        let status = response.status();
        if !status.is_success() {
            return Err(IdentityError::Http(format!(
                "unexpected HTTP status {} from {uri}",
                status.as_u16()
            )));
        }

        // Read the body in chunks so an oversized response is rejected before it
        // is fully buffered, bounding memory regardless of Content-Length.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| IdentityError::Http(format!("read body from {uri}: {e}")))?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(IdentityError::Deserialization(format!(
                    "JWK Set from {uri} exceeds {MAX_BODY_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        JsonWebKeySet::parse(&body)
    }
}

impl Default for JwksClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`JwksClient`]. Obtain one via [`JwksClient::builder`].
pub struct JwksClientBuilder {
    http: Option<HttpClient>,
    cache_ttl: Duration,
    timeout: Duration,
    allow_http: bool,
    refresh_cooldown: Duration,
}

impl JwksClientBuilder {
    /// Returns a builder seeded with the default configuration.
    fn new() -> Self {
        Self {
            http: None,
            cache_ttl: DEFAULT_CACHE_TTL,
            timeout: DEFAULT_TIMEOUT,
            allow_http: false,
            refresh_cooldown: DEFAULT_REFRESH_COOLDOWN,
        }
    }

    /// Sets how long a fetched key set is cached before the next call re-fetches
    /// it. A non-positive duration is ignored and the default (24h) is retained.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        if !ttl.is_zero() {
            self.cache_ttl = ttl;
        }
        self
    }

    /// Bounds each JWKS request with a per-request timeout. A non-positive
    /// duration is ignored and the default (30s) is retained.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// Permits `http://` JWKS URIs, which are otherwise rejected. Intended for
    /// local development and integration tests against non-TLS providers; do not
    /// enable in production.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Sets the minimum interval between automatic forced refreshes for a given
    /// `jwks_uri` in [`JwksClient::resolve_key`]. Within this window a `kid`
    /// miss returns [`IdentityError::KeyNotFound`] without a network re-fetch,
    /// bounding the rate at which an untrusted `kid` can trigger outbound
    /// traffic. A zero duration disables throttling (every miss refreshes);
    /// explicit [`JwksClient::force_refresh`] is never throttled.
    pub fn refresh_cooldown(mut self, cooldown: Duration) -> Self {
        self.refresh_cooldown = cooldown;
        self
    }

    /// Uses `client` for JWKS requests instead of a default [`reqwest::Client`],
    /// letting callers share a connection pool or supply custom transport
    /// configuration.
    pub fn http_client(mut self, client: HttpClient) -> Self {
        self.http = Some(client);
        self
    }

    /// Builds the [`JwksClient`].
    pub fn build(self) -> JwksClient {
        JwksClient {
            http: self.http.unwrap_or_default(),
            cache: Cache::new(),
            cache_ttl: self.cache_ttl,
            timeout: self.timeout,
            allow_http: self.allow_http,
            refresh_cooldown: self.refresh_cooldown,
        }
    }
}

impl Default for JwksClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A JWK Set with one RSA and one EC signing key (mirrors
    /// `spec/test-fixtures/jwks/valid.json`).
    const VALID_SET: &str = r#"{
        "keys": [
            {"kty":"RSA","kid":"rsa-sig-key","use":"sig","alg":"RS256",
             "n":"0vx7agoebGcQ","e":"AQAB"},
            {"kty":"EC","kid":"ec-sig-key","use":"sig","alg":"ES256",
             "crv":"P-256","x":"f83OJ3D2xF1B","y":"x_FEzRu9m36H"}
        ]
    }"#;

    /// Mounts a single GET handler on `/jwks` returning `template`.
    async fn mount(server: &MockServer, template: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    fn jwks_uri(server: &MockServer) -> String {
        format!("{}/jwks", server.uri())
    }

    // JWKS-001 / JWKS-002: fetch a valid set; both RSA and EC keys parse with
    // their key-type parameters intact.
    #[tokio::test]
    async fn fetches_and_parses_valid_set() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let set = client.fetch(&jwks_uri(&server)).await.expect("fetch");

        assert_eq!(set.keys().len(), 2);
        let rsa = set.resolve_key("rsa-sig-key").expect("rsa present");
        assert_eq!(rsa.kty, "RSA");
        assert!(!rsa.n.is_empty() && !rsa.e.is_empty());
    }

    // JWKS-003 / AC6: an EC key resolves with kty == "EC" and curve parameters.
    #[tokio::test]
    async fn resolves_ec_key_by_kid() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let key = client
            .resolve_key(&jwks_uri(&server), "ec-sig-key")
            .await
            .expect("ec key resolves");

        assert_eq!(key.kty, "EC");
        assert_eq!(key.crv, "P-256");
    }

    // JWKS-004: a kid absent from the cached set triggers one forced refresh; the
    // provider now serves the rotated key and resolution succeeds on retry.
    #[tokio::test]
    async fn resolve_with_refresh_retries() {
        let server = MockServer::start().await;
        // First response lacks the rotated kid; the second (post-refresh) has it.
        let without = r#"{ "keys": [ {"kty":"RSA","kid":"old","n":"a","e":"AQAB"} ] }"#;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(without))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string(VALID_SET))
            .mount(&server)
            .await;

        let client = JwksClient::builder().allow_http(true).build();
        let key = client
            .resolve_key(&jwks_uri(&server), "rsa-sig-key")
            .await
            .expect("rotated key resolves after refresh");

        assert_eq!(key.kid, "rsa-sig-key");
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2, "one initial fetch + one forced refresh");
    }

    // JWKS-004: a kid that never appears errors KeyNotFound after the refresh.
    #[tokio::test]
    async fn resolve_absent_kid_errors_after_refresh() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let err = client
            .resolve_key(&jwks_uri(&server), "never")
            .await
            .expect_err("absent kid errors");

        assert!(
            matches!(&err, IdentityError::KeyNotFound(kid) if kid == "never"),
            "expected KeyNotFound(never), got {err:?}"
        );
    }

    // JWKS-004 (security): repeated unknown-kid resolutions are rate-limited by
    // the refresh cooldown, so a random kid cannot amplify traffic. The first
    // miss refreshes once (request 2); a second miss within the cooldown is
    // throttled and makes no further request. Mirrors go/pkg/jwks
    // TestResolveKeyWithRefresh_Throttled.
    #[tokio::test]
    async fn refresh_cooldown_throttles_repeated_misses() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder()
            .allow_http(true)
            .refresh_cooldown(Duration::from_secs(60))
            .build();
        let uri = jwks_uri(&server);

        // First unknown-kid resolution: cold fetch (req 1) + one forced refresh
        // (req 2), then KeyNotFound.
        client
            .resolve_key(&uri, "never")
            .await
            .expect_err("first miss errors");
        // Second unknown-kid resolution within the cooldown: throttled, no fetch.
        client
            .resolve_key(&uri, "never")
            .await
            .expect_err("second miss errors");

        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            2,
            "second miss throttled within cooldown; no extra refresh"
        );
    }

    // A zero refresh_cooldown disables throttling: every unknown-kid miss forces
    // a refresh, so two misses issue two extra fetches.
    #[tokio::test]
    async fn zero_refresh_cooldown_refreshes_every_miss() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder()
            .allow_http(true)
            .refresh_cooldown(Duration::ZERO)
            .build();
        let uri = jwks_uri(&server);

        client
            .resolve_key(&uri, "never")
            .await
            .expect_err("first miss errors");
        client
            .resolve_key(&uri, "never")
            .await
            .expect_err("second miss errors");

        // req 1 = cold fetch; req 2 + req 3 = a forced refresh per miss.
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 3, "no throttling: each miss refreshes");
    }

    // JWKS-005: a second fetch() within the TTL makes no HTTP request.
    #[tokio::test]
    async fn caches_within_ttl() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let uri = jwks_uri(&server);
        client.fetch(&uri).await.expect("first fetch");
        client.fetch(&uri).await.expect("cache hit");

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "second call served from cache");
    }

    // JWKS-006: force_refresh() invalidates the cache and re-fetches.
    #[tokio::test]
    async fn force_refresh_refetches() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let uri = jwks_uri(&server);
        client.fetch(&uri).await.expect("first fetch");
        let set = client.force_refresh(&uri).await.expect("force refresh");

        assert!(!set.keys().is_empty());
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2, "force_refresh bypasses the cache");
    }

    // JWKS-007: an empty key set from the endpoint is a validation error.
    #[tokio::test]
    async fn rejects_empty_key_set() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(r#"{ "keys": [] }"#),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let err = client
            .fetch(&jwks_uri(&server))
            .await
            .expect_err("empty errors");
        assert!(
            matches!(err, IdentityError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    // JWKS-007 / AC7: a non-JSON body is a deserialization error.
    #[tokio::test]
    async fn rejects_malformed_json() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string("not-json"),
        )
        .await;

        let client = JwksClient::builder().allow_http(true).build();
        let err = client
            .fetch(&jwks_uri(&server))
            .await
            .expect_err("malformed body errors");
        assert!(
            matches!(err, IdentityError::Deserialization(_)),
            "expected Deserialization, got {err:?}"
        );
    }

    // AC7: a non-2xx response is an HTTP error carrying the status.
    #[tokio::test]
    async fn maps_http_status_error() {
        let server = MockServer::start().await;
        mount(&server, ResponseTemplate::new(500)).await;

        let client = JwksClient::builder().allow_http(true).build();
        let err = client
            .fetch(&jwks_uri(&server))
            .await
            .expect_err("500 errors");
        match err {
            IdentityError::Http(msg) => assert!(msg.contains("500"), "{msg}"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    // An http:// URI is rejected by default and no HTTP request is made.
    #[tokio::test]
    async fn requires_https_by_default() {
        let client = JwksClient::new();
        let err = client
            .fetch("http://insecure.example.com/jwks")
            .await
            .expect_err("http uri rejected");
        match err {
            IdentityError::Validation(msg) => assert!(msg.contains("https"), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // An empty jwks_uri is a validation error.
    #[tokio::test]
    async fn rejects_empty_uri() {
        let client = JwksClient::new();
        let err = client.fetch("   ").await.expect_err("empty uri rejected");
        assert!(
            matches!(err, IdentityError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    // A very large TTL (`Duration::MAX`) must not overflow `Instant` and panic;
    // the entry is stored and served from cache (parity with discovery).
    #[tokio::test]
    async fn handles_max_ttl_without_panicking() {
        let server = MockServer::start().await;
        mount(
            &server,
            ResponseTemplate::new(200).set_body_string(VALID_SET),
        )
        .await;

        let client = JwksClient::builder()
            .allow_http(true)
            .cache_ttl(Duration::MAX)
            .build();
        let uri = jwks_uri(&server);
        client.fetch(&uri).await.expect("first fetch");
        client.fetch(&uri).await.expect("cache hit");

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "max-ttl entry stays cached");
    }
}
