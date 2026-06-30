package jwks

import (
	"net/http"
	"time"
)

// defaultCacheTTL is the default lifetime of a cached JWK Set when
// [WithCacheTTL] is not supplied. Signing keys rotate infrequently, so a long
// TTL is safe — a key-not-found resolution forces a refresh regardless
// (JWKS-004).
const defaultCacheTTL = 24 * time.Hour

// defaultRefreshCooldown is the minimum interval between automatic forced
// refreshes for a given jwks_uri (see [WithRefreshCooldown]). It bounds the rate
// at which an unknown kid can trigger a network re-fetch, so an attacker
// presenting tokens with random kid values cannot amplify traffic against the
// provider. Explicit [JSONWebKeySet.ForceRefresh] is not throttled.
const defaultRefreshCooldown = 5 * time.Second

// config holds the resolved settings for a FetchKeySet call.
type config struct {
	httpClient      *http.Client
	cacheTTL        time.Duration
	timeout         time.Duration
	allowHTTP       bool
	refreshCooldown time.Duration
}

// Option customises FetchKeySet via the functional-options pattern. The option
// surface mirrors the discovery client so the two compose consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		httpClient:      http.DefaultClient,
		cacheTTL:        defaultCacheTTL,
		refreshCooldown: defaultRefreshCooldown,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}
	if cfg.cacheTTL <= 0 {
		cfg.cacheTTL = defaultCacheTTL
	}
	if cfg.refreshCooldown < 0 {
		cfg.refreshCooldown = defaultRefreshCooldown
	}
	return cfg
}

// WithCacheTTL sets how long a fetched key set is cached before the next call
// re-fetches it. The default is 24 hours. A non-positive duration is ignored
// and the default is retained.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithHTTPClient uses client for the JWKS request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the JWKS request with a context deadline of d. It composes
// with the caller's context; the earlier deadline wins.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithRefreshCooldown sets the minimum interval between automatic forced
// refreshes triggered by [JSONWebKeySet.ResolveKeyWithRefresh] for the same
// jwks_uri. Within the cooldown a kid miss returns a key-not-found error without
// re-fetching, bounding attacker-driven re-fetches when token kid values are
// untrusted. The default is 5 seconds. A zero value disables throttling; a
// negative value is ignored and the default is retained. Explicit
// [JSONWebKeySet.ForceRefresh] is never throttled.
func WithRefreshCooldown(d time.Duration) Option {
	return func(c *config) { c.refreshCooldown = d }
}

// WithInsecureAllowHTTP permits http:// jwks_uri values, which are otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
