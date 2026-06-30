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

// config holds the resolved settings for a FetchKeySet call.
type config struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	timeout    time.Duration
	allowHTTP  bool
}

// Option customises FetchKeySet via the functional-options pattern. The option
// surface mirrors the discovery client so the two compose consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		httpClient: http.DefaultClient,
		cacheTTL:   defaultCacheTTL,
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

// WithInsecureAllowHTTP permits http:// jwks_uri values, which are otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
