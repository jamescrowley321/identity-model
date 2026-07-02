package discovery

import (
	"net/http"
	"time"
)

// defaultCacheTTL is the default lifetime of a cached discovery document when
// [WithCacheTTL] is not supplied.
const defaultCacheTTL = 24 * time.Hour

// config holds the resolved settings for a FetchConfiguration call.
type config struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	timeout    time.Duration
	allowHTTP  bool
}

// Option customises FetchConfiguration via the functional-options pattern.
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

// WithCacheTTL sets how long a fetched configuration is cached before the next
// call re-fetches it. The default is 24 hours. A non-positive duration is
// ignored and the default is retained.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithHTTPClient uses client for the discovery request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the discovery request with a context deadline of d. It
// composes with the caller's context; the earlier deadline wins.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithInsecureAllowHTTP permits http:// issuer URLs, which are otherwise
// rejected (DISC-010). Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
