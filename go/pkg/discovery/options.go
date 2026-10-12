package discovery

import (
	"net/http"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// Defaults from spec/config.md.
const (
	// DefaultCacheTTL is how long a document is cached when its response has
	// no Cache-Control max-age.
	DefaultCacheTTL = time.Hour
	// DefaultMaxCacheEntries is how many issuers a client's cache holds.
	DefaultMaxCacheEntries = 64
)

// config holds a [Client]'s settings.
type config struct {
	transport  transport.Settings
	allowHTTP  bool
	cacheTTL   time.Duration
	maxEntries int
}

// Option configures a [Client] (functional options).
type Option func(*config)

// ConfigError reports every invalid option passed to [NewClient]. Each issue
// names the option and the rule it broke, never the value.
type ConfigError = transport.ConfigError

// ConfigIssue is one invalid option in a [ConfigError].
type ConfigIssue = transport.Issue

// ErrInvalidConfig matches any [ConfigError].
var ErrInvalidConfig = transport.ErrInvalidConfig

// newConfig applies opts on top of the defaults and validates the result.
func newConfig(opts ...Option) (*config, *transport.Transport, error) {
	cfg := &config{
		transport:  transport.Defaults(),
		cacheTTL:   DefaultCacheTTL,
		maxEntries: DefaultMaxCacheEntries,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	tr, issues := cfg.transport.Build()
	if cfg.cacheTTL < transport.MinCacheTTL || cfg.cacheTTL > transport.MaxCacheTTL {
		issues = append(issues, ConfigIssue{Setting: "WithCacheTTL", Rule: transport.RuleCacheTTL})
	}
	if cfg.maxEntries < 1 {
		issues = append(issues, ConfigIssue{Setting: "WithMaxCacheEntries", Rule: transport.RuleAtLeastOne})
	}
	if len(issues) > 0 {
		return nil, nil, transport.NewConfigError("discovery", issues)
	}
	return cfg, tr, nil
}

// WithTimeout bounds each request attempt, including reading the response.
// Default 30 seconds; must be > 0.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.transport.Timeout = d }
}

// WithRetryMaxAttempts sets how many times a 429, a 5xx or a transport error
// is retried. Default 3; 0 disables retries; must be >= 0.
func WithRetryMaxAttempts(n int) Option {
	return func(c *config) { c.transport.RetryMaxAttempts = n }
}

// WithRetryBaseDelay sets the base of the exponential backoff between retries
// (base, 2*base, 4*base, …, each capped at 120 seconds; a longer Retry-After
// wins). Default 1 second; must be >= 0.
func WithRetryBaseDelay(d time.Duration) Option {
	return func(c *config) { c.transport.RetryBaseDelay = d }
}

// WithCABundle verifies TLS against the certificates in the PEM file at path
// instead of the system roots. It cannot be combined with [WithHTTPClient]:
// configure the TLS roots on that client instead.
func WithCABundle(path string) Option {
	return func(c *config) { c.transport.CABundle = path }
}

// WithHTTPClient sends requests through client instead of
// [http.DefaultClient]. A nil client keeps the default.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.transport.HTTPClient = client }
}

// WithInsecureAllowHTTP permits http:// issuer URLs, which are otherwise
// rejected (DISC-010). Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}

// WithCacheTTL sets how long a document is cached when the response has no
// Cache-Control max-age. Default 1 hour; must be 60 seconds to 24 hours.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithMaxCacheEntries bounds how many issuers the client's cache holds. Over
// the bound the least-recently-used entry (a read hit or a store counts as a
// use) is evicted, so a caller driven to resolve many distinct issuers — a
// multi-tenant gateway or an attacker-supplied issuer header — cannot grow the
// cache without limit. Default 64; must be >= 1.
func WithMaxCacheEntries(n int) Option {
	return func(c *config) { c.maxEntries = n }
}
