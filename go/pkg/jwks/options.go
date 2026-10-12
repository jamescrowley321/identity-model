package jwks

import (
	"net/http"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// Defaults from spec/config.md.
const (
	// DefaultCacheTTL is how long a key set is cached when its response has no
	// Cache-Control max-age. Signing keys rotate infrequently, and an unknown
	// kid forces a refresh regardless (JWKS-004).
	DefaultCacheTTL = 24 * time.Hour
	// DefaultMaxCacheEntries is how many jwks_uri values a client's cache
	// holds.
	DefaultMaxCacheEntries = 64
	// DefaultMaxSize is the largest JWKS response accepted, in bytes.
	DefaultMaxSize = 524288
	// DefaultMaxKeys is the most keys accepted in one JWKS.
	DefaultMaxKeys = 100
	// DefaultRefreshCooldown is the minimum interval between automatic
	// refreshes of one jwks_uri triggered by an unknown kid.
	DefaultRefreshCooldown = 5 * time.Second
	// MaxRefreshCooldown is the largest valid [WithRefreshCooldown].
	MaxRefreshCooldown = time.Hour
)

// config holds a [Client]'s settings.
type config struct {
	transport       transport.Settings
	allowHTTP       bool
	cacheTTL        time.Duration
	maxEntries      int
	maxSize         int
	maxKeys         int
	refreshCooldown time.Duration
}

// Option configures a [Client] (functional options). The option surface
// mirrors the discovery client so the two compose consistently.
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
		transport:       transport.Defaults(),
		cacheTTL:        DefaultCacheTTL,
		maxEntries:      DefaultMaxCacheEntries,
		maxSize:         DefaultMaxSize,
		maxKeys:         DefaultMaxKeys,
		refreshCooldown: DefaultRefreshCooldown,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	tr, issues := cfg.transport.Build()
	if cfg.maxSize < 1 {
		issues = append(issues, ConfigIssue{Setting: "WithMaxSize", Rule: transport.RuleAtLeastOne})
	}
	if cfg.maxKeys < 1 {
		issues = append(issues, ConfigIssue{Setting: "WithMaxKeys", Rule: transport.RuleAtLeastOne})
	}
	if cfg.cacheTTL < transport.MinCacheTTL || cfg.cacheTTL > transport.MaxCacheTTL {
		issues = append(issues, ConfigIssue{Setting: "WithCacheTTL", Rule: transport.RuleCacheTTL})
	}
	if cfg.refreshCooldown < 0 || cfg.refreshCooldown > MaxRefreshCooldown {
		issues = append(issues, ConfigIssue{Setting: "WithRefreshCooldown", Rule: "must be 0s to 3600s"})
	}
	if cfg.maxEntries < 1 {
		issues = append(issues, ConfigIssue{Setting: "WithMaxCacheEntries", Rule: transport.RuleAtLeastOne})
	}
	if len(issues) > 0 {
		return nil, nil, transport.NewConfigError("jwks", issues)
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

// WithInsecureAllowHTTP permits http:// jwks_uri values, which are otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}

// WithMaxSize sets the largest JWKS response accepted, in bytes; a larger body
// is a [ParseError]. Default 524288 (512 KiB); must be >= 1.
func WithMaxSize(n int) Option {
	return func(c *config) { c.maxSize = n }
}

// WithMaxKeys sets the most keys accepted in one JWKS; a set with more is a
// [ParseError]. Default 100; must be >= 1.
func WithMaxKeys(n int) Option {
	return func(c *config) { c.maxKeys = n }
}

// WithCacheTTL sets how long a key set is cached when the response has no
// Cache-Control max-age. Default 24 hours; must be 60 seconds to 24 hours.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithRefreshCooldown sets the minimum interval between automatic refreshes
// triggered by [JSONWebKeySet.ResolveKeyWithRefresh] for the same jwks_uri.
// Within the cooldown a kid miss returns a key-not-found error without
// re-fetching, bounding attacker-driven re-fetches when token kid values are
// untrusted. Default 5 seconds; 0 disables the cooldown; must be 0 to 1 hour.
// Explicit [JSONWebKeySet.ForceRefresh] is never throttled.
func WithRefreshCooldown(d time.Duration) Option {
	return func(c *config) { c.refreshCooldown = d }
}

// WithMaxCacheEntries bounds how many jwks_uri values the client's cache
// holds. Over the bound the least-recently-used entry (a read hit or a store
// counts as a use) is evicted, and its refresh-cooldown record with it, so a
// caller driven to resolve tokens against many distinct jwks_uri values — a
// multi-tenant gateway or an attacker-supplied issuer header — cannot grow the
// cache without limit. Default 64; must be >= 1.
func WithMaxCacheEntries(n int) Option {
	return func(c *config) { c.maxEntries = n }
}
