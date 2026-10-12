package userinfo

import (
	"net/http"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// config holds the resolved settings for a UserInfo request.
type config struct {
	expectedSub string
	validateSub bool
	transport   transport.Settings
	// tr is built from transport by newConfig.
	tr        *transport.Transport
	allowHTTP bool
}

// Option customises a UserInfo request via the functional-options pattern. The
// option surface mirrors the discovery, jwks, jwt and token clients so the
// packages compose consistently.
type Option func(*config)

// ConfigError reports every invalid option passed to a call. Each issue names
// the option and the rule it broke, never the value.
type ConfigError = transport.ConfigError

// ConfigIssue is one invalid option in a [ConfigError].
type ConfigIssue = transport.Issue

// ErrInvalidConfig matches any [ConfigError].
var ErrInvalidConfig = transport.ErrInvalidConfig

// newConfig applies opts on top of the defaults and validates the transport
// settings. An invalid value is a [*ConfigError]; nothing is sent.
func newConfig(opts ...Option) (*config, error) {
	cfg := &config{
		transport: transport.Defaults(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	tr, issues := cfg.transport.Build()
	if len(issues) > 0 {
		return nil, transport.NewConfigError("userinfo", issues)
	}
	cfg.tr = tr
	return cfg, nil
}

// WithSubjectValidation requires that the UserInfo "sub" claim equals
// expectedSub — the "sub" of the ID token the access token was issued
// alongside. A mismatch is reported as a [SubjectMismatchError]
// (OIDC Core 1.0 §5.3.2). When unset, no subject check is performed.
func WithSubjectValidation(expectedSub string) Option {
	return func(c *config) {
		c.expectedSub = expectedSub
		c.validateSub = true
	}
}

// WithHTTPClient sends the UserInfo request through client instead of
// [http.DefaultClient]. A nil client keeps the default.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.transport.HTTPClient = client }
}

// WithTimeout bounds each attempt of the UserInfo request, including reading the
// response. It composes with the caller's context; the earlier deadline wins.
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

// WithInsecureAllowHTTP permits an http:// UserInfo endpoint, which is
// otherwise rejected. Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
