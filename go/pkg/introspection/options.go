package introspection

import (
	"net/http"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// ClientAuthMethod selects how the introspecting client presents its
// credentials to the protected introspection endpoint (RFC 7662 §2.1,
// RFC 6749 §2.3).
type ClientAuthMethod int

const (
	// ClientSecretBasic sends the client_id and client_secret in an HTTP Basic
	// Authorization header (RFC 6749 §2.3.1). This is the default.
	ClientSecretBasic ClientAuthMethod = iota
	// ClientSecretPost sends the client_id and client_secret as form parameters
	// in the request body (RFC 6749 §2.3.1).
	ClientSecretPost
)

// config holds the resolved settings for an introspection request.
type config struct {
	authMethod    ClientAuthMethod
	tokenTypeHint string
	extraParams   map[string]string
	transport     transport.Settings
	// tr is built from transport by newConfig.
	tr        *transport.Transport
	allowHTTP bool
}

// Option customises an introspection request via the functional-options
// pattern. The option surface mirrors the discovery, jwks, jwt, token and
// userinfo clients so the packages compose consistently.
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
		transport:  transport.Defaults(),
		authMethod: ClientSecretBasic,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	tr, issues := cfg.transport.Build()
	if len(issues) > 0 {
		return nil, transport.NewConfigError("introspection", issues)
	}
	cfg.tr = tr
	return cfg, nil
}

// WithClientAuth selects the client authentication method (RFC 6749 §2.3). The
// default is [ClientSecretBasic].
func WithClientAuth(method ClientAuthMethod) Option {
	return func(c *config) { c.authMethod = method }
}

// WithTokenTypeHint sets the optional token_type_hint form parameter
// (RFC 7662 §2.1), typically "access_token" or "refresh_token". The server MAY
// use it to optimize lookup but MUST NOT fail if the hint is incorrect. When
// unset, no hint is sent.
func WithTokenTypeHint(hint string) Option {
	return func(c *config) { c.tokenTypeHint = hint }
}

// WithExtraParams adds arbitrary additional form parameters to the request, for
// provider-specific extensions. Reserved parameters set by the request itself
// (token, token_type_hint, client_id, client_secret) take precedence and cannot
// be overridden.
func WithExtraParams(params map[string]string) Option {
	return func(c *config) { c.extraParams = params }
}

// WithHTTPClient sends the introspection request through client instead of
// [http.DefaultClient]. A nil client keeps the default.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.transport.HTTPClient = client }
}

// WithTimeout bounds each attempt of the introspection request, including reading the
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

// WithInsecureAllowHTTP permits an http:// introspection endpoint, which is
// otherwise rejected. Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
