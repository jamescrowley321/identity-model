package revocation

import (
	"net/http"
	"time"
)

// ClientAuthMethod selects how the revoking client presents its credentials to
// the protected revocation endpoint (RFC 7009 §2.1, RFC 6749 §2.3).
type ClientAuthMethod int

const (
	// ClientSecretBasic sends the client_id and client_secret in an HTTP Basic
	// Authorization header (RFC 6749 §2.3.1). This is the default.
	ClientSecretBasic ClientAuthMethod = iota
	// ClientSecretPost sends the client_id and client_secret as form parameters
	// in the request body (RFC 6749 §2.3.1).
	ClientSecretPost
)

// defaultRequestTimeout bounds a revocation request when [WithTimeout] is not
// supplied, so a hung endpoint cannot block indefinitely.
const defaultRequestTimeout = 30 * time.Second

// config holds the resolved settings for a revocation request.
type config struct {
	authMethod    ClientAuthMethod
	tokenTypeHint string
	extraParams   map[string]string
	httpClient    *http.Client
	timeout       time.Duration
	allowHTTP     bool
}

// Option customises a revocation request via the functional-options pattern.
// The option surface mirrors the discovery, jwks, jwt, token, userinfo and
// introspection clients so the packages compose consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		authMethod: ClientSecretBasic,
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}
	return cfg
}

// WithClientAuth selects the client authentication method (RFC 6749 §2.3). The
// default is [ClientSecretBasic].
func WithClientAuth(method ClientAuthMethod) Option {
	return func(c *config) { c.authMethod = method }
}

// WithTokenTypeHint sets the optional token_type_hint form parameter
// (RFC 7009 §2.1), typically "access_token" or "refresh_token". The server MAY
// use it to optimize lookup but MUST accept the request even if the hint is
// incorrect. When unset, no hint is sent.
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

// WithHTTPClient uses client for the revocation request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the revocation request with a context deadline of d. It
// composes with the caller's context; the earlier deadline wins. The default is
// 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithInsecureAllowHTTP permits an http:// revocation endpoint, which is
// otherwise rejected. Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
