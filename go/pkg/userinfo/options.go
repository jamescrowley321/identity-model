package userinfo

import (
	"net/http"
	"time"
)

// defaultRequestTimeout bounds a UserInfo request when [WithTimeout] is not
// supplied, so a hung endpoint cannot block indefinitely.
const defaultRequestTimeout = 30 * time.Second

// config holds the resolved settings for a UserInfo request.
type config struct {
	expectedSub string
	validateSub bool
	httpClient  *http.Client
	timeout     time.Duration
	allowHTTP   bool
}

// Option customises a UserInfo request via the functional-options pattern. The
// option surface mirrors the discovery, jwks, jwt and token clients so the
// packages compose consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
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

// WithHTTPClient uses client for the UserInfo request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the UserInfo request with a context deadline of d. It
// composes with the caller's context; the earlier deadline wins. The default
// is 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithInsecureAllowHTTP permits an http:// UserInfo endpoint, which is
// otherwise rejected. Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
