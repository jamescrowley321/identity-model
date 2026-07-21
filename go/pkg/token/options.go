package token

import (
	"net/http"
	"time"
)

// ClientAuthMethod selects how client credentials are presented to the token
// endpoint (RFC 6749 §2.3).
type ClientAuthMethod int

const (
	// ClientSecretBasic sends the client_id and client_secret in an HTTP Basic
	// Authorization header (RFC 6749 §2.3.1). This is the default.
	ClientSecretBasic ClientAuthMethod = iota
	// ClientSecretPost sends the client_id and client_secret as form parameters
	// in the request body (RFC 6749 §2.3.1).
	ClientSecretPost
)

// defaultRequestTimeout bounds a token request when [WithTimeout] is not
// supplied, so a hung endpoint cannot block indefinitely.
const defaultRequestTimeout = 30 * time.Second

// config holds the resolved settings for a token request.
type config struct {
	authMethod   ClientAuthMethod
	scopes       []string
	codeVerifier string
	extraParams  map[string]string
	httpClient   *http.Client
	timeout      time.Duration
	allowHTTP    bool

	// Token exchange (RFC 8693) parameters.
	actorToken         string
	actorTokenType     string
	resources          []string
	audiences          []string
	requestedTokenType string
}

// Option customises a token request via the functional-options pattern. The
// option surface mirrors the discovery, jwks and jwt clients so the packages
// compose consistently.
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

// WithScopes requests the named scopes, sent as a single space-delimited scope
// form parameter (RFC 6749 §3.3). When unset, no scope parameter is sent.
func WithScopes(scopes ...string) Option {
	return func(c *config) { c.scopes = scopes }
}

// WithCodeVerifier attaches the PKCE code_verifier to an authorization code
// exchange (RFC 7636 §4.5). It is ignored by the client credentials grant.
func WithCodeVerifier(verifier string) Option {
	return func(c *config) { c.codeVerifier = verifier }
}

// WithExtraParams adds arbitrary additional form parameters to the request,
// for provider-specific extensions (e.g. resource or audience). Reserved
// parameters set by the grant itself take precedence.
func WithExtraParams(params map[string]string) Option {
	return func(c *config) { c.extraParams = params }
}

// WithActorToken attaches the actor token and its type URI to a token exchange
// request, turning it into a delegation exchange (RFC 8693 §1.1, §2.1). The
// tokenType is one of the TokenType* URIs (RFC 8693 §3) and is REQUIRED whenever
// an actor token is present. It is ignored by grants other than token exchange.
func WithActorToken(token, tokenType string) Option {
	return func(c *config) {
		c.actorToken = token
		c.actorTokenType = tokenType
	}
}

// WithResource adds one or more target resource URIs to a token exchange
// request (RFC 8693 §2.1). Each resource is sent as a separate repeated
// resource form parameter; repeated calls accumulate. It is ignored by grants
// other than token exchange.
func WithResource(resources ...string) Option {
	return func(c *config) { c.resources = append(c.resources, resources...) }
}

// WithAudience adds one or more target audiences to a token exchange request
// (RFC 8693 §2.1). Each audience is sent as a separate repeated audience form
// parameter; repeated calls accumulate. It is ignored by grants other than
// token exchange.
func WithAudience(audiences ...string) Option {
	return func(c *config) { c.audiences = append(c.audiences, audiences...) }
}

// WithRequestedTokenType sets the requested_token_type for a token exchange
// request, naming the desired type of the issued token (RFC 8693 §2.1). The uri
// is one of the TokenType* URIs (RFC 8693 §3); the server MAY issue a different
// type. It is ignored by grants other than token exchange.
func WithRequestedTokenType(uri string) Option {
	return func(c *config) { c.requestedTokenType = uri }
}

// WithHTTPClient uses client for the token request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the token request with a context deadline of d. It composes
// with the caller's context; the earlier deadline wins. The default is 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithInsecureAllowHTTP permits an http:// token endpoint, which is otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
