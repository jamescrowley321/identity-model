package token

import (
	"net/http"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
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

// config holds the resolved settings for a token request.
type config struct {
	authMethod   ClientAuthMethod
	clientSecret string
	scopes       []string
	codeVerifier string
	extraParams  map[string]string
	transport    transport.Settings
	// tr is built from transport by newConfig.
	tr        *transport.Transport
	allowHTTP bool

	// Token exchange (RFC 8693) parameters.
	actorToken     string
	actorTokenType string
	// actorTokenSet records that [WithActorToken] was applied, which a bare
	// string cannot express. A supplied-but-empty actor token is a caller error
	// (rejected by [TokenExchange]), not a request for impersonation; omitting
	// the option is how impersonation is requested.
	actorTokenSet      bool
	resources          []string
	audiences          []string
	requestedTokenType string
}

// Option customises a token request via the functional-options pattern. The
// option surface mirrors the discovery, jwks and jwt clients so the packages
// compose consistently.
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
		return nil, transport.NewConfigError("token", issues)
	}
	cfg.tr = tr
	return cfg, nil
}

// WithClientAuth selects the client authentication method (RFC 6749 §2.3). The
// default is [ClientSecretBasic].
func WithClientAuth(method ClientAuthMethod) Option {
	return func(c *config) { c.authMethod = method }
}

// WithClientSecret authenticates the [AuthorizationCode] exchange as a
// confidential client (RFC 6749 §2.3.1). The secret is presented via the
// configured [ClientAuthMethod] — client_secret_basic (default) or
// client_secret_post. Omit it (or pass "") for a public client, which is
// identified by client_id in the request body. It has no effect on
// [ClientCredentials] / [TokenExchange], which take the secret positionally.
func WithClientSecret(secret string) Option {
	return func(c *config) { c.clientSecret = secret }
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

// WithExtraParams adds arbitrary additional form parameters to the request, for
// provider-specific extensions (e.g. an RFC 8707 resource on the client
// credentials grant). Reserved parameters set by the grant itself take
// precedence and can never be injected or overridden this way; a key is matched
// case-insensitively and with surrounding whitespace trimmed, so no spelling of
// it slips past a server that folds or trims the parameter name.
//
// On the [TokenExchange] grant that reservation additionally covers resource,
// audience and requested_token_type, which are sourced from [WithResource],
// [WithAudience] and [WithRequestedTokenType]. Supplying one of those three here
// is rejected by [TokenExchange] rather than dropped, so a caller who pinned a
// targeting parameter this way learns to move it to the option instead of
// silently sending an unrestricted exchange.
func WithExtraParams(params map[string]string) Option {
	return func(c *config) { c.extraParams = params }
}

// WithActorToken attaches the actor token and its type URI to a token exchange
// request, turning it into a delegation exchange (RFC 8693 §1.1, §2.1). The
// tokenType is one of the TokenType* URIs (RFC 8693 §3) and is REQUIRED whenever
// an actor token is present. It is ignored by grants other than token exchange.
//
// Applying this option with an empty token or tokenType is rejected by
// [TokenExchange] rather than quietly dropped: a delegation request that loses
// its actor token becomes an impersonation request, whose issued token carries
// the subject's full authority with no act claim. Omit the option entirely to
// request impersonation.
func WithActorToken(token, tokenType string) Option {
	return func(c *config) {
		c.actorToken = token
		c.actorTokenType = tokenType
		c.actorTokenSet = true
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

// WithHTTPClient sends the token request through client instead of
// [http.DefaultClient]. A nil client keeps the default.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.transport.HTTPClient = client }
}

// WithTimeout bounds each attempt of the token request, including reading the
// response. It composes with the caller's context; the earlier deadline wins.
// Default 30 seconds; must be > 0.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.transport.Timeout = d }
}

// WithRetryMaxAttempts sets how many times a 429, a 5xx or a transport error
// is retried. Default 3; 0 disables retries; must be >= 0. [AuthorizationCode]
// never retries: its code is single-use.
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

// WithInsecureAllowHTTP permits an http:// token endpoint, which is otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}
