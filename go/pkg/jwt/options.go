package jwt

import (
	"log/slog"
	"time"
)

// defaultAllowedAlgorithms is the set of accepted JWS algorithms when
// [WithAllowedAlgorithms] is not supplied. Only asymmetric signature algorithms
// are permitted: the symmetric "HS*" family is intentionally excluded so a token
// signed with HMAC cannot be verified against a provider's public key
// (algorithm confusion). "none" is never accepted (JWT-003).
var defaultAllowedAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// config holds the resolved settings for a Validate call.
type config struct {
	expectedIssuer   string
	expectedAudience string
	expectedNonce    string
	nonceSet         bool
	clockSkew        time.Duration
	requiredClaims   []string
	allowedAlgs      []string
	now              func() time.Time
	claimsValidator  ClaimsValidator
	logger           *slog.Logger
}

// Option customises [Validate] via the functional-options pattern. The option
// surface mirrors the discovery and jwks clients so the packages compose
// consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		allowedAlgs: defaultAllowedAlgorithms,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if len(cfg.allowedAlgs) == 0 {
		cfg.allowedAlgs = defaultAllowedAlgorithms
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return cfg
}

// WithExpectedIssuer requires the token's iss claim to exactly match issuer
// (JWT-007, RFC 7519 §4.1.1). When unset, iss is not checked.
func WithExpectedIssuer(issuer string) Option {
	return func(c *config) { c.expectedIssuer = issuer }
}

// WithExpectedAudience requires the token's aud claim to contain audience
// (JWT-008, RFC 7519 §4.1.3). When unset, aud is not checked.
func WithExpectedAudience(audience string) Option {
	return func(c *config) { c.expectedAudience = audience }
}

// WithExpectedNonce requires the token's nonce claim to equal nonce (JWT-004,
// OIDC Core 1.0 §3.1.3.7). When unset, nonce is not checked. An empty string is
// a valid expected value, so the option records that a nonce was requested.
func WithExpectedNonce(nonce string) Option {
	return func(c *config) {
		c.expectedNonce = nonce
		c.nonceSet = true
	}
}

// WithClockSkew tolerates up to d of clock drift when evaluating the time-based
// claims exp and nbf (JWT-011, RFC 7519 §4.1.4–4.1.5). The default is zero.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) { c.clockSkew = d }
}

// WithRequiredClaims requires each named claim to be present (JWT-012, RFC 7519
// §4.1). Presence only — value checks for the registered claims use the
// dedicated options above.
func WithRequiredClaims(claims ...string) Option {
	return func(c *config) { c.requiredClaims = claims }
}

// WithAllowedAlgorithms overrides the accepted JWS algorithms. Supplying "none"
// has no effect: it is always rejected (JWT-003). Passing no algorithms keeps
// the default asymmetric allowlist.
func WithAllowedAlgorithms(algs ...string) Option {
	return func(c *config) { c.allowedAlgs = algs }
}

// WithNow overrides the clock used to evaluate exp/nbf, for deterministic
// tests. Production callers should leave the default ([time.Now]).
func WithNow(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

// WithClaimsValidator installs a [ClaimsValidator] that runs after the signature
// and the registered/required claim checks pass — the hook for application
// policy on the decoded claims (tenant, scope, role checks). A rejection
// (*[ClaimsValidationError]) fails the token; any other error from the validator
// fails it closed too, wrapped generically. Compose several rules with
// [CombineClaimsValidators] and the ready-made [RequireClaims],
// [RequireClaimValue], and [RequireScopes].
func WithClaimsValidator(v ClaimsValidator) Option {
	return func(c *config) { c.claimsValidator = v }
}

// WithLogger enables server-side logging of claims-validator outcomes through
// logger: a rejection is logged at INFO with its structured reason, a
// programming error in a validator at ERROR. When unset (the default) the
// library logs nothing, keeping it quiet unless the application opts in.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}
