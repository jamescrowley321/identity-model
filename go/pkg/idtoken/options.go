package idtoken

import (
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// config holds the resolved settings for a validation call. The base fields
// configure the underlying [jwt.Validate]; the profile fields drive the
// ID-Token-specific rules. [ValidateClaims] reads only the profile fields (the
// base fields are irrelevant to the network-free claim validator).
type config struct {
	// Base JWT validation (used only by ValidateIDToken).
	issuer      string
	allowedAlgs []string

	// ID-Token profile.
	clientID       string
	nonce          string
	nonceSet       bool
	accessToken    string
	accessTokenSet bool
	code           string
	codeSet        bool
	maxAge         time.Duration
	maxAgeSet      bool
	// leeway is the clock-skew tolerance. It is applied to the base exp check
	// (as jwt.WithClockSkew) and, mirroring the reference implementation, to the
	// max_age/auth_time freshness check (§3.1.3.7 step 12).
	leeway  time.Duration
	nowFunc func() time.Time
}

// Option customises validation via the functional-options pattern, mirroring
// the jwt, discovery and jwks clients so the packages compose consistently.
type Option func(*config)

func newConfig(opts ...Option) *config {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// now resolves the clock, defaulting to time.Now.
func (c *config) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

// jwtOptions maps the base config onto the options for [jwt.Validate]. The nonce
// is intentionally NOT forwarded: the ID-Token profile owns the nonce check so a
// mismatch surfaces as a ProfileError (nonce_mismatch), matching the reference.
func (c *config) jwtOptions() []jwt.Option {
	var opts []jwt.Option
	if c.issuer != "" {
		opts = append(opts, jwt.WithExpectedIssuer(c.issuer))
	}
	// The RP's client_id MUST be an aud member of an ID Token, so it doubles as
	// the expected audience for the base validation (§3.1.3.7 step 3).
	if c.clientID != "" {
		opts = append(opts, jwt.WithExpectedAudience(c.clientID))
	}
	if c.leeway != 0 {
		opts = append(opts, jwt.WithClockSkew(c.leeway))
	}
	if len(c.allowedAlgs) > 0 {
		opts = append(opts, jwt.WithAllowedAlgorithms(c.allowedAlgs...))
	}
	if c.nowFunc != nil {
		opts = append(opts, jwt.WithNow(c.nowFunc))
	}
	return opts
}

// WithIssuer sets the expected issuer for the base JWT validation (§3.1.3.7
// step 2). Used only by [ValidateIDToken].
func WithIssuer(issuer string) Option {
	return func(c *config) { c.issuer = issuer }
}

// WithClientID sets the relying party's client_id. It is enforced as the
// expected audience of the base JWT validation (§3.1.3.7 step 3) and, when a
// token carries an azp, azp MUST equal it (§3.1.3.7 step 6).
func WithClientID(clientID string) Option {
	return func(c *config) { c.clientID = clientID }
}

// WithNonce requires the token's nonce to be present and equal nonce, the value
// the RP sent on the authorization request (§3.1.3.7 step 11). When unset, nonce
// is not checked. An empty string is a valid expected value, so the option
// records that a nonce was requested.
func WithNonce(nonce string) Option {
	return func(c *config) {
		c.nonce = nonce
		c.nonceSet = true
	}
}

// WithAccessToken requires the token's at_hash to be present and match the
// left-half hash of accessToken (§3.3.2.11). When unset, at_hash is not checked.
func WithAccessToken(accessToken string) Option {
	return func(c *config) {
		c.accessToken = accessToken
		c.accessTokenSet = true
	}
}

// WithCode requires the token's c_hash to be present and match the left-half
// hash of code (§3.3.2.11). When unset, c_hash is not checked.
func WithCode(code string) Option {
	return func(c *config) {
		c.code = code
		c.codeSet = true
	}
}

// WithMaxAge requires auth_time to be present and satisfy
// now - auth_time <= maxAge + leeway (§3.1.3.7 step 12). When unset, auth_time
// is not checked.
func WithMaxAge(maxAge time.Duration) Option {
	return func(c *config) {
		c.maxAge = maxAge
		c.maxAgeSet = true
	}
}

// WithClockSkew tolerates up to d of clock drift. It applies to the base exp
// check and to the max_age/auth_time freshness check (§3.1.3.7 step 12). The
// default is zero.
func WithClockSkew(d time.Duration) Option {
	return func(c *config) { c.leeway = d }
}

// WithAllowedAlgorithms overrides the accepted JWS algorithms for the base JWT
// validation (see [jwt.WithAllowedAlgorithms]). Used only by [ValidateIDToken].
func WithAllowedAlgorithms(algs ...string) Option {
	return func(c *config) { c.allowedAlgs = algs }
}

// WithNow overrides the clock used for the max_age/auth_time check (and the base
// exp check), for deterministic tests. Production callers leave the default
// (time.Now).
func WithNow(now func() time.Time) Option {
	return func(c *config) { c.nowFunc = now }
}
