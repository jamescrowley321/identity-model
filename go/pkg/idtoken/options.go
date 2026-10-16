package idtoken

import (
	"slices"
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
	clientID         string
	trustedAudiences []string
	validateAZP      bool
	nonce            string
	nonceSet         bool
	accessToken      string
	accessTokenSet   bool
	// accessTokenWithIDToken: the access token came in the same authorization
	// response as the ID Token, so at_hash is required (§3.2.2.10, §3.3.2.11).
	// Defaults to true.
	accessTokenWithIDToken bool
	code                   string
	codeSet                bool
	// codeWithIDToken: the code came in the same authorization response as the
	// ID Token, so c_hash is required (§3.3.2.11). Defaults to true.
	codeWithIDToken bool
	maxAge          time.Duration
	maxAgeSet       bool
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
	cfg := &config{accessTokenWithIDToken: true, codeWithIDToken: true}
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

// trustsAudience reports whether aud is the client_id (when set) or one of the
// configured trusted audiences (§3.1.3.7 step 3).
func (c *config) trustsAudience(aud string) bool {
	if c.clientID != "" && aud == c.clientID {
		return true
	}
	return slices.Contains(c.trustedAudiences, aud)
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
// expected audience of the base JWT validation (§3.1.3.7 step 3) and, with
// [WithAZPValidation], is the value a present azp must equal.
func WithClientID(clientID string) Option {
	return func(c *config) { c.clientID = clientID }
}

// WithTrustedAudiences lists the additional audiences, besides the client_id,
// that the client trusts to appear in an ID Token's aud. Every aud value MUST be
// the client_id or one of these, otherwise the token is rejected (§3.1.3.7
// step 3). The list only adds trusted values: omitting it, or passing none,
// trusts the client_id alone, and nothing disables the check.
func WithTrustedAudiences(audiences ...string) Option {
	return func(c *config) { c.trustedAudiences = audiences }
}

// WithAZPValidation opts in to the authorized-party (azp) rules: a token with
// multiple audiences must carry an azp, and a present azp must equal the
// client_id. OIDC Core 1.0 errata set 2 makes neither a MUST — §3.1.3.7 step 5
// is a MAY/SHOULD, and the multiple-audience rule is the Core 1.0 (2014) step-4
// SHOULD that errata set 2 removed. Without this option azp is ignored, as §2
// advises relying parties that use no extensions.
func WithAZPValidation() Option {
	return func(c *config) { c.validateAZP = true }
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

// WithAccessToken requires the token's at_hash to match the left-half hash of
// accessToken (§3.3.2.11). The claim must also be present unless
// [WithAccessTokenIssuedWithIDToken](false) is set. When unset, at_hash is not
// checked.
func WithAccessToken(accessToken string) Option {
	return func(c *config) {
		c.accessToken = accessToken
		c.accessTokenSet = true
	}
}

// WithAccessTokenIssuedWithIDToken states whether the [WithAccessToken] value
// came back in the same authorization response as the ID Token (response_type
// "id_token token" or "code id_token token"), which makes at_hash REQUIRED
// (§3.2.2.10, §3.3.2.11). The default is true. Pass false for a token-endpoint
// ID Token, which may omit at_hash (§3.1.3.6); a present at_hash must still
// match. It has no effect without [WithAccessToken].
func WithAccessTokenIssuedWithIDToken(issued bool) Option {
	return func(c *config) { c.accessTokenWithIDToken = issued }
}

// WithCode requires the token's c_hash to match the left-half hash of code
// (§3.3.2.11). The claim must also be present unless
// [WithCodeIssuedWithIDToken](false) is set. When unset, c_hash is not checked.
func WithCode(code string) Option {
	return func(c *config) {
		c.code = code
		c.codeSet = true
	}
}

// WithCodeIssuedWithIDToken states whether the [WithCode] value came back in
// the same authorization response as the ID Token (response_type
// "code id_token" or "code id_token token"), which makes c_hash REQUIRED
// (§3.3.2.11). The default is true. Pass false when it did not; a present
// c_hash must still match. It has no effect without [WithCode].
func WithCodeIssuedWithIDToken(issued bool) Option {
	return func(c *config) { c.codeWithIDToken = issued }
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
