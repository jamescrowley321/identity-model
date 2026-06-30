package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// NumericDate is a JWT timestamp: seconds (possibly fractional) since the Unix
// epoch (RFC 7519 §2). It marshals to and from a JSON number.
type NumericDate struct {
	time.Time
}

// maxNumericDate bounds an acceptable timestamp magnitude in seconds. Beyond
// 2^53 a float64 can no longer hold an integer second exactly, and the int64
// conversion below would overflow for very large inputs — wrapping a crafted
// far-future exp into a garbage time that defeats the expiry check. Real epoch
// timestamps are many orders of magnitude inside this bound.
const maxNumericDate = 1 << 53

// UnmarshalJSON decodes a JSON number of seconds since the epoch.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("numeric date: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f > maxNumericDate || f < -maxNumericDate {
		return fmt.Errorf("numeric date %v is out of range", f)
	}
	sec, frac := math.Modf(f)
	n.Time = time.Unix(int64(sec), int64(math.Round(frac*float64(time.Second)))).UTC()
	return nil
}

// MarshalJSON encodes the timestamp as a JSON number of whole seconds.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Unix())
}

// Audience is the JWT aud claim, which may be a single string or an array of
// strings (RFC 7519 §4.1.3). It always unmarshals into a slice.
type Audience []string

// UnmarshalJSON accepts either a JSON string or an array of strings. A JSON
// null yields an empty (nil) audience rather than a slice holding one empty
// string.
func (a *Audience) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		*a = nil
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("audience: must be a string or array of strings: %w", err)
	}
	*a = many
	return nil
}

// Contains reports whether the audience includes s.
func (a Audience) Contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// Claims is the validated set of JWT claims (RFC 7519 §4). The registered
// claims are modelled as fields; any additional claims are preserved in Extra
// and reachable through [Claims.GetClaim] and [Claims.GetString].
type Claims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  Audience     `json:"aud,omitempty"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
	Nonce     string       `json:"nonce,omitempty"`

	// Extra holds claims not modelled above (e.g. email, scope, groups).
	Extra map[string]json.RawMessage `json:"-"`

	// all holds every claim key from the payload, including the modelled ones,
	// so presence checks ([Claims.Has]) and the generic accessors can see the
	// full set. It is unexported; callers use the accessor methods.
	all map[string]json.RawMessage
}

// modelledClaimFields is the set of JSON names decoded into named [Claims]
// fields. They are excluded from Extra so Extra holds only unmodelled claims.
var modelledClaimFields = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {},
	"exp": {}, "nbf": {}, "iat": {},
	"jti": {}, "nonce": {},
}

// duplicateTopLevelKey reports the first claim name that appears more than once
// at the top level of a JSON object payload. encoding/json silently resolves
// duplicate keys last-wins, which would let an attacker smuggle a second iss or
// aud that the modelled fields and the Extra view disagree about; a security
// validator must reject such tokens. A payload that is not a JSON object yields
// "" — the struct decode in parseClaims reports the shape error instead.
func duplicateTopLevelKey(payload []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", nil
	}
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", err
		}
		key := keyTok.(string)
		if _, dup := seen[key]; dup {
			return key, nil
		}
		seen[key] = struct{}{}
		// Consume the value (including any nested object/array) so the next
		// token read is the following key.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", err
		}
	}
	return "", nil
}

// parseClaims decodes a JWT payload into typed [Claims], preserving unmodelled
// claims in Extra (mirrors the jwks key-parsing contract).
func parseClaims(payload []byte) (*Claims, error) {
	if dup, err := duplicateTopLevelKey(payload); err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("scan claims: %v", err)}
	} else if dup != "" {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("duplicate claim %q", dup)}
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("decode claims: %v", err)}
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("decode claims object: %v", err)}
	}
	c.all = all
	extra := make(map[string]json.RawMessage, len(all))
	for name, raw := range all {
		if _, modelled := modelledClaimFields[name]; !modelled {
			extra[name] = raw
		}
	}
	if len(extra) > 0 {
		c.Extra = extra
	}
	return &c, nil
}

// Has reports whether the named claim was present in the token payload,
// regardless of whether it is modelled as a field or stored in Extra.
func (c *Claims) Has(claim string) bool {
	_, ok := c.all[claim]
	return ok
}

// GetClaim returns the raw JSON of the named claim and whether it was present.
func (c *Claims) GetClaim(claim string) (json.RawMessage, bool) {
	raw, ok := c.all[claim]
	return raw, ok
}

// GetString returns the named claim decoded as a string. It reports an error if
// the claim is absent or is not a JSON string.
func (c *Claims) GetString(claim string) (string, error) {
	raw, ok := c.all[claim]
	if !ok {
		return "", fmt.Errorf("jwt: claim %q not present", claim)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("jwt: claim %q is not a string: %w", claim, err)
	}
	return s, nil
}

// validate enforces the registered and configured claim rules. iat must always
// be present (JWT-013) and exp must not be expired (JWT-005); the remaining
// checks apply only when the corresponding option was supplied.
func (c *Claims) validate(cfg *config) error {
	now := cfg.now()
	skew := cfg.clockSkew

	// iat MUST be present (JWT-002, JWT-013, RFC 7519 §4.1.6 — required by this
	// validator even though the RFC marks it optional).
	if c.IssuedAt == nil {
		return &ClaimValidationError{Claim: "iat", Reason: "required claim is missing"}
	}

	// exp MUST be present and not expired, allowing for clock skew (JWT-005,
	// JWT-011, RFC 7519 §4.1.4).
	if c.Expiry == nil {
		return &ClaimValidationError{Claim: "exp", Reason: "required claim is missing"}
	}
	if !now.Add(-skew).Before(c.Expiry.Time) {
		return &ClaimValidationError{Claim: "exp", Reason: "token has expired"}
	}

	// nbf, when present, must not be in the future beyond the skew (JWT-006,
	// RFC 7519 §4.1.5).
	if c.NotBefore != nil && now.Add(skew).Before(c.NotBefore.Time) {
		return &ClaimValidationError{Claim: "nbf", Reason: "token is not yet valid"}
	}

	// iss exact match when expected (JWT-007, RFC 7519 §4.1.1).
	if cfg.expectedIssuer != "" && c.Issuer != cfg.expectedIssuer {
		return &ClaimValidationError{Claim: "iss", Reason: fmt.Sprintf("expected %q, got %q", cfg.expectedIssuer, c.Issuer)}
	}

	// aud must contain the expected audience when expected (JWT-008, RFC 7519
	// §4.1.3).
	if cfg.expectedAudience != "" && !c.Audience.Contains(cfg.expectedAudience) {
		return &ClaimValidationError{Claim: "aud", Reason: fmt.Sprintf("does not contain expected audience %q", cfg.expectedAudience)}
	}

	// nonce match when expected (JWT-004, OIDC Core 1.0 §3.1.3.7).
	if cfg.nonceSet && c.Nonce != cfg.expectedNonce {
		return &ClaimValidationError{Claim: "nonce", Reason: "nonce does not match expected value"}
	}

	// custom required claims must be present (JWT-012, RFC 7519 §4.1).
	for _, claim := range cfg.requiredClaims {
		if !c.Has(claim) {
			return &ClaimValidationError{Claim: claim, Reason: "required claim is missing"}
		}
	}

	return nil
}
