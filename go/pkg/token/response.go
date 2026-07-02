package token

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// TokenResponse is a successful OAuth 2.0 token endpoint response
// (RFC 6749 §5.1). Standard parameters are modelled as typed fields; any
// additional provider-specific parameters are preserved in Extra.
type TokenResponse struct {
	// AccessToken is the issued access token (required).
	AccessToken string `json:"access_token"`
	// TokenType is the token type, typically "Bearer" (required).
	TokenType string `json:"token_type"`
	// ExpiresIn is the access token lifetime in seconds, if provided.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// Scope is the granted scope, if it differs from the request.
	Scope string `json:"scope,omitempty"`
	// RefreshToken is the issued refresh token, if any.
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken is the OIDC ID token, present for the authorization code grant
	// when the openid scope was requested.
	IDToken string `json:"id_token,omitempty"`
	// Extra holds any non-standard parameters returned by the provider.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON decodes a token response, routing modelled parameters to their
// typed fields and any remaining parameters to Extra. expires_in is tolerated
// as either a JSON number or a numeric string, since some providers send it as
// a string even though RFC 6749 specifies a number.
func (r *TokenResponse) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	strFields := map[string]*string{
		"access_token":  &r.AccessToken,
		"token_type":    &r.TokenType,
		"scope":         &r.Scope,
		"refresh_token": &r.RefreshToken,
		"id_token":      &r.IDToken,
	}
	for key, dst := range strFields {
		if v, ok := raw[key]; ok {
			if err := json.Unmarshal(v, dst); err != nil {
				return fmt.Errorf("decode %s: %w", key, err)
			}
			delete(raw, key)
		}
	}

	if v, ok := raw["expires_in"]; ok {
		n, err := flexibleInt64(v)
		if err != nil {
			return fmt.Errorf("decode expires_in: %w", err)
		}
		r.ExpiresIn = n
		delete(raw, "expires_in")
	}

	if len(raw) > 0 {
		r.Extra = make(map[string]any, len(raw))
		for k, v := range raw {
			var val any
			if err := json.Unmarshal(v, &val); err != nil {
				return fmt.Errorf("decode extra field %s: %w", k, err)
			}
			r.Extra[k] = val
		}
	}
	return nil
}

// flexibleInt64 decodes a JSON value that is either a number or a numeric
// string into an int64. expires_in is an optional parameter (RFC 6749 §5.1),
// so a JSON null or empty string is treated as absent (0) rather than an error:
// a valid token must not be discarded over a missing-but-present lifetime. A
// fractional value (e.g. 3600.0, sent by some providers) is truncated to whole
// seconds.
func flexibleInt64(v json.RawMessage) (int64, error) {
	if string(v) == "null" {
		return 0, nil
	}
	var n json.Number
	if err := json.Unmarshal(v, &n); err == nil {
		if n == "" {
			return 0, nil
		}
		if i, err := n.Int64(); err == nil {
			return i, nil
		}
		if f, err := n.Float64(); err == nil {
			return floatToSeconds(f)
		}
		return 0, fmt.Errorf("expected integer seconds, got %q", n.String())
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return 0, fmt.Errorf("expected number or numeric string")
	}
	if s = strings.TrimSpace(s); s == "" {
		return 0, nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return floatToSeconds(f)
	}
	return 0, fmt.Errorf("expected numeric string, got %q", s)
}

// floatToSeconds truncates a fractional lifetime to whole seconds, rejecting
// values that cannot be represented as an int64 (overflow, Inf, NaN) so that a
// crafted or malformed expires_in cannot silently wrap to a garbage time.
func floatToSeconds(f float64) (int64, error) {
	if math.IsInf(f, 0) || math.IsNaN(f) || f >= math.MaxInt64 || f < math.MinInt64 {
		return 0, fmt.Errorf("expires_in out of range: %v", f)
	}
	return int64(f), nil
}
