package introspection

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Audience models the introspection "aud" member, which per RFC 7662 §2.2 (via
// RFC 7519 §4.1.3) MAY be a single string or an array of strings. It always
// unmarshals into a slice.
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
	var many []*string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("audience: must be a string or array of strings: %w", err)
	}
	out := make(Audience, 0, len(many))
	for _, s := range many {
		if s == nil {
			return fmt.Errorf("audience: array contains a null element")
		}
		out = append(out, *s)
	}
	*a = out
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

// Introspection is the response from an OAuth 2.0 token introspection request
// (RFC 7662 §2.2). Only Active is guaranteed present; the standard metadata
// members are populated when active=true and applicable, and any additional
// provider-specific members are preserved in Extra.
type Introspection struct {
	// Active indicates whether the token is currently active (REQUIRED). A token
	// is active if it has been issued and is neither expired nor revoked.
	Active bool `json:"active"`
	// Scope is the space-delimited list of scopes associated with the token.
	Scope string `json:"scope,omitempty"`
	// ClientID is the client identifier the token was issued to.
	ClientID string `json:"client_id,omitempty"`
	// Username is a human-readable identifier for the resource owner.
	Username string `json:"username,omitempty"`
	// TokenType is the type of the token, e.g. "Bearer".
	TokenType string `json:"token_type,omitempty"`
	// Exp is the token expiration time (seconds since the Unix epoch).
	Exp int64 `json:"exp,omitempty"`
	// Iat is the token issuance time (seconds since the Unix epoch).
	Iat int64 `json:"iat,omitempty"`
	// Nbf is the not-before time (seconds since the Unix epoch).
	Nbf int64 `json:"nbf,omitempty"`
	// Sub is the subject of the token.
	Sub string `json:"sub,omitempty"`
	// Aud is the intended audience; a single string or an array of strings.
	Aud Audience `json:"aud,omitempty"`
	// Iss is the issuer of the token.
	Iss string `json:"iss,omitempty"`
	// Jti is the string identifier of the token (the JWT ID).
	Jti string `json:"jti,omitempty"`
	// Extra holds any non-standard members returned by the provider.
	Extra map[string]any `json:"-"`
}

// standardMembers are the §2.2 members routed to typed fields; anything else
// falls through to Extra.
var standardMembers = map[string]bool{
	"active": true, "scope": true, "client_id": true, "username": true,
	"token_type": true, "exp": true, "iat": true, "nbf": true,
	"sub": true, "aud": true, "iss": true, "jti": true,
}

// UnmarshalJSON decodes an introspection response, routing the standard §2.2
// members to their typed fields and preserving any additional members in Extra.
// The typed members are decoded via an alias so their field tags apply while
// this method keeps control of the overflow map.
func (r *Introspection) UnmarshalJSON(data []byte) error {
	type alias Introspection
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = Introspection(a)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// active is REQUIRED (RFC 7662 §2.2). A 2xx body that omits it (e.g. `{}` or
	// `null`) or sets it to JSON null would silently decode to Active=false,
	// indistinguishable from a legitimately inactive token; reject it as
	// malformed instead. A wrong-typed active (e.g. a string) is already caught
	// by the alias decode above.
	if av, ok := raw["active"]; !ok || bytes.Equal(bytes.TrimSpace(av), []byte("null")) {
		return fmt.Errorf("introspection: response missing required \"active\" member (RFC 7662 §2.2)")
	}
	for k := range raw {
		if standardMembers[k] {
			delete(raw, k)
		}
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
