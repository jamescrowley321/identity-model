package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
)

// A ClaimsValidator runs after the signature and the registered/required claim
// checks pass — the hook an application uses to enforce its own rules on the
// decoded [Claims] (tenant membership, custom scopes, role checks, ...). Supply
// one with [WithClaimsValidator].
//
// ValidateClaims returns nil to accept and a *[ClaimsValidationError] to reject.
// A rejection then propagates from [Validate] unchanged, carrying its structured
// reason. Returning any other (non-ClaimsValidationError) error is treated as a
// programming error: [Validate] fails the token closed, wrapping it in a generic
// "claims validation failed" error rather than trusting the token.
//
// This mirrors the injectable claims validator in the Python and Rust libraries
// so a resource server can express the same policy in any of them.
type ClaimsValidator interface {
	ValidateClaims(claims *Claims) error
}

// ClaimsValidatorFunc adapts a plain function to the [ClaimsValidator]
// interface, so a one-off rule can be written inline without a named type.
type ClaimsValidatorFunc func(claims *Claims) error

// ValidateClaims calls f.
func (f ClaimsValidatorFunc) ValidateClaims(claims *Claims) error { return f(claims) }

// ErrClaimsValidation matches any *[ClaimsValidationError] via errors.Is. A
// ClaimsValidationError also matches [ErrClaimValidation], so a caller that
// already branches on the general claim-validation sentinel catches injected
// rejections too (parity with the Python ClaimsValidationError being a subclass
// of the base validation exception).
var ErrClaimsValidation = errors.New("jwt: claims validation rejected")

// ClaimsValidationError is the typed rejection returned by a [ClaimsValidator].
// It carries a structured Reason and, when the rejection is tied to a specific
// claim, that claim's name — so callers surface why without parsing a message.
type ClaimsValidationError struct {
	// Reason explains why the claims were rejected.
	Reason string
	// Claim optionally names the offending claim ("" when the rejection is not
	// tied to a single claim, e.g. an aggregated any-of failure).
	Claim string
}

func (e *ClaimsValidationError) Error() string {
	if e.Claim != "" {
		return fmt.Sprintf("jwt: claims validation rejected: %s (claim %q)", e.Reason, e.Claim)
	}
	return fmt.Sprintf("jwt: claims validation rejected: %s", e.Reason)
}

// Is reports a match for both the dedicated [ErrClaimsValidation] sentinel and
// the general [ErrClaimValidation] sentinel, integrating injected-validator
// rejections into the existing claim-validation taxonomy.
func (e *ClaimsValidationError) Is(target error) bool {
	return target == ErrClaimsValidation || target == ErrClaimValidation
}

// CombineMode selects how [CombineClaimsValidators] combines its members.
type CombineMode string

const (
	// CombineAll requires every validator to accept. The combined validator
	// fails fast, returning the first rejection (or programming error). An empty
	// all-of set is a no-op that accepts.
	CombineAll CombineMode = "all"
	// CombineAny requires at least one validator to accept. The combined
	// validator returns an aggregated *[ClaimsValidationError] only if every
	// member rejects. An empty any-of set is a construction error.
	CombineAny CombineMode = "any"
)

// CombineClaimsValidators composes validators into a single [ClaimsValidator],
// evaluated in order.
//
// With mode [CombineAll] every validator must accept; the combined validator
// returns the first non-nil error (fail fast). An empty all-of set accepts.
//
// With mode [CombineAny] at least one validator must accept. A member that
// returns a *[ClaimsValidationError] is a clean reject: the next member is
// tried. If every member rejects, the combined validator returns a
// *ClaimsValidationError aggregating each reason. Crucially, only a
// *ClaimsValidationError counts as a clean reject — any other error (a
// programming bug in a member) propagates immediately rather than being recorded
// as a rejection reason, which could otherwise flip the result to accept.
//
// It returns an error for an unknown mode, or for [CombineAny] with no
// validators (an empty any-of set can never be satisfied, so it would reject
// every token — guarded at construction rather than at call time).
func CombineClaimsValidators(validators []ClaimsValidator, mode CombineMode) (ClaimsValidator, error) {
	if mode != CombineAll && mode != CombineAny {
		return nil, fmt.Errorf("jwt: CombineClaimsValidators mode must be %q or %q, got %q", CombineAll, CombineAny, mode)
	}
	members := append([]ClaimsValidator(nil), validators...)
	if mode == CombineAny && len(members) == 0 {
		return nil, fmt.Errorf("jwt: CombineClaimsValidators(%q) needs at least one validator; an empty any-of set rejects every token", CombineAny)
	}

	return ClaimsValidatorFunc(func(claims *Claims) error {
		if mode == CombineAll {
			for _, v := range members {
				if err := v.ValidateClaims(claims); err != nil {
					return err
				}
			}
			return nil
		}

		reasons := make([]string, 0, len(members))
		for _, v := range members {
			err := v.ValidateClaims(claims)
			if err == nil {
				return nil
			}
			var cve *ClaimsValidationError
			if !errors.As(err, &cve) {
				// A programming error, not a clean reject: propagate immediately.
				return err
			}
			reasons = append(reasons, cve.Reason)
		}
		return &ClaimsValidationError{
			Reason: "no validator accepted the claims: " + strings.Join(reasons, "; "),
		}
	}), nil
}

// RequireClaims returns a [ClaimsValidator] that rejects unless every named
// claim is present and non-null. A claim carrying a JSON null counts as missing.
// It returns an error if no claim names are given.
func RequireClaims(names ...string) (ClaimsValidator, error) {
	if len(names) == 0 {
		return nil, errors.New("jwt: RequireClaims needs at least one claim name")
	}
	required := append([]string(nil), names...)
	return ClaimsValidatorFunc(func(claims *Claims) error {
		for _, name := range required {
			if claimMissing(claims, name) {
				return &ClaimsValidationError{
					Reason: fmt.Sprintf("required claim %q is missing", name),
					Claim:  name,
				}
			}
		}
		return nil
	}), nil
}

// RequireClaimValue returns a [ClaimsValidator] that rejects unless claim name
// is present AND equal to value. An absent claim always rejects — including when
// value is nil, so RequireClaimValue("x", nil) means "x must be present and
// null", not "x may be missing" (the fail-open a plain absent-is-ok check would
// allow). Values are compared by JSON equality, so a JSON number in the token
// matches an int or float expectation regardless of Go's numeric type.
func RequireClaimValue(name string, value any) ClaimsValidator {
	// Normalise the expected value through the JSON codec once, so it lands in
	// the same type space (float64 for numbers, etc.) as a decoded claim.
	wantJSON, wantErr := json.Marshal(value)
	var want any
	if wantErr == nil {
		_ = json.Unmarshal(wantJSON, &want)
	}
	return ClaimsValidatorFunc(func(claims *Claims) error {
		reject := &ClaimsValidationError{
			Reason: fmt.Sprintf("claim %q must equal %v", name, value),
			Claim:  name,
		}
		raw, ok := claims.GetClaim(name)
		if !ok {
			return reject // absent always rejects, even when value is nil
		}
		if wantErr != nil {
			return reject // expected value is not JSON-encodable; nothing can match it
		}
		var got any
		if err := json.Unmarshal(raw, &got); err != nil {
			return reject
		}
		if !reflect.DeepEqual(got, want) {
			return reject
		}
		return nil
	})
}

// RequireScopes returns a [ClaimsValidator] that rejects unless the token grants
// every named scope. Scopes are read from the OAuth 2.0 scope claim (a
// space-delimited string) or the scp claim (an array). It returns an error if no
// scopes are given.
func RequireScopes(scopes ...string) (ClaimsValidator, error) {
	if len(scopes) == 0 {
		return nil, errors.New("jwt: RequireScopes needs at least one scope")
	}
	required := append([]string(nil), scopes...)
	return ClaimsValidatorFunc(func(claims *Claims) error {
		granted := grantedScopes(claims)
		var missing []string
		for _, scope := range required {
			if _, ok := granted[scope]; !ok {
				missing = append(missing, scope)
			}
		}
		if len(missing) > 0 {
			return &ClaimsValidationError{
				Reason: fmt.Sprintf("missing required scope(s): %s", strings.Join(missing, ", ")),
				Claim:  "scope",
			}
		}
		return nil
	}), nil
}

// claimMissing reports whether name is absent, or present but JSON null.
func claimMissing(claims *Claims, name string) bool {
	raw, ok := claims.GetClaim(name)
	if !ok {
		return true
	}
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// grantedScopes returns the scopes the token grants, read from scope (a
// space-delimited string) or scp (an array). An absent, null, or empty-string
// scope falls through to scp — some IdPs send {"scope": "", "scp": [...]}, and
// an empty string must not shadow a populated array. A malformed (non-string,
// non-array) scope does NOT fall through: it yields no scopes, so the validator
// fails closed rather than treating the token as fully scoped.
func grantedScopes(claims *Claims) map[string]struct{} {
	value, ok := decodeClaim(claims, "scope")
	if !ok || value == nil {
		value, _ = decodeClaim(claims, "scp")
	} else if s, isStr := value.(string); isStr && s == "" {
		value, _ = decodeClaim(claims, "scp")
	}
	return scopesFromValue(value)
}

// decodeClaim decodes the named claim into a Go value (the JSON type space:
// string, float64, bool, []any, map[string]any, or nil). The bool reports
// presence. A claim whose JSON fails to decode yields a nil value.
func decodeClaim(claims *Claims, name string) (any, bool) {
	raw, ok := claims.GetClaim(name)
	if !ok {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, true
	}
	return v, true
}

// scopesFromValue extracts a scope set from a decoded claim value: a string is
// split on whitespace; an array contributes its string members (non-string
// members are dropped); any other shape yields no scopes (fail closed).
func scopesFromValue(value any) map[string]struct{} {
	set := make(map[string]struct{})
	switch v := value.(type) {
	case string:
		for _, s := range strings.Fields(v) {
			set[s] = struct{}{}
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				set[s] = struct{}{}
			}
		}
	}
	return set
}

// runClaimsValidator invokes the configured claims validator against the decoded
// claims, logging any rejection server-side (parity with the Python pipeline). A
// *ClaimsValidationError propagates unchanged, preserving its structured reason;
// any other error is a programming bug in the validator, so the token fails
// closed wrapped in a generic error rather than being trusted.
func runClaimsValidator(ctx context.Context, cfg *config, claims *Claims) (err error) {
	// A panicking validator (or a typed-nil ClaimsValidatorFunc, whose non-nil
	// interface passes the guard but nil-func call panics) must fail the token
	// CLOSED as a wrapped rejection — never crash Validate or yield an accept.
	// Mirrors Python's "any error -> generic wrapped rejection".
	defer func() {
		if r := recover(); r != nil {
			if cfg.logger != nil {
				cfg.logger.LogAttrs(ctx, slog.LevelError, "claims validator panicked",
					slog.Any("panic", r))
			}
			err = fmt.Errorf("jwt: claims validation failed: validator panicked: %v", r)
		}
	}()

	err = cfg.claimsValidator.ValidateClaims(claims)
	if err == nil {
		return nil
	}

	var cve *ClaimsValidationError
	if errors.As(err, &cve) {
		if cfg.logger != nil {
			cfg.logger.LogAttrs(ctx, slog.LevelInfo, "claims validation rejected the token",
				slog.String("reason", cve.Reason), slog.String("claim", cve.Claim))
		}
		return err
	}

	if cfg.logger != nil {
		cfg.logger.LogAttrs(ctx, slog.LevelError, "claims validation failed",
			slog.String("error", err.Error()))
	}
	return fmt.Errorf("jwt: claims validation failed: %w", err)
}
