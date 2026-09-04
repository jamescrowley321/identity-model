package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// claimsFrom builds a *Claims from a raw JSON object, exercising the real
// claim-parsing path so the validators see claims exactly as Validate would.
func claimsFrom(t *testing.T, obj map[string]any) *Claims {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	c, err := parseClaims(b)
	if err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	return c
}

// requireClaims / requireScopes / combine construct the fallible validators,
// failing the test on a construction error (Go cannot splice a two-value return
// into a call that prepends t).
func requireClaims(t *testing.T, names ...string) ClaimsValidator {
	t.Helper()
	v, err := RequireClaims(names...)
	if err != nil {
		t.Fatalf("RequireClaims: %v", err)
	}
	return v
}

func requireScopes(t *testing.T, scopes ...string) ClaimsValidator {
	t.Helper()
	v, err := RequireScopes(scopes...)
	if err != nil {
		t.Fatalf("RequireScopes: %v", err)
	}
	return v
}

func combine(t *testing.T, validators []ClaimsValidator, mode CombineMode) ClaimsValidator {
	t.Helper()
	v, err := CombineClaimsValidators(validators, mode)
	if err != nil {
		t.Fatalf("CombineClaimsValidators: %v", err)
	}
	return v
}

// asClaimsErr extracts a *ClaimsValidationError, failing the test otherwise.
func asClaimsErr(t *testing.T, err error) *ClaimsValidationError {
	t.Helper()
	var cve *ClaimsValidationError
	if !errors.As(err, &cve) {
		t.Fatalf("err = %v, want *ClaimsValidationError", err)
	}
	return cve
}

// errBoom / boom model a validator with a programming error (not a clean reject).
var errBoom = errors.New("bug")

func boom(_ *Claims) error { return errBoom }

// --- ClaimsValidationError -------------------------------------------------

func TestClaimsValidationError_TypedAndStructured(t *testing.T) {
	err := &ClaimsValidationError{Reason: "nope", Claim: "tenant"}
	if err.Reason != "nope" || err.Claim != "tenant" {
		t.Fatalf("fields = %q/%q", err.Reason, err.Claim)
	}
	// Integrated into the existing taxonomy: matches its own sentinel AND the
	// general claim-validation sentinel.
	if !errors.Is(err, ErrClaimsValidation) {
		t.Error("errors.Is(err, ErrClaimsValidation) = false")
	}
	if !errors.Is(err, ErrClaimValidation) {
		t.Error("errors.Is(err, ErrClaimValidation) = false")
	}
	if !strings.Contains(err.Error(), "tenant") || !strings.Contains(err.Error(), "nope") {
		t.Errorf("Error() = %q, want reason+claim", err.Error())
	}
}

func TestClaimsValidationError_WithoutClaim(t *testing.T) {
	err := &ClaimsValidationError{Reason: "nope"}
	if err.Claim != "" {
		t.Errorf("Claim = %q, want empty", err.Claim)
	}
	if strings.Contains(err.Error(), "claim ") {
		t.Errorf("Error() = %q, should omit the claim clause", err.Error())
	}
}

// --- RequireClaims ---------------------------------------------------------

func TestRequireClaims(t *testing.T) {
	v := requireClaims(t, "sub", "tid")

	// Accepts when all present.
	if err := v.ValidateClaims(claimsFrom(t, map[string]any{"sub": "u1", "tid": "t1"})); err != nil {
		t.Fatalf("all present: %v", err)
	}

	// Rejects a missing claim, naming it.
	err := v.ValidateClaims(claimsFrom(t, map[string]any{"sub": "u1"}))
	if cve := asClaimsErr(t, err); cve.Claim != "tid" {
		t.Errorf("claim = %q, want tid", cve.Claim)
	}

	// A JSON null counts as missing.
	nv := requireClaims(t, "tid")
	if err := nv.ValidateClaims(claimsFrom(t, map[string]any{"tid": nil})); err == nil {
		t.Error("null claim: want rejection")
	}
}

func TestRequireClaims_NeedsAName(t *testing.T) {
	if _, err := RequireClaims(); err == nil {
		t.Error("RequireClaims() with no names should error")
	}
}

// --- RequireClaimValue -----------------------------------------------------

func TestRequireClaimValue_AcceptsAndRejects(t *testing.T) {
	v := RequireClaimValue("role", "admin")
	if err := v.ValidateClaims(claimsFrom(t, map[string]any{"role": "admin"})); err != nil {
		t.Fatalf("matching value: %v", err)
	}
	err := v.ValidateClaims(claimsFrom(t, map[string]any{"role": "user"}))
	if cve := asClaimsErr(t, err); cve.Claim != "role" {
		t.Errorf("claim = %q, want role", cve.Claim)
	}
}

func TestRequireClaimValue_RejectsAbsentClaim(t *testing.T) {
	err := RequireClaimValue("role", "admin").ValidateClaims(claimsFrom(t, map[string]any{}))
	if cve := asClaimsErr(t, err); cve.Claim != "role" {
		t.Errorf("claim = %q, want role", cve.Claim)
	}
}

func TestRequireClaimValue_NilMeansPresentNullNotAbsent(t *testing.T) {
	v := RequireClaimValue("x", nil)
	// "must equal nil" means present-and-null.
	if err := v.ValidateClaims(claimsFrom(t, map[string]any{"x": nil})); err != nil {
		t.Errorf("present null: %v, want accept", err)
	}
	// An absent claim must NOT pass (fail closed).
	if err := v.ValidateClaims(claimsFrom(t, map[string]any{})); err == nil {
		t.Error("absent claim: want rejection")
	}
}

func TestRequireClaimValue_NumericJSONEquality(t *testing.T) {
	// A JSON number in the token matches an int expectation despite Go decoding
	// it to float64.
	if err := RequireClaimValue("ver", 2).ValidateClaims(claimsFrom(t, map[string]any{"ver": 2})); err != nil {
		t.Errorf("numeric equality: %v", err)
	}
	if err := RequireClaimValue("ver", 2).ValidateClaims(claimsFrom(t, map[string]any{"ver": 3})); err == nil {
		t.Error("numeric mismatch: want rejection")
	}
}

// --- RequireScopes ---------------------------------------------------------

func TestRequireScopes(t *testing.T) {
	tests := []struct {
		name    string
		require []string
		claims  map[string]any
		wantErr bool
		// missingNamed / notNamed assert the reason names only the missing scopes.
		missingNamed []string
		notNamed     []string
	}{
		{
			name:    "from space-delimited scope string",
			require: []string{"read"},
			claims:  map[string]any{"scope": "read write"},
		},
		{
			name:    "from scp list",
			require: []string{"read", "write"},
			claims:  map[string]any{"scp": []any{"read", "write", "admin"}},
		},
		{
			name:         "rejects missing and names only them",
			require:      []string{"read", "delete"},
			claims:       map[string]any{"scope": "read"},
			wantErr:      true,
			missingNamed: []string{"delete"},
			notNamed:     []string{"read"},
		},
		{
			name:    "malformed object scope fails closed",
			require: []string{"read"},
			claims:  map[string]any{"scope": map[string]any{"unexpected": "shape"}},
			wantErr: true,
		},
		{
			name:    "malformed number scope fails closed",
			require: []string{"read"},
			claims:  map[string]any{"scope": 123},
			wantErr: true,
		},
		{
			name:    "null scope with no scp fails closed",
			require: []string{"read"},
			claims:  map[string]any{"scope": nil},
			wantErr: true,
		},
		{
			name:    "list drops non-string members but keeps valid scopes",
			require: []string{"read"},
			claims:  map[string]any{"scope": []any{"read", 7, nil}},
		},
		{
			name:    "list missing scope still rejects",
			require: []string{"admin"},
			claims:  map[string]any{"scope": []any{"read", 7, nil}},
			wantErr: true,
		},
		{
			name:    "empty-string scope falls through to scp",
			require: []string{"read"},
			claims:  map[string]any{"scope": "", "scp": []any{"read", "write"}},
		},
		{
			name:    "non-empty scope takes precedence over scp",
			require: []string{"write"},
			claims:  map[string]any{"scope": "read", "scp": []any{"write"}},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := requireScopes(t, tc.require...)
			err := v.ValidateClaims(claimsFrom(t, tc.claims))
			if tc.wantErr {
				cve := asClaimsErr(t, err)
				if cve.Claim != "scope" {
					t.Errorf("claim = %q, want scope", cve.Claim)
				}
				for _, s := range tc.missingNamed {
					if !strings.Contains(cve.Reason, s) {
						t.Errorf("reason %q should name missing scope %q", cve.Reason, s)
					}
				}
				for _, s := range tc.notNamed {
					if strings.Contains(cve.Reason, s) {
						t.Errorf("reason %q should not name granted scope %q", cve.Reason, s)
					}
				}
				return
			}
			if err != nil {
				t.Errorf("want accept, got %v", err)
			}
		})
	}
}

func TestRequireScopes_NeedsAScope(t *testing.T) {
	if _, err := RequireScopes(); err == nil {
		t.Error("RequireScopes() with no scopes should error")
	}
}

// --- CombineClaimsValidators -----------------------------------------------

func TestCombineAll_PassesWhenEveryValidatorPasses(t *testing.T) {
	combined := combine(t, []ClaimsValidator{
		requireClaims(t, "sub"),
		requireScopes(t, "read"),
	}, CombineAll)
	if err := combined.ValidateClaims(claimsFrom(t, map[string]any{"sub": "u1", "scope": "read"})); err != nil {
		t.Fatalf("all pass: %v", err)
	}
}

func TestCombineAll_ReturnsFirstFailure(t *testing.T) {
	combined := combine(t, []ClaimsValidator{
		requireClaims(t, "sub"),
		RequireClaimValue("role", "admin"),
	}, CombineAll)
	err := combined.ValidateClaims(claimsFrom(t, map[string]any{"sub": "u1", "role": "user"}))
	if cve := asClaimsErr(t, err); cve.Claim != "role" {
		t.Errorf("claim = %q, want role (first failure)", cve.Claim)
	}
}

func TestCombineAny_PassesWhenOnePasses(t *testing.T) {
	combined := combine(t, []ClaimsValidator{
		RequireClaimValue("role", "admin"),
		requireScopes(t, "read"),
	}, CombineAny)
	// role is "user" (first rejects) but scope "read" is granted (second passes).
	if err := combined.ValidateClaims(claimsFrom(t, map[string]any{"role": "user", "scope": "read"})); err != nil {
		t.Fatalf("any pass: %v", err)
	}
}

func TestCombineAny_AggregatesReasonsWhenAllReject(t *testing.T) {
	combined := combine(t, []ClaimsValidator{
		requireClaims(t, "a"),
		requireClaims(t, "b"),
	}, CombineAny)
	err := combined.ValidateClaims(claimsFrom(t, map[string]any{"c": 1}))
	cve := asClaimsErr(t, err)
	if !strings.Contains(cve.Reason, "a") || !strings.Contains(cve.Reason, "b") {
		t.Errorf("reason %q should aggregate both a and b", cve.Reason)
	}
}

func TestCombineAny_EmptyIsRejectedAtConstruction(t *testing.T) {
	if _, err := CombineClaimsValidators(nil, CombineAny); err == nil {
		t.Error("empty any-of set should be a construction error")
	}
}

func TestCombineAll_EmptyIsANoop(t *testing.T) {
	combined := combine(t, nil, CombineAll)
	if err := combined.ValidateClaims(claimsFrom(t, map[string]any{"anything": true})); err != nil {
		t.Errorf("empty all-of set should accept, got %v", err)
	}
}

func TestCombineAll_PropagatesNonClaimsError(t *testing.T) {
	combined := combine(t, []ClaimsValidator{ClaimsValidatorFunc(boom)}, CombineAll)
	err := combined.ValidateClaims(claimsFrom(t, map[string]any{}))
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom propagated", err)
	}
	var cve *ClaimsValidationError
	if errors.As(err, &cve) {
		t.Error("a programming error must not be reported as a ClaimsValidationError")
	}
}

func TestCombineAny_PropagatesNonClaimsError(t *testing.T) {
	// The load-bearing invariant: any mode catches only *ClaimsValidationError,
	// so a member's programming error is NOT recorded as a rejection reason
	// (which could flip the result to accept) — it propagates.
	combined := combine(t, []ClaimsValidator{
		ClaimsValidatorFunc(boom),
		requireClaims(t, "sub"),
	}, CombineAny)
	err := combined.ValidateClaims(claimsFrom(t, map[string]any{}))
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom propagated", err)
	}
}

func TestCombine_RejectsInvalidMode(t *testing.T) {
	if _, err := CombineClaimsValidators([]ClaimsValidator{requireClaims(t, "sub")}, CombineMode("All")); err == nil {
		t.Error("invalid mode should be a construction error")
	}
}

// --- runClaimsValidator (pipeline integration point) -----------------------

func TestRunClaimsValidator_PreservesStructuredReason(t *testing.T) {
	cfg := newConfig(WithClaimsValidator(requireClaims(t, "tid")))
	err := runClaimsValidator(context.Background(), cfg, claimsFrom(t, map[string]any{"sub": "u1"}))
	if cve := asClaimsErr(t, err); cve.Claim != "tid" {
		t.Errorf("claim = %q, want tid (unwrapped)", cve.Claim)
	}
}

func TestRunClaimsValidator_WrapsPlainErrorGenerically(t *testing.T) {
	cfg := newConfig(WithClaimsValidator(ClaimsValidatorFunc(boom)))
	err := runClaimsValidator(context.Background(), cfg, claimsFrom(t, map[string]any{"sub": "u1"}))
	// Wrapped, not a ClaimsValidationError, and carries the generic message.
	var cve *ClaimsValidationError
	if errors.As(err, &cve) {
		t.Error("a programming error must not surface as a ClaimsValidationError")
	}
	if !strings.Contains(err.Error(), "claims validation failed") {
		t.Errorf("err = %q, want generic 'claims validation failed'", err.Error())
	}
	if !errors.Is(err, errBoom) {
		t.Error("wrapped error should still unwrap to the original bug")
	}
}

func TestRunClaimsValidator_AcceptsValidClaims(t *testing.T) {
	cfg := newConfig(WithClaimsValidator(requireScopes(t, "read")))
	if err := runClaimsValidator(context.Background(), cfg, claimsFrom(t, map[string]any{"sub": "u1", "scope": "read"})); err != nil {
		t.Fatalf("valid claims: %v", err)
	}
}
