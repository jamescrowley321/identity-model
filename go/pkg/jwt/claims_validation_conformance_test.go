package jwt

// Cross-language conformance for the injectable claims-validator API (issue
// #603). This is a bespoke, per-language runner: it reads the shared vector set
// in spec/test-fixtures/claims-validation/vectors.json directly (NOT via the
// generic spec/conformance/*.json capability machinery, which has a different
// schema), builds each validator from the `validator` spec, runs it against
// `claims`, and asserts the accept / reject / construction_error outcome. When a
// rejection names a specific claim, that claim is asserted too; rejection reason
// wording is language-specific and intentionally NOT asserted.
//
// The test lives in package jwt (white box) so it can build a *Claims from the
// vector's raw claims object through parseClaims, exercising the exact accessor
// path (GetClaim/all) the validators use in production.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// claimsVectorsPath resolves the shared vector file relative to THIS test
// source file, so the vectors are found regardless of the working directory the
// test is invoked from. The file sits at go/pkg/jwt/, three directories below
// the repo root that holds spec/.
func claimsVectorsPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the test source file")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(repoRoot, "spec", "test-fixtures", "claims-validation", "vectors.json")
}

// clvSuite is the top-level shape of vectors.json.
type clvSuite struct {
	Description string    `json:"description"`
	Cases       []clvCase `json:"cases"`
}

// clvCase is one conformance case. Exactly one field of Expect is set.
type clvCase struct {
	ID        string           `json:"id"`
	Desc      string           `json:"desc"`
	Validator clvValidatorSpec `json:"validator"`
	Claims    json.RawMessage  `json:"claims,omitempty"`
	Expect    clvExpect        `json:"expect"`
}

// clvValidatorSpec is the declarative description of a validator to build. It is
// a union over the four validator types; only the fields for `Type` are read.
type clvValidatorSpec struct {
	Type    string             `json:"type"`
	Names   []string           `json:"names,omitempty"`
	Name    string             `json:"name,omitempty"`
	Value   json.RawMessage    `json:"value,omitempty"`
	Scopes  []string           `json:"scopes,omitempty"`
	Require string             `json:"require,omitempty"`
	Of      []clvValidatorSpec `json:"of,omitempty"`
}

// clvExpect is the asserted outcome. Exactly one is set per case.
type clvExpect struct {
	Accept            bool       `json:"accept,omitempty"`
	Reject            *clvReject `json:"reject,omitempty"`
	ConstructionError bool       `json:"construction_error,omitempty"`
}

// clvReject optionally names the claim a rejection must surface. An empty Claim
// (the {} form) asserts only that the validator rejected.
type clvReject struct {
	Claim string `json:"claim,omitempty"`
}

// buildClaimsValidator constructs the validator described by spec, mirroring how
// an application would wire the same policy. A construction error (empty
// require_claims/require_scopes, empty any-of combine, unknown combine mode, or a
// member that itself fails to build) is returned rather than panicking, so the
// runner can assert the construction_error expectation.
func buildClaimsValidator(spec clvValidatorSpec) (ClaimsValidator, error) {
	switch spec.Type {
	case "require_claims":
		return RequireClaims(spec.Names...)
	case "require_claim_value":
		var value any
		if len(spec.Value) > 0 {
			if err := json.Unmarshal(spec.Value, &value); err != nil {
				return nil, fmt.Errorf("decode require_claim_value.value: %w", err)
			}
		}
		return RequireClaimValue(spec.Name, value), nil
	case "require_scopes":
		return RequireScopes(spec.Scopes...)
	case "combine":
		members := make([]ClaimsValidator, 0, len(spec.Of))
		for i, m := range spec.Of {
			v, err := buildClaimsValidator(m)
			if err != nil {
				return nil, fmt.Errorf("combine member %d: %w", i, err)
			}
			members = append(members, v)
		}
		return CombineClaimsValidators(members, CombineMode(spec.Require))
	default:
		return nil, fmt.Errorf("unknown validator type %q", spec.Type)
	}
}

// mustParseVectorClaims builds a *Claims from the vector's raw claims object via
// the production parse path, so GetClaim/all are populated exactly as at runtime.
func mustParseVectorClaims(t *testing.T, id string, raw json.RawMessage) *Claims {
	t.Helper()
	if len(raw) == 0 {
		t.Fatalf("%s: vector has no claims to run the validator against", id)
	}
	claims, err := parseClaims(raw)
	if err != nil {
		t.Fatalf("%s: parse vector claims: %v", id, err)
	}
	return claims
}

// TestClaimsValidationConformance runs every vector in the shared claims-
// validation set against the Go validators.
func TestClaimsValidationConformance(t *testing.T) {
	raw, err := os.ReadFile(claimsVectorsPath(t))
	if err != nil {
		t.Fatalf("read claims-validation vectors: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a typo in a vector fails loudly, never silently skips
	var suite clvSuite
	if err := dec.Decode(&suite); err != nil {
		t.Fatalf("decode claims-validation vectors: %v", err)
	}
	if len(suite.Cases) == 0 {
		t.Fatal("claims-validation vectors contain no cases")
	}

	for _, tc := range suite.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			validator, buildErr := buildClaimsValidator(tc.Validator)

			if tc.Expect.ConstructionError {
				if buildErr == nil {
					t.Fatalf("%s: expected a construction error, but the validator built successfully", tc.ID)
				}
				return // must NOT run a validator that should have failed to build
			}
			if buildErr != nil {
				t.Fatalf("%s: validator construction failed unexpectedly: %v", tc.ID, buildErr)
			}

			claims := mustParseVectorClaims(t, tc.ID, tc.Claims)
			runErr := validator.ValidateClaims(claims)

			switch {
			case tc.Expect.Accept:
				if runErr != nil {
					t.Fatalf("%s: expected accept, got rejection: %v", tc.ID, runErr)
				}
			case tc.Expect.Reject != nil:
				if runErr == nil {
					t.Fatalf("%s: expected rejection, got accept", tc.ID)
				}
				var cve *ClaimsValidationError
				if !errors.As(runErr, &cve) {
					t.Fatalf("%s: expected *ClaimsValidationError, got %T: %v", tc.ID, runErr, runErr)
				}
				if want := tc.Expect.Reject.Claim; want != "" && cve.Claim != want {
					t.Fatalf("%s: rejection named claim %q, want %q", tc.ID, cve.Claim, want)
				}
			default:
				t.Fatalf("%s: vector sets no expectation (accept/reject/construction_error)", tc.ID)
			}
		})
	}
}
