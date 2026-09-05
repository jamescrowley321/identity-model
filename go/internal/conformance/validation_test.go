package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// Paths from go/internal/conformance to the shared spec tree at the repo root.
const (
	specVectorsDir = "../../../spec/vectors"
	fixtureRoot    = "../../../spec/test-fixtures"
)

// fallbackNow is used when a vector omits options.now. It matches the fixture
// tests' fixed clock (Unix 1_700_000_000 = 2023-11-14T22:13:20Z).
var fallbackNow = time.Unix(1_700_000_000, 0).UTC()

// TestValidationConformance drives every vector in validation.json against the
// Go jwt.Validate implementation, and asserts full coverage of the capability's
// test ids so Go cannot silently skip a case another language executes.
func TestValidationConformance(t *testing.T) {
	suite, err := LoadCapability(filepath.Join(specVectorsDir, "validation.json"))
	if err != nil {
		t.Fatalf("load capability: %v", err)
	}

	signingKey := mustSigningKey(t)
	keySet := mustFixtureKeySet(t)

	executed := make(map[string]bool, len(suite.Tests))
	for _, tc := range suite.Tests {
		t.Run(tc.ID, func(t *testing.T) {
			if tc.IsNative() {
				if tc.Reason == "" || tc.NativeTest == "" {
					t.Fatalf("%s: native execution requires reason + native_test", tc.ID)
				}
				t.Skipf("native-executed by %s: %s", tc.NativeTest, tc.Reason)
			}
			if len(tc.Vectors) == 0 {
				t.Fatalf("%s: no vectors and not marked native", tc.ID)
			}
			executed[tc.ID] = true
			for i, v := range tc.Vectors {
				runVector(t, tc.ID, i, v, signingKey, keySet)
			}
		})
	}

	// Coverage gate: every non-native case must have been executed.
	for _, tc := range suite.Tests {
		if !tc.IsNative() && !executed[tc.ID] {
			t.Errorf("case %s is defined but was not executed by the Go runner", tc.ID)
		}
	}

	writeCoverageReport(t, suite, executed)
}

// writeCoverageReport emits the executed/native case ids for the
// cross-language coverage gate (tools/spec_coverage_gate.py) when
// SPEC_COVERAGE_OUT is set. Same shape as the Python and Rust runners.
func writeCoverageReport(t *testing.T, suite *Capability, executed map[string]bool) {
	t.Helper()
	out := os.Getenv("SPEC_COVERAGE_OUT")
	if out == "" {
		return
	}
	native := map[string]string{}
	for _, tc := range suite.Tests {
		if tc.IsNative() {
			native[tc.ID] = tc.NativeTest
		}
	}
	ids := make([]string, 0, len(executed))
	for id := range executed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	report := map[string]any{
		"language":   "go",
		"capability": suite.Capability,
		"executed":   ids,
		"native":     native,
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal coverage report: %v", err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatalf("write coverage report %s: %v", out, err)
	}
}

func runVector(t *testing.T, id string, idx int, v Vector, signingKey *jose.JSONWebKey, keySet *jwks.JSONWebKeySet) {
	t.Helper()
	label := id
	if v.Name != "" {
		label = id + " (" + v.Name + ")"
	}

	now := parseNow(t, v.Options.Now)

	var token string
	if v.Token.Static != "" {
		token = strings.TrimSpace(string(mustReadFixture(t, v.Token.Static)))
	} else {
		tok, err := MintToken(v.Token, signingKey, now)
		if err != nil {
			t.Fatalf("%s[%d]: mint token: %v", label, idx, err)
		}
		token = tok
	}

	claims, err := jwt.Validate(context.Background(), token, keySet, optionsFor(t, v.Options, now)...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s[%d]: expected accept, got error: %v", label, idx, err)
		}
		assertClaims(t, label, idx, claims, v.Expect.Claims)
	case OutcomeReject:
		assertReject(t, label, idx, err, v.Expect)
	default:
		t.Fatalf("%s[%d]: unknown expected outcome %q", label, idx, v.Expect.Outcome)
	}
}

// assertReject checks the validation error matches the canonical code (and, for
// claim_validation, the offending claim).
func assertReject(t *testing.T, label string, idx int, err error, exp Expect) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s[%d]: expected reject (%s), got nil", label, idx, exp.Error)
	}
	sentinel := canonicalSentinel(exp.Error)
	if sentinel == nil {
		t.Fatalf("%s[%d]: unknown canonical error code %q", label, idx, exp.Error)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("%s[%d]: expected error %q, got %v", label, idx, exp.Error, err)
	}
	if exp.Error == ErrorClaimValidation && exp.Claim != "" {
		var cve *jwt.ClaimValidationError
		if !errors.As(err, &cve) {
			t.Fatalf("%s[%d]: expected *jwt.ClaimValidationError, got %T", label, idx, err)
		}
		if cve.Claim != exp.Claim {
			t.Fatalf("%s[%d]: expected offending claim %q, got %q", label, idx, exp.Claim, cve.Claim)
		}
	}
}

// assertClaims asserts every claim listed in the vector's accept expectation.
func assertClaims(t *testing.T, label string, idx int, claims *jwt.Claims, want map[string]any) {
	t.Helper()
	for name, wantVal := range want {
		s, ok := wantVal.(string)
		if !ok {
			t.Fatalf("%s[%d]: expected claim %q must be a string in the vector, got %T", label, idx, name, wantVal)
		}
		switch name {
		case "iss":
			if claims.Issuer != s {
				t.Errorf("%s[%d]: iss = %q, want %q", label, idx, claims.Issuer, s)
			}
		case "sub":
			if claims.Subject != s {
				t.Errorf("%s[%d]: sub = %q, want %q", label, idx, claims.Subject, s)
			}
		case "aud":
			if !claims.Audience.Contains(s) {
				t.Errorf("%s[%d]: aud %v does not contain %q", label, idx, claims.Audience, s)
			}
		case "nonce":
			if claims.Nonce != s {
				t.Errorf("%s[%d]: nonce = %q, want %q", label, idx, claims.Nonce, s)
			}
		default:
			t.Fatalf("%s[%d]: unsupported asserted claim %q", label, idx, name)
		}
	}
}

// canonicalSentinel maps a language-neutral error code to the Go sentinel error.
func canonicalSentinel(code string) error {
	switch code {
	case ErrorMalformed:
		return jwt.ErrMalformedToken
	case ErrorAlgNone:
		return jwt.ErrAlgNone
	case ErrorUnsupportedAlg:
		return jwt.ErrUnsupportedAlgorithm
	case ErrorSignature:
		return jwt.ErrSignature
	case ErrorKeyConversion:
		return jwt.ErrKeyConversion
	case ErrorClaimValidation:
		return jwt.ErrClaimValidation
	default:
		return nil
	}
}

// optionsFor maps the language-neutral options onto jwt.Option values.
func optionsFor(t *testing.T, o Options, now time.Time) []jwt.Option {
	t.Helper()
	opts := []jwt.Option{jwt.WithNow(func() time.Time { return now })}
	if o.ExpectedIssuer != "" {
		opts = append(opts, jwt.WithExpectedIssuer(o.ExpectedIssuer))
	}
	if o.ExpectedAudience != "" {
		opts = append(opts, jwt.WithExpectedAudience(o.ExpectedAudience))
	}
	if o.ExpectedNonce != "" {
		opts = append(opts, jwt.WithExpectedNonce(o.ExpectedNonce))
	}
	if o.ClockSkew != "" {
		d, err := time.ParseDuration(o.ClockSkew)
		if err != nil {
			t.Fatalf("parse clock_skew %q: %v", o.ClockSkew, err)
		}
		opts = append(opts, jwt.WithClockSkew(d))
	}
	if len(o.RequiredClaims) > 0 {
		opts = append(opts, jwt.WithRequiredClaims(o.RequiredClaims...))
	}
	if len(o.AllowedAlgorithms) > 0 {
		opts = append(opts, jwt.WithAllowedAlgorithms(o.AllowedAlgorithms...))
	}
	return opts
}

func parseNow(t *testing.T, s string) time.Time {
	t.Helper()
	if s == "" {
		return fallbackNow
	}
	now, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse options.now %q: %v", s, err)
	}
	return now.UTC()
}

func mustSigningKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	key, err := SigningKeyFromBytes(mustReadFixture(t, "validation/signing-key.jwk.json"))
	if err != nil {
		t.Fatalf("load signing key: %v", err)
	}
	return key
}

// mustFixtureKeySet serves the public JWKS fixture over httptest and fetches it
// through the real jwks client, matching how the package tests build key sets.
func mustFixtureKeySet(t *testing.T) *jwks.JSONWebKeySet {
	t.Helper()
	body := mustReadFixture(t, "validation/jwks.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	set, err := jwks.FetchKeySet(context.Background(), srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch key set: %v", err)
	}
	return set
}

func mustReadFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}
