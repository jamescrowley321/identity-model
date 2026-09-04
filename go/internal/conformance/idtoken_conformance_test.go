package conformance

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
)

// TestIDTokenConformance drives every vector in id-token.json through the pure,
// network-free idtoken.ValidateClaims and asserts the accept/reject outcome and
// the canonical reason. It is the Go leg of the cross-language ID-Token profile
// parity: it MUST agree with the Python reference runner
// (py/src/tests/unit/test_id_token_conformance.py) on all vectors.
//
// This capability is marked cross_language_coverage_gate: "pending" in the spec,
// so it is deliberately NOT wired into the enforcement gate
// (tools/spec_coverage_gate.py, which runs only TestValidationConformance) and
// writes no coverage report. The in-test coverage assertion below still guards
// against silently skipping a case.
func TestIDTokenConformance(t *testing.T) {
	suite, err := LoadIDTokenCapability(filepath.Join(specConformanceDir, "id-token.json"))
	if err != nil {
		t.Fatalf("load id-token capability: %v", err)
	}
	if len(suite.Tests) == 0 {
		t.Fatal("id-token capability defines no tests")
	}

	executed := make(map[string]bool, len(suite.Tests))
	for _, tc := range suite.Tests {
		t.Run(tc.ID, func(t *testing.T) {
			if len(tc.Vectors) == 0 {
				t.Fatalf("%s: no vectors", tc.ID)
			}
			executed[tc.ID] = true
			for i, v := range tc.Vectors {
				runIDTokenVector(t, tc.ID, i, v)
			}
		})
	}

	// Coverage gate: every case must have been executed. The id-token capability
	// has no native-executed cases, so any unexecuted id is a silent skip.
	for _, tc := range suite.Tests {
		if !executed[tc.ID] {
			t.Errorf("case %s is defined but was not executed by the Go id-token runner", tc.ID)
		}
	}
}

func runIDTokenVector(t *testing.T, id string, idx int, v IDTokenVector) {
	t.Helper()
	label := id
	if v.Name != "" {
		label = id + " (" + v.Name + ")"
	}

	err := idtoken.ValidateClaims(v.Input.Claims, headerAlgOf(v.Input), idTokenOptionsFor(v.Input)...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s[%d]: expected accept, got error: %v", label, idx, err)
		}
	case OutcomeReject:
		if err == nil {
			t.Fatalf("%s[%d]: expected reject (%s), got nil", label, idx, v.Expect.Reason)
		}
		if !errors.Is(err, idtoken.ErrIDTokenProfile) {
			t.Fatalf("%s[%d]: error %v does not match ErrIDTokenProfile", label, idx, err)
		}
		var pe *idtoken.ProfileError
		if !errors.As(err, &pe) {
			t.Fatalf("%s[%d]: expected *idtoken.ProfileError, got %T (%v)", label, idx, err, err)
		}
		if pe.Reason != v.Expect.Reason {
			t.Fatalf("%s[%d]: reason = %q, want %q", label, idx, pe.Reason, v.Expect.Reason)
		}
		// The canonical error family is fixed for this capability.
		if v.Expect.Error != idtoken.CanonicalError {
			t.Fatalf("%s[%d]: vector carries unexpected canonical error family %q, want %q",
				label, idx, v.Expect.Error, idtoken.CanonicalError)
		}
	default:
		t.Fatalf("%s[%d]: unknown expected outcome %q", label, idx, v.Expect.Outcome)
	}
}

// idTokenOptionsFor maps the language-neutral vector input onto idtoken.Option
// values. The fixed POSIX-seconds clock is injected so the auth_time/max_age
// check is deterministic.
func idTokenOptionsFor(in IDTokenInput) []idtoken.Option {
	opts := []idtoken.Option{idtoken.WithNow(func() time.Time { return posixTime(in.Now) })}
	if in.ClientID != "" {
		opts = append(opts, idtoken.WithClientID(in.ClientID))
	}
	if in.Nonce != nil {
		opts = append(opts, idtoken.WithNonce(*in.Nonce))
	}
	if in.AccessToken != nil {
		opts = append(opts, idtoken.WithAccessToken(*in.AccessToken))
	}
	if in.Code != nil {
		opts = append(opts, idtoken.WithCode(*in.Code))
	}
	if in.MaxAge != nil {
		opts = append(opts, idtoken.WithMaxAge(time.Duration(*in.MaxAge)*time.Second))
	}
	if in.Leeway != nil {
		opts = append(opts, idtoken.WithClockSkew(secondsToDuration(*in.Leeway)))
	}
	return opts
}

// headerAlgOf resolves the vector's header_alg, treating a JSON null (nil
// pointer) as a missing alg (empty string), which fails closed on a hash check.
func headerAlgOf(in IDTokenInput) string {
	if in.HeaderAlg == nil {
		return ""
	}
	return *in.HeaderAlg
}

// posixTime converts POSIX seconds (possibly fractional) into a UTC time.
func posixTime(sec float64) time.Time {
	return time.Unix(0, int64(sec*float64(time.Second))).UTC()
}

// secondsToDuration converts a fractional-seconds leeway into a time.Duration.
func secondsToDuration(sec float64) time.Duration {
	return time.Duration(sec * float64(time.Second))
}
