package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/revocation"
)

// TestRevocationConformance drives every vector in revocation.json against
// revocation.Revoke.
func TestRevocationConformance(t *testing.T) {
	suite := LoadHTTPCapability(t, "revocation.json")

	for _, tc := range suite.Tests {
		t.Run(tc.ID, func(t *testing.T) {
			if len(tc.Vectors) == 0 {
				t.Fatalf("%s: no vectors", tc.ID)
			}
			for i, v := range tc.Vectors {
				runRevocationVector(t, vectorLabel(tc.ID, i, v), v)
			}
		})
	}
}

func runRevocationVector(t *testing.T, label string, v HTTPVector) {
	t.Helper()
	srv := newMockServer(t, v)
	ctx := context.Background()

	endpoint := srv.URL + "/revoke"
	if discover, _ := v.Input["discover"].(bool); discover {
		discovery.ClearCache()
		cfg, err := discovery.FetchConfiguration(ctx, srv.URL, discovery.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("%s: discovery: %v", label, err)
		}
		endpoint = cfg.RevocationEndpoint
	}

	opts := []revocation.Option{revocation.WithInsecureAllowHTTP()}
	if hint := inputString(v, "token_type_hint"); hint != "" {
		opts = append(opts, revocation.WithTokenTypeHint(hint))
	}
	err := revocation.Revoke(ctx, endpoint, "cid", "secret", inputString(v, "token"), opts...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
	case OutcomeReject:
		var re *revocation.RevocationError
		if !errors.As(err, &re) {
			t.Fatalf("%s: expected RevocationError %q, got %v", label, v.Expect.Error, err)
		}
		if re.Code != v.Expect.Error {
			t.Errorf("%s: error = %q, want %q", label, re.Code, v.Expect.Error)
		}
		if re.StatusCode != v.Expect.Status {
			t.Errorf("%s: status = %d, want %d", label, re.StatusCode, v.Expect.Status)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
	srv.assertRequest(t, label, v.ExpectRequest)
}
