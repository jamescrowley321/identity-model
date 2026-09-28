//go:build integration

package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/revocation"
)

// runRevocationVector is the revocation.json adapter: revocation.Revoke.
func runRevocationVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()
	ctx := context.Background()

	endpoint := base + inputOr(v, "endpoint_path", "/revoke")
	if discover, _ := v.Input["discover"].(bool); discover {
		discovery.ClearCache()
		cfg, err := discovery.FetchConfiguration(ctx, base, discovery.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("%s: discovery: %v", label, err)
		}
		endpoint = cfg.RevocationEndpoint
	}

	opts := []revocation.Option{revocation.WithInsecureAllowHTTP()}
	if hint := inputString(v, "token_type_hint"); hint != "" {
		opts = append(opts, revocation.WithTokenTypeHint(hint))
	}
	err := revocation.Revoke(ctx, endpoint, inputOr(v, "client_id", "cid"), inputOr(v, "client_secret", "secret"), inputString(v, "token"), opts...)

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
}
