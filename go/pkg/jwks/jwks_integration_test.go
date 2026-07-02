//go:build integration

package jwks_test

import (
	"context"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// TestIntegration_FetchKeySet exercises a real JWKS fetch against the provider
// selected by the TEST_* environment (RFC 7517 §5). The default profile is
// the infra/ node-oidc-provider:
//
//	cd infra && docker compose up -d
//	cd go && go test -tags=integration ./pkg/jwks/...
//
// The jwks_uri is resolved from discovery against the profile's issuer, or
// overridden directly with TEST_JWKS_ADDRESS.
func TestIntegration_FetchKeySet(t *testing.T) {
	tc := integrationtest.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwksURI := tc.JWKSURI
	if jwksURI == "" {
		var dopts []discovery.Option
		if tc.AllowHTTP {
			dopts = append(dopts, discovery.WithInsecureAllowHTTP())
		}
		cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, dopts...)
		if err != nil {
			t.Fatalf("discovery FetchConfiguration(%s): %v", tc.Issuer, err)
		}
		jwksURI = cfg.JWKSURI
	}

	opts := []jwks.Option{jwks.WithTimeout(5 * time.Second)}
	if tc.AllowHTTP {
		opts = append(opts, jwks.WithInsecureAllowHTTP())
	}

	set, err := jwks.FetchKeySet(ctx, jwksURI, opts...)
	if err != nil {
		t.Fatalf("FetchKeySet(%s): %v", jwksURI, err)
	}
	if len(set.Keys) == 0 {
		t.Fatal("provider returned no keys")
	}

	// Resolve the first key by its kid (JWKS-003).
	first := set.Keys[0]
	if first.Kid != "" {
		if _, ok := set.ResolveKey(first.Kid); !ok {
			t.Errorf("ResolveKey(%q) returned not found for a present key", first.Kid)
		}
	}

	// ForceRefresh must re-fetch without error (JWKS-006) and keep the keys.
	if err := set.ForceRefresh(ctx); err != nil {
		t.Errorf("ForceRefresh: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Error("key set empty after ForceRefresh")
	}
}
