//go:build integration

package jwks_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// TestIntegration_FetchKeySet exercises a real JWKS fetch against the infra/
// node-oidc-provider (RFC 7517 §5). Bring it up first:
//
//	cd infra && docker compose up -d
//	cd go && go test -tags=integration ./pkg/jwks/...
//
// The jwks_uri is resolved from discovery against DISCOVERY_ISSUER (default the
// infra provider), or overridden directly with JWKS_URI. node-oidc-provider
// serves plain HTTP locally, so WithInsecureAllowHTTP is required.
func TestIntegration_FetchKeySet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		issuer := os.Getenv("DISCOVERY_ISSUER")
		if issuer == "" {
			issuer = "http://localhost:9000"
		}
		cfg, err := discovery.FetchConfiguration(ctx, issuer, discovery.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("discovery FetchConfiguration(%s): %v", issuer, err)
		}
		jwksURI = cfg.JWKSURI
	}

	set, err := jwks.FetchKeySet(ctx, jwksURI,
		jwks.WithInsecureAllowHTTP(),
		jwks.WithTimeout(5*time.Second),
	)
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
