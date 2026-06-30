//go:build integration

package discovery_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

// TestIntegration_FetchConfiguration exercises a real discovery fetch against
// the infra/ node-oidc-provider (OIDC Discovery 1.0). Bring it up first:
//
//	cd infra && docker compose up -d
//	cd go && go test -tags=integration ./pkg/discovery/...
//
// The issuer defaults to the infra provider but can be overridden with
// DISCOVERY_ISSUER. node-oidc-provider serves plain HTTP locally, so
// WithInsecureAllowHTTP is required.
func TestIntegration_FetchConfiguration(t *testing.T) {
	issuer := os.Getenv("DISCOVERY_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:9000"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := discovery.FetchConfiguration(ctx, issuer,
		discovery.WithInsecureAllowHTTP(),
		discovery.WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("FetchConfiguration(%s): %v", issuer, err)
	}

	if cfg.Issuer != issuer {
		t.Errorf("issuer = %q, want %q", cfg.Issuer, issuer)
	}
	for name, val := range map[string]string{
		"authorization_endpoint": cfg.AuthorizationEndpoint,
		"token_endpoint":         cfg.TokenEndpoint,
		"jwks_uri":               cfg.JWKSURI,
	} {
		if val == "" {
			t.Errorf("required endpoint %q is empty", name)
		}
	}
	if len(cfg.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("id_token_signing_alg_values_supported is empty")
	}

	// A second call within the TTL must be served from cache.
	if _, err := discovery.FetchConfiguration(ctx, issuer, discovery.WithInsecureAllowHTTP()); err != nil {
		t.Errorf("cached re-fetch: %v", err)
	}
}
