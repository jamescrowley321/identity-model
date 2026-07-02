//go:build integration

package discovery_test

import (
	"context"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

// TestIntegration_FetchConfiguration exercises a real discovery fetch against
// the provider selected by the TEST_* environment (OIDC Discovery 1.0). The
// default profile is the infra/ node-oidc-provider:
//
//	cd infra && docker compose up -d
//	cd go && go test -tags=integration ./pkg/discovery/...
//
// Point TEST_DISCO_ADDRESS at another provider (IdentityServer, Ory, Descope)
// to run the same test there; the Makefile targets load per-provider .env.*
// profiles. Local fixtures serve plain HTTP, which enables
// WithInsecureAllowHTTP via the profile's AllowHTTP.
func TestIntegration_FetchConfiguration(t *testing.T) {
	tc := integrationtest.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := []discovery.Option{discovery.WithTimeout(5 * time.Second)}
	if tc.AllowHTTP {
		opts = append(opts, discovery.WithInsecureAllowHTTP())
	}

	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, opts...)
	if err != nil {
		t.Fatalf("FetchConfiguration(%s): %v", tc.Issuer, err)
	}

	if cfg.Issuer != tc.Issuer {
		t.Errorf("issuer = %q, want %q", cfg.Issuer, tc.Issuer)
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
	if _, err := discovery.FetchConfiguration(ctx, tc.Issuer, opts...); err != nil {
		t.Errorf("cached re-fetch: %v", err)
	}
}
