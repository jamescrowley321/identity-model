//go:build integration

package introspection_test

import (
	"context"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/introspection"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// Local node-oidc-provider opaque-token client. Introspection is only
// meaningful for opaque (reference) tokens, so these tests use the dedicated
// test-opaque client (infra/node-oidc-provider/provider.js) rather than the
// default JWT-issuing client_credentials client. These credentials only exist
// on the local fixture provider; against any cloud profile the test skips.
const (
	opaqueClientID     = "test-opaque"
	opaqueClientSecret = "test-opaque-secret"
)

// introspectionEndpoint discovers the local provider's introspection_endpoint
// or skips. It also skips against non-local (cloud) profiles, which do not
// provision the opaque-token client these tests require.
func introspectionEndpoint(t *testing.T, ctx context.Context, tc integrationtest.Config) string {
	t.Helper()
	if !tc.AllowHTTP {
		t.Skip("introspection integration tests require the local opaque-token client; skipping cloud profile")
	}
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("provider not reachable at %s (local: run `cd infra && docker compose up -d`): %v", tc.Issuer, err)
	}
	if cfg.IntrospectionEndpoint == "" {
		t.Skip("discovery returned no introspection_endpoint")
	}
	return cfg.IntrospectionEndpoint
}

// endpoints discovers both the token and introspection endpoints.
func endpoints(t *testing.T, ctx context.Context, tc integrationtest.Config) (tokenEP, introspectEP string) {
	t.Helper()
	introspectEP = introspectionEndpoint(t, ctx, tc)
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("provider not reachable: %v", err)
	}
	if cfg.TokenEndpoint == "" {
		t.Fatal("discovery returned no token_endpoint")
	}
	return cfg.TokenEndpoint, introspectEP
}

// INTR-001/INTR-006 (live): mint a real opaque access token from the local
// provider and introspect it — the response reports active=true and echoes the
// issuing client_id.
func TestIntegration_Introspect_ActiveOpaqueToken(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenEP, introspectEP := endpoints(t, ctx, tc)

	resp, err := token.ClientCredentials(ctx, tokenEP, opaqueClientID, opaqueClientSecret,
		token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("mint opaque token: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access_token")
	}

	ir, err := introspection.Introspect(ctx, introspectEP, opaqueClientID, opaqueClientSecret,
		resp.AccessToken, introspection.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect active token: %v", err)
	}
	if !ir.Active {
		t.Fatalf("Active = false for a freshly issued token: %+v", ir)
	}
	if ir.ClientID != "" && ir.ClientID != opaqueClientID {
		t.Errorf("client_id = %q, want %q", ir.ClientID, opaqueClientID)
	}
}

// INTR-002 (live): introspecting an unknown/garbage token returns active=false.
func TestIntegration_Introspect_InactiveToken(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	introspectEP := introspectionEndpoint(t, ctx, tc)

	ir, err := introspection.Introspect(ctx, introspectEP, opaqueClientID, opaqueClientSecret,
		"definitely-not-a-real-token", introspection.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect garbage token: %v", err)
	}
	if ir.Active {
		t.Error("Active = true for a garbage token, want false")
	}
}

// INTR-005 (live): introspecting with wrong client credentials fails client
// authentication.
func TestIntegration_Introspect_BadClientAuth(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	introspectEP := introspectionEndpoint(t, ctx, tc)

	_, err := introspection.Introspect(ctx, introspectEP, opaqueClientID, "wrong-secret",
		"any-token", introspection.WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected client-authentication failure, got nil")
	}
}
