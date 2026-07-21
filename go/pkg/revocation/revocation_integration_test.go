//go:build integration

package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/introspection"
	"github.com/jamescrowley321/identity-model/go/pkg/revocation"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// Revocation is exercised against opaque (reference) access tokens so the
// provider actually removes state on revoke. Only the node-oidc-provider fixture
// provisions an opaque-token client_credentials client
// (infra/node-oidc-provider/provider.js, surfaced via TEST_OPAQUE_CLIENT_ID);
// every other profile — IdentityServer, Ory, Descope — leaves it unset, so those
// runs skip.

// endpoints discovers the token, revocation, and introspection endpoints or
// skips. It also skips against any profile that does not provision an
// opaque-token client. introspectEP is "" when the provider advertises none.
func endpoints(t *testing.T, ctx context.Context, tc integrationtest.Config) (tokenEP, revokeEP, introspectEP string) {
	t.Helper()
	if tc.OpaqueClientID == "" {
		t.Skip("no opaque-token client for this profile (TEST_OPAQUE_CLIENT_ID unset); revocation integration requires opaque tokens")
	}
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("provider not reachable at %s (local: run `cd infra && docker compose up -d`): %v", tc.Issuer, err)
	}
	if cfg.RevocationEndpoint == "" {
		t.Skip("discovery returned no revocation_endpoint")
	}
	if cfg.TokenEndpoint == "" {
		t.Fatal("discovery returned no token_endpoint")
	}
	return cfg.TokenEndpoint, cfg.RevocationEndpoint, cfg.IntrospectionEndpoint
}

// REV-001/REV-005 (live): mint a real opaque access token from the local
// provider and revoke it — the endpoint answers 200 and Revoke returns nil.
// Then confirm, via introspection, that the token is genuinely no longer
// accepted (Epic 5 story 5.2 AC-5: "confirming the revoked token is no longer
// accepted"), not merely that the endpoint returned 200.
func TestIntegration_Revoke_OpaqueToken(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenEP, revokeEP, introspectEP := endpoints(t, ctx, tc)

	resp, err := token.ClientCredentials(ctx, tokenEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("mint opaque token: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access_token")
	}

	// Sanity: before revocation the opaque token introspects as active, so the
	// post-revocation check below is meaningful (skip the whole assertion if the
	// provider advertises no introspection endpoint).
	if introspectEP != "" {
		before, err := introspection.Introspect(ctx, introspectEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
			resp.AccessToken, introspection.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("introspect before revoke: %v", err)
		}
		if !before.Active {
			t.Fatal("freshly minted opaque token introspected as inactive; cannot verify revocation")
		}
	}

	if err := revocation.Revoke(ctx, revokeEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		resp.AccessToken, revocation.WithTokenTypeHint("access_token"), revocation.WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke opaque token: %v", err)
	}

	// AC-5: the revoked token must no longer be accepted. Introspection is the
	// authoritative check for an opaque token — it now reports active=false.
	if introspectEP != "" {
		after, err := introspection.Introspect(ctx, introspectEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
			resp.AccessToken, introspection.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("introspect after revoke: %v", err)
		}
		if after.Active {
			t.Error("revoked token still introspects as active; revocation did not take effect")
		}
	}
}

// REV-001 (live): the server returns 200 regardless of token validity (§2.1
// anti-scanning). Revoking the same token twice — and revoking an unknown
// token — both succeed.
func TestIntegration_Revoke_IdempotentAndUnknown(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenEP, revokeEP, _ := endpoints(t, ctx, tc)

	resp, err := token.ClientCredentials(ctx, tokenEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("mint opaque token: %v", err)
	}

	// First revoke succeeds.
	if err := revocation.Revoke(ctx, revokeEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		resp.AccessToken, revocation.WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	// Second revoke of the now already-revoked token also returns 200/nil.
	if err := revocation.Revoke(ctx, revokeEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		resp.AccessToken, revocation.WithInsecureAllowHTTP()); err != nil {
		t.Errorf("second Revoke (already revoked): %v, want nil", err)
	}
	// An entirely unknown token also returns 200/nil.
	if err := revocation.Revoke(ctx, revokeEP, tc.OpaqueClientID, tc.OpaqueClientSecret,
		"definitely-not-a-real-token", revocation.WithInsecureAllowHTTP()); err != nil {
		t.Errorf("Revoke unknown token: %v, want nil", err)
	}
}

// REV-004 (live): revoking with wrong client credentials fails client
// authentication with an HTTP 401 RevocationError.
func TestIntegration_Revoke_BadClientAuth(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, revokeEP, _ := endpoints(t, ctx, tc)

	err := revocation.Revoke(ctx, revokeEP, tc.OpaqueClientID, "wrong-secret",
		"any-token", revocation.WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected client-authentication failure, got nil")
	}
}
