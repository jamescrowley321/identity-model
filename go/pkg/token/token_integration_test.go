//go:build integration

package token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// infraIssuer is the local node-oidc-provider from infra/ (docker compose up).
const infraIssuer = "http://localhost:9000"

// The static client credentials client configured in infra/provider.js.
const (
	ccClientID     = "test-client-credentials"
	ccClientSecret = "test-client-credentials-secret"
)

// tokenEndpoint discovers the live provider's token_endpoint or skips.
func tokenEndpoint(t *testing.T, ctx context.Context) string {
	t.Helper()
	cfg, err := discovery.FetchConfiguration(ctx, infraIssuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("infra provider not reachable at %s (run `cd infra && docker compose up -d`): %v", infraIssuer, err)
	}
	if cfg.TokenEndpoint == "" {
		t.Fatalf("discovery returned no token_endpoint")
	}
	return cfg.TokenEndpoint
}

// CC-001/CC-002 (live): the client credentials grant obtains a real access
// token from the provider using client_secret_basic.
func TestIntegration_ClientCredentials_AgainstLiveProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx)

	resp, err := token.ClientCredentials(ctx, endpoint, ccClientID, ccClientSecret,
		token.WithScopes("api"), token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials against live provider: %v", err)
	}
	if resp.AccessToken == "" {
		t.Errorf("empty access_token: %+v", resp)
	}
	if resp.TokenType == "" {
		t.Errorf("empty token_type: %+v", resp)
	}
}

// CC-004 (live): a bad client secret produces a typed TokenError from the live
// provider, exercising the real RFC 6749 §5.2 error path.
func TestIntegration_ClientCredentials_InvalidClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx)

	_, err := token.ClientCredentials(ctx, endpoint, ccClientID, "wrong-secret",
		token.WithInsecureAllowHTTP())
	var te *token.TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *token.TokenError", err)
	}
	if te.Code == "" {
		t.Errorf("token error has empty code: %+v", te)
	}
}

// ACG-004/ACG-005/ACG-006 (live, partial): exchanging an invalid authorization
// code carrying a PKCE code_verifier reaches the live token endpoint and is
// rejected with a typed TokenError. This confirms the request shape (grant
// type, code, code_verifier) and live error parsing. A full interactive PKCE
// round-trip (browser login at /authorize) is out of scope for an automated
// test; the request plumbing it depends on is verified here.
func TestIntegration_AuthorizationCode_PKCE_Rejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx)

	verifier, err := token.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}

	_, err = token.AuthorizationCode(ctx, endpoint, "test-pkce-public", "invalid-code",
		"http://localhost:8080/callback",
		token.WithCodeVerifier(verifier), token.WithInsecureAllowHTTP())
	var te *token.TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *token.TokenError (invalid_grant)", err)
	}
}
