//go:build integration

package token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// tokenEndpoint discovers the live provider's token_endpoint or skips.
func tokenEndpoint(t *testing.T, ctx context.Context, tc integrationtest.Config) string {
	t.Helper()
	var dopts []discovery.Option
	if tc.AllowHTTP {
		dopts = append(dopts, discovery.WithInsecureAllowHTTP())
	}
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, dopts...)
	if err != nil {
		t.Skipf("provider not reachable at %s (local: run `cd infra && docker compose up -d`): %v", tc.Issuer, err)
	}
	if cfg.TokenEndpoint == "" {
		t.Fatalf("discovery returned no token_endpoint")
	}
	return cfg.TokenEndpoint
}

// CC-001/CC-002 (live): the client credentials grant obtains a real access
// token from the provider using client_secret_basic.
func TestIntegration_ClientCredentials_AgainstLiveProvider(t *testing.T) {
	tc := integrationtest.Load()
	if tc.ClientID == "" {
		t.Skip("TEST_CLIENT_ID not set for this provider profile")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx, tc)

	opts := []token.Option{token.WithScopes(tc.Scopes()...)}
	if tc.AllowHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	resp, err := token.ClientCredentials(ctx, endpoint, tc.ClientID, tc.ClientSecret, opts...)
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
	tc := integrationtest.Load()
	if tc.ClientID == "" {
		t.Skip("TEST_CLIENT_ID not set for this provider profile")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx, tc)

	opts := []token.Option{}
	if tc.AllowHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	_, err := token.ClientCredentials(ctx, endpoint, tc.ClientID, "wrong-secret", opts...)
	var te *token.TokenError
	var re *token.RequestError
	switch {
	case errors.As(err, &te):
		if te.Code == "" {
			t.Errorf("token error has empty code: %+v", te)
		}
	case errors.As(err, &re):
		// Some providers (e.g. Descope) reject bad credentials with a
		// proprietary, non-RFC 6749 error body; the client surfaces those as
		// a typed RequestError carrying the HTTP status.
		if re.StatusCode < 400 || re.StatusCode >= 500 {
			t.Errorf("StatusCode = %d, want 4xx: %+v", re.StatusCode, re)
		}
	default:
		t.Fatalf("error = %v, want *token.TokenError or *token.RequestError", err)
	}
}

// ACG-004/ACG-005/ACG-006 (live, partial): exchanging an invalid authorization
// code carrying a PKCE code_verifier reaches the live token endpoint and is
// rejected with a typed TokenError. This confirms the request shape (grant
// type, code, code_verifier) and live error parsing. A full interactive PKCE
// round-trip (browser login at /authorize) is out of scope for an automated
// test; the request plumbing it depends on is verified here.
func TestIntegration_AuthorizationCode_PKCE_Rejected(t *testing.T) {
	tc := integrationtest.Load()
	if tc.PublicClientID == "" {
		t.Skip("TEST_PKCE_PUBLIC_CLIENT_ID not set for this provider profile")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := tokenEndpoint(t, ctx, tc)

	verifier, err := token.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}

	opts := []token.Option{token.WithCodeVerifier(verifier)}
	if tc.AllowHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	_, err = token.AuthorizationCode(ctx, endpoint, tc.PublicClientID, "invalid-code",
		tc.RedirectURI, opts...)
	var te *token.TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *token.TokenError (invalid_grant)", err)
	}
}
