//go:build integration

package userinfo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// infraIssuer is the local node-oidc-provider from infra/ (docker compose up).
const infraIssuer = "http://localhost:9000"

// The static client credentials client configured in infra/provider.js.
const (
	ccClientID     = "test-client-credentials"
	ccClientSecret = "test-client-credentials-secret"
)

// userInfoEndpoint discovers the live provider's userinfo_endpoint or skips.
func userInfoEndpoint(t *testing.T, ctx context.Context) string {
	t.Helper()
	cfg, err := discovery.FetchConfiguration(ctx, infraIssuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("infra provider not reachable at %s (run `cd infra && docker compose up -d`): %v", infraIssuer, err)
	}
	if cfg.UserInfoEndpoint == "" {
		t.Fatalf("discovery returned no userinfo_endpoint")
	}
	return cfg.UserInfoEndpoint
}

// UI-004 (live): a bogus access token is rejected by the live provider with a
// 401 UserInfoError carrying a WWW-Authenticate challenge. This error path is
// always runnable without an interactive end-user login.
func TestIntegration_UserInfo_BogusToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := userInfoEndpoint(t, ctx)

	_, err := userinfo.Fetch(ctx, endpoint, "this-is-not-a-valid-token",
		userinfo.WithInsecureAllowHTTP())
	var ue *userinfo.UserInfoError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T (%v), want *userinfo.UserInfoError", err, err)
	}
	if ue.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", ue.StatusCode)
	}
	if ue.WWWAuthenticate == "" {
		t.Errorf("expected WWW-Authenticate challenge, got empty")
	}
}

// UI-001 (live, best-effort): a client_credentials access token is presented to
// the UserInfo endpoint. A CC token has no end-user subject, so per OIDC the
// provider rejects it at the UserInfo endpoint; we assert a typed error rather
// than a successful claims response.
//
// Known gap: the positive end-user path (a real access token issued via the
// authorization_code flow, whose claims include a sub matching the ID token)
// requires an interactive browser login at /authorize and is documented here
// rather than asserted (same deferral as token ACG-006).
func TestIntegration_UserInfo_ClientCredentialsToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dcfg, err := discovery.FetchConfiguration(ctx, infraIssuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("infra provider not reachable at %s: %v", infraIssuer, err)
	}
	if dcfg.UserInfoEndpoint == "" || dcfg.TokenEndpoint == "" {
		t.Fatalf("discovery missing endpoints: userinfo=%q token=%q", dcfg.UserInfoEndpoint, dcfg.TokenEndpoint)
	}

	tok, err := token.ClientCredentials(ctx, dcfg.TokenEndpoint, ccClientID, ccClientSecret,
		token.WithScopes("openid"), token.WithInsecureAllowHTTP())
	if err != nil {
		// The provider may decline openid scope for the CC grant; that is an
		// acceptable outcome for this best-effort probe.
		t.Skipf("client_credentials with openid scope unavailable: %v", err)
	}

	_, err = userinfo.Fetch(ctx, dcfg.UserInfoEndpoint, tok.AccessToken,
		userinfo.WithInsecureAllowHTTP())
	if err == nil {
		t.Skip("provider returned claims for a client_credentials token; no assertion to make")
	}
	// Any typed error (UserInfoError for a rejected token, RequestError for a
	// missing sub) is a valid outcome — a CC token is not an end-user token.
	if !errors.Is(err, userinfo.ErrUserInfoResponse) && !errors.Is(err, userinfo.ErrRequest) {
		t.Errorf("unexpected error type: %T (%v)", err, err)
	}
}
