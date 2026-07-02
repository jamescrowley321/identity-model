//go:build integration

package userinfo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// discover fetches the live provider's configuration or skips.
func discover(t *testing.T, ctx context.Context, tc integrationtest.Config) *discovery.ProviderConfiguration {
	t.Helper()
	var dopts []discovery.Option
	if tc.AllowHTTP {
		dopts = append(dopts, discovery.WithInsecureAllowHTTP())
	}
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, dopts...)
	if err != nil {
		t.Skipf("provider not reachable at %s (local: run `cd infra && docker compose up -d`): %v", tc.Issuer, err)
	}
	return cfg
}

// UI-004 (live): a bogus access token is rejected by the live provider with a
// 401 UserInfoError carrying a WWW-Authenticate challenge. This error path is
// always runnable without an interactive end-user login.
func TestIntegration_UserInfo_BogusToken(t *testing.T) {
	tc := integrationtest.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dcfg := discover(t, ctx, tc)
	if dcfg.UserInfoEndpoint == "" {
		t.Skip("provider does not advertise a userinfo_endpoint")
	}

	opts := []userinfo.Option{}
	if tc.AllowHTTP {
		opts = append(opts, userinfo.WithInsecureAllowHTTP())
	}
	_, err := userinfo.Fetch(ctx, dcfg.UserInfoEndpoint, "this-is-not-a-valid-token", opts...)
	var ue *userinfo.UserInfoError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %T (%v), want *userinfo.UserInfoError", err, err)
	}
	if ue.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", ue.StatusCode)
	}
	if ue.WWWAuthenticate == "" {
		// RFC 6750 §3 requires WWW-Authenticate on a 401, but some providers
		// (e.g. Descope) omit it; tolerate the omission while still requiring
		// the 401 and the typed error above.
		t.Logf("provider omitted the WWW-Authenticate challenge on 401 (RFC 6750 §3)")
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
	tc := integrationtest.Load()
	if tc.ClientID == "" {
		t.Skip("TEST_CLIENT_ID not set for this provider profile")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dcfg := discover(t, ctx, tc)
	if dcfg.UserInfoEndpoint == "" || dcfg.TokenEndpoint == "" {
		t.Skipf("provider missing endpoints: userinfo=%q token=%q", dcfg.UserInfoEndpoint, dcfg.TokenEndpoint)
	}

	topts := []token.Option{token.WithScopes("openid")}
	if tc.AllowHTTP {
		topts = append(topts, token.WithInsecureAllowHTTP())
	}
	tok, err := token.ClientCredentials(ctx, dcfg.TokenEndpoint, tc.ClientID, tc.ClientSecret, topts...)
	if err != nil {
		// The provider may decline openid scope for the CC grant; that is an
		// acceptable outcome for this best-effort probe.
		t.Skipf("client_credentials with openid scope unavailable: %v", err)
	}

	uopts := []userinfo.Option{}
	if tc.AllowHTTP {
		uopts = append(uopts, userinfo.WithInsecureAllowHTTP())
	}
	_, err = userinfo.Fetch(ctx, dcfg.UserInfoEndpoint, tok.AccessToken, uopts...)
	if err == nil {
		t.Skip("provider returned claims for a client_credentials token; no assertion to make")
	}
	// Any typed error (UserInfoError for a rejected token, RequestError for a
	// missing sub) is a valid outcome — a CC token is not an end-user token.
	if !errors.Is(err, userinfo.ErrUserInfoResponse) && !errors.Is(err, userinfo.ErrRequest) {
		t.Errorf("unexpected error type: %T (%v)", err, err)
	}
}
