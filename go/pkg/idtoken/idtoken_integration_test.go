//go:build integration

package idtoken_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// A fixed nonce/max_age sent on the authorization request so node-oidc echoes a
// nonce and an auth_time into the minted ID Token, letting the live suite
// exercise the §3.1.3.7 nonce (step 11) and max_age/auth_time (step 12) bindings
// on a real token — mirroring the Python integration suite.
const (
	liveNonce  = "live-go-id-token-nonce-9f83c1"
	liveMaxAge = 3600
)

// liveIDToken runs a full headless authorization-code + PKCE flow (requesting a
// nonce and max_age), exchanges the code, and returns the real ID Token, the
// access token, the client_id and the discovered issuer/keyset — or skips when
// the selected profile cannot run the automated flow. It mirrors the Python
// suite's id_token_flow fixture.
type liveIDTokenResult struct {
	idToken     string
	accessToken string
	clientID    string
	issuer      string
	keySet      *jwks.JSONWebKeySet
	allowHTTP   bool
}

func obtainLiveIDToken(t *testing.T, ctx context.Context) liveIDTokenResult {
	t.Helper()
	tc := integrationtest.Load()
	if tc.PublicClientID == "" {
		t.Skip("TEST_PKCE_PUBLIC_CLIENT_ID not set for this provider profile")
	}

	var dopts []discovery.Option
	if tc.AllowHTTP {
		dopts = append(dopts, discovery.WithInsecureAllowHTTP())
	}
	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, dopts...)
	if err != nil {
		integrationtest.SkipUnreachable(t, "provider not reachable at %s (local: run `make infra-up`): %v", tc.Issuer, err)
	}
	if cfg.AuthorizationEndpoint == "" {
		t.Skip("provider advertises no authorization_endpoint")
	}

	verifier, err := token.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	state, err := token.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}

	res, err := integrationtest.PerformAuthCodeFlow(ctx, cfg.AuthorizationEndpoint,
		tc.PublicClientID, tc.RedirectURI, "openid", token.S256Challenge(verifier), state,
		func(v url.Values) {
			v.Set("nonce", liveNonce)
			v.Set("max_age", strconv.Itoa(liveMaxAge))
		})
	if errors.Is(err, integrationtest.ErrNoDevInteractions) {
		t.Skipf("headless flow unavailable on this profile: %v", err)
	}
	if err != nil {
		t.Fatalf("PerformAuthCodeFlow: %v", err)
	}

	opts := []token.Option{token.WithCodeVerifier(verifier)}
	if tc.AllowHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	tokenResp, err := token.AuthorizationCode(ctx, cfg.TokenEndpoint, tc.PublicClientID,
		res.Code, tc.RedirectURI, opts...)
	if err != nil {
		t.Fatalf("AuthorizationCode exchange: %v", err)
	}
	if tokenResp.IDToken == "" {
		t.Skip("auth-code token response carried no id_token (openid scope not honoured)")
	}

	var jopts []jwks.Option
	if tc.AllowHTTP {
		jopts = append(jopts, jwks.WithInsecureAllowHTTP())
	}
	set, err := jwks.FetchKeySet(ctx, cfg.JWKSURI, jopts...)
	if err != nil {
		t.Fatalf("fetch live jwks: %v", err)
	}

	return liveIDTokenResult{
		idToken:     tokenResp.IDToken,
		accessToken: tokenResp.AccessToken,
		clientID:    tc.PublicClientID,
		issuer:      tc.Issuer,
		keySet:      set,
		allowHTTP:   tc.AllowHTTP,
	}
}

// decodeUnverifiedClaims reads an ID Token's claims WITHOUT verifying — only to
// branch on the presence of provider-optional claims (nonce/auth_time/at_hash).
func decodeUnverifiedClaims(t *testing.T, idToken string) map[string]any {
	t.Helper()
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a 3-part JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse id_token payload: %v", err)
	}
	return claims
}

// TestIntegration_ValidateIDToken_BaseProfile proves the full public entry point
// ValidateIDToken end-to-end against a live OP: a genuine ID Token is minted via
// a real auth-code + PKCE flow, its signature is verified against the OP's live
// JWKS, and the ID-Token profile (sub + azp + the requested nonce/max_age) is
// enforced on the real claims. node-oidc-provider's code-flow ID Token does not
// carry an at_hash (OPs emit it only for authorization-endpoint responses), so
// at_hash is asserted only when the OP actually mints one — that leg guards
// itself and documents the reason. at_hash coverage otherwise lives in the
// conformance vectors.
func TestIntegration_ValidateIDToken_BaseProfile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live := obtainLiveIDToken(t, ctx)

	claims, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
	)
	if err != nil {
		t.Fatalf("ValidateIDToken against live provider: %v", err)
	}
	if claims.Subject == "" {
		t.Errorf("validated ID Token is missing the required sub claim")
	}
	if claims.Issuer != live.issuer {
		t.Errorf("iss = %q, want %q", claims.Issuer, live.issuer)
	}
	if !claims.Audience.Contains(live.clientID) {
		t.Errorf("aud %v does not contain the RP client_id %q", claims.Audience, live.clientID)
	}
	if claims.Expiry == nil || claims.IssuedAt == nil || !claims.Expiry.After(claims.IssuedAt.Time) {
		t.Errorf("expected exp after iat, got exp=%v iat=%v", claims.Expiry, claims.IssuedAt)
	}
}

// TestIntegration_ValidateIDToken_WrongAudience confirms the same real ID Token
// is rejected by the base validation when validated for a different client_id.
func TestIntegration_ValidateIDToken_WrongAudience(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live := obtainLiveIDToken(t, ctx)

	_, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID("some-other-audience"),
	)
	if err == nil {
		t.Fatalf("expected rejection for a mismatched audience, got nil")
	}
}

// TestIntegration_ValidateIDToken_NonceBinding exercises the §3.1.3.7 step 11
// nonce binding on the real token, when the OP echoed the requested nonce.
func TestIntegration_ValidateIDToken_NonceBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live := obtainLiveIDToken(t, ctx)
	if _, ok := decodeUnverifiedClaims(t, live.idToken)["nonce"]; !ok {
		t.Skip("OP did not echo the requested nonce into the ID Token")
	}

	// The nonce we sent passes.
	if _, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
		idtoken.WithNonce(liveNonce),
	); err != nil {
		t.Fatalf("ValidateIDToken with the sent nonce: %v", err)
	}

	// A different nonce is rejected by the profile check.
	_, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
		idtoken.WithNonce("not-the-nonce-we-sent"),
	)
	var pe *idtoken.ProfileError
	if !errors.As(err, &pe) || pe.Reason != idtoken.ReasonNonceMismatch {
		t.Fatalf("err = %v, want *ProfileError{nonce_mismatch}", err)
	}
}

// TestIntegration_ValidateIDToken_MaxAge exercises the §3.1.3.7 step 12
// max_age/auth_time freshness on the real auth_time claim, when the OP included
// one for the requested max_age.
func TestIntegration_ValidateIDToken_MaxAge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live := obtainLiveIDToken(t, ctx)
	if _, ok := decodeUnverifiedClaims(t, live.idToken)["auth_time"]; !ok {
		t.Skip("OP did not include auth_time in the ID Token for the requested max_age")
	}

	// A just-minted token whose auth_time is ~now passes a generous max_age.
	if _, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
		idtoken.WithMaxAge(liveMaxAge*time.Second),
	); err != nil {
		t.Fatalf("ValidateIDToken with max_age: %v", err)
	}
}

// TestIntegration_ValidateIDToken_AtHashWhenPresent asserts the at_hash binding
// only when the OP actually mints an at_hash in its code-flow ID Token. node-oidc
// (like most OPs) emits at_hash only for authorization-endpoint responses, so
// this leg documents its skip; the at_hash construction is covered exhaustively
// by the conformance vectors (IDT-007/008).
func TestIntegration_ValidateIDToken_AtHashWhenPresent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live := obtainLiveIDToken(t, ctx)
	if _, ok := decodeUnverifiedClaims(t, live.idToken)["at_hash"]; !ok {
		t.Skip("OP's code-flow ID Token carries no at_hash (emitted only for " +
			"authorization-endpoint responses) — at_hash binding covered by conformance vectors")
	}
	if live.accessToken == "" {
		t.Fatalf("ID Token carried an at_hash but the flow returned no access_token")
	}

	// The issued access token passes the at_hash binding.
	if _, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
		idtoken.WithAccessToken(live.accessToken),
	); err != nil {
		t.Fatalf("ValidateIDToken with at_hash: %v", err)
	}

	// A tampered access token is rejected by the at_hash check.
	_, err := idtoken.ValidateIDToken(ctx, live.idToken, live.keySet,
		idtoken.WithIssuer(live.issuer),
		idtoken.WithClientID(live.clientID),
		idtoken.WithAccessToken(live.accessToken+"tampered"),
	)
	var pe *idtoken.ProfileError
	if !errors.As(err, &pe) || pe.Reason != idtoken.ReasonAtHashMismatch {
		t.Fatalf("err = %v, want *ProfileError{at_hash_mismatch}", err)
	}
}
