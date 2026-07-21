//go:build integration

package dpop_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/dpop"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// DPOP-001/DPOP-005 (live): request a client_credentials access token from the
// local provider through a DPoP transport and confirm the provider issued a
// DPoP-bound token — token_type "DPoP" and, for a JWT access token, a cnf.jkt
// equal to the RFC 7638 thumbprint of the proof key.
//
// Gate: node-oidc-provider advertises dpop_signing_alg_values_supported in
// discovery (its DPoP feature is enabled). Every profile that does not advertise
// it — and any profile unreachable — skips, keeping IdentityServer/Ory/Descope
// runs green.
func TestIntegration_DPoP_BoundClientCredentials(t *testing.T) {
	tc := integrationtest.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := discovery.FetchConfiguration(ctx, tc.Issuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("provider not reachable at %s (local: run `cd infra && docker compose up -d`): %v", tc.Issuer, err)
	}
	if _, ok := cfg.Extra["dpop_signing_alg_values_supported"]; !ok {
		t.Skip("provider does not advertise dpop_signing_alg_values_supported; DPoP not supported")
	}
	if cfg.TokenEndpoint == "" {
		t.Fatal("discovery returned no token_endpoint")
	}

	key, err := dpop.GenerateKey(dpop.ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	// Drive the token request through the DPoP transport: it attaches a proof to
	// the POST and transparently handles a use_dpop_nonce challenge (RFC 9449 §8).
	httpClient := &http.Client{Transport: dpop.NewTransport(key)}
	resp, err := token.ClientCredentials(ctx, cfg.TokenEndpoint, tc.ClientID, tc.ClientSecret,
		token.WithScopes(tc.Scope),
		token.WithHTTPClient(httpClient),
		token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("client_credentials with DPoP: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access_token")
	}
	// RFC 9449 §5: a DPoP-bound token is issued with token_type "DPoP".
	if !strings.EqualFold(resp.TokenType, "DPoP") {
		t.Errorf("token_type = %q, want DPoP", resp.TokenType)
	}

	// DPOP-005: a JWT access token carries cnf.jkt bound to the proof key. Opaque
	// tokens carry no decodable claims — assert the binding only when the token is
	// a JWT.
	if jkt, ok := boundJKT(t, resp.AccessToken); ok {
		if jkt != thumbprint {
			t.Errorf("access token cnf.jkt = %q, want the proof key thumbprint %q", jkt, thumbprint)
		}
	} else {
		t.Logf("access token is not a decodable JWT; skipped cnf.jkt assertion (token_type DPoP already verified)")
	}
}

// boundJKT extracts cnf.jkt from a JWT access token's payload without verifying
// its signature — the AS applied the binding, and this test only inspects it.
// The second return is false when tok is not a three-part JWT.
func boundJKT(t *testing.T, tok string) (string, bool) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return claims.Cnf.Jkt, claims.Cnf.Jkt != ""
}

// DPOP-004/DPOP-008 (self-contained): a full DPoP flow against an in-process
// authorization server and resource server — the AS issues a bound token after a
// nonce challenge, the RS accepts the token only under the DPoP scheme with a
// valid ath-bound proof. This runs with no external provider so the complete
// nonce-retry + resource path is always exercised under -tags=integration.
func TestIntegration_DPoP_EndToEndMock(t *testing.T) {
	key, err := dpop.GenerateKey(dpop.ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	thumbprint, err := key.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	const accessToken = "mock-dpop-bound-token"
	const serverNonce = "mock-nonce-xyz"

	var tokenCalls int
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Require a DPoP proof bound to this request.
		proof, err := dpop.VerifyProof(r.Header.Get("DPoP"), r.Method, "http://"+r.Host+r.URL.Path)
		if err != nil {
			http.Error(w, "bad proof", http.StatusBadRequest)
			return
		}
		if proof.Thumbprint != thumbprint {
			t.Errorf("AS: proof thumbprint = %q, want %q", proof.Thumbprint, thumbprint)
		}
		tokenCalls++
		// RFC 9449 §8: first challenge the client for a nonce, then accept it.
		if proof.Nonce != serverNonce {
			w.Header().Set("DPoP-Nonce", serverNonce)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + accessToken + `","token_type":"DPoP","expires_in":3600}`))
	}))
	defer as.Close()

	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFC 9449 §7: the token is presented under the DPoP scheme, not Bearer.
		auth := r.Header.Get("Authorization")
		if auth != "DPoP "+accessToken {
			http.Error(w, "want DPoP scheme", http.StatusUnauthorized)
			return
		}
		// The proof must be bound to the presented token via ath.
		if _, err := dpop.VerifyProof(r.Header.Get("DPoP"), r.Method, "http://"+r.Host+r.URL.Path,
			dpop.WithExpectedAth(accessToken)); err != nil {
			http.Error(w, "proof not bound to token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"protected"}`))
	}))
	defer rs.Close()

	// Token request (nonce challenge → retry handled transparently).
	tokenClient := &http.Client{Transport: dpop.NewTransport(key)}
	tokResp, err := tokenClient.Post(as.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200 after nonce retry", tokResp.StatusCode)
	}
	if tokenCalls < 2 {
		t.Errorf("AS saw %d proofs, want >=2 (challenge + retry)", tokenCalls)
	}

	// Resource request under the DPoP scheme with an ath-bound proof.
	resClient := &http.Client{Transport: dpop.NewTransport(key, dpop.WithAccessToken(accessToken))}
	res, err := resClient.Get(rs.URL + "/protected")
	if err != nil {
		t.Fatalf("resource request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("resource status = %d, want 200", res.StatusCode)
	}
}
