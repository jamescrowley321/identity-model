//go:build integration

package token_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// RFC 8693 token exchange has no support in node-oidc-provider (the local
// integration fixture) or in the hosted provider profiles — Descope discovery
// advertises the grant but its token endpoint rejects it with E011003. Epic 0F
// explicitly permits a mock-endpoint integration test for this capability, so
// these tests drive the real token.TokenExchange client against a self-contained
// httptest server implementing RFC 8693, replaying the same conformance fixtures
// the unit tests and token-exchange.json use. This exercises the full HTTP
// round-trip (form encoding, client auth header, status handling, JSON parsing)
// end to end, which the unit tests' in-process handlers approximate but this
// confirms over a real socket.

// exchangeFixtureBytes reads a conformance fixture from
// spec/test-fixtures/token-exchange for the mock server to replay.
func exchangeFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "token-exchange", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// mockExchangeServer implements a minimal RFC 8693 token endpoint. It records
// the last decoded form so tests can assert what the client transmitted, then
// replays fixtureName (or an invalid_grant error when the subject token is the
// literal "expired").
func mockExchangeServer(t *testing.T, fixtureName string, lastForm *map[string][]string) *httptest.Server {
	t.Helper()
	okBody := exchangeFixtureBytes(t, fixtureName)
	errBody := exchangeFixtureBytes(t, "exchange-error-invalid-grant.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		*lastForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")

		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		if r.PostForm.Get("subject_token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"subject_token required"}`))
			return
		}
		if r.PostForm.Get("subject_token") == "expired" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(errBody)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(okBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// EXCH-001 (integration): a real HTTP impersonation exchange against the mock
// endpoint returns the parsed issued-token trio.
func TestIntegration_TokenExchange_Impersonation(t *testing.T) {
	var form map[string][]string
	srv := mockExchangeServer(t, "exchange-impersonation-success.json", &form)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := token.TokenExchange(ctx, srv.URL, "cid", "secret",
		"real-subject-token", token.TokenTypeAccessToken, token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if resp.AccessToken == "" || resp.IssuedTokenType == "" {
		t.Errorf("response = %+v", resp)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
}

// EXCH-002 (integration): a delegation exchange transmits BOTH the subject and
// actor tokens (with their types) over the wire.
func TestIntegration_TokenExchange_Delegation(t *testing.T) {
	var form map[string][]string
	srv := mockExchangeServer(t, "exchange-delegation-success.json", &form)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := token.TokenExchange(ctx, srv.URL, "cid", "secret",
		"real-subject-token", token.TokenTypeAccessToken,
		token.WithActorToken("real-actor-token", token.TokenTypeJWT),
		token.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange delegation: %v", err)
	}
	if got := form["subject_token"]; len(got) != 1 || got[0] != "real-subject-token" {
		t.Errorf("subject_token not received: %v", form)
	}
	if got := form["actor_token"]; len(got) != 1 || got[0] != "real-actor-token" {
		t.Errorf("actor_token not received: %v", form)
	}
	if got := form["actor_token_type"]; len(got) != 1 || got[0] != token.TokenTypeJWT {
		t.Errorf("actor_token_type not received: %v", form)
	}
}

// EXCH-006 (integration): the mock rejects an expired subject token with a 400
// OAuth error body, which the client surfaces as a typed TokenError.
func TestIntegration_TokenExchange_ErrorResponse(t *testing.T) {
	var form map[string][]string
	srv := mockExchangeServer(t, "exchange-impersonation-success.json", &form)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := token.TokenExchange(ctx, srv.URL, "cid", "secret",
		"expired", token.TokenTypeAccessToken, token.WithInsecureAllowHTTP())
	var te *token.TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *token.TokenError", err)
	}
	if te.Code != "invalid_grant" {
		t.Errorf("error code = %q, want invalid_grant", te.Code)
	}
}
