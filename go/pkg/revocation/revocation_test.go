package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

// fixture reads a shared conformance fixture from spec/test-fixtures/revocation.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/revocation; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "revocation", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// capturedRequest records what the test revocation endpoint received so
// assertions can inspect the method, headers and decoded form body.
type capturedRequest struct {
	method      string
	contentType string
	accept      string
	authHeader  string
	form        url.Values
}

// newServer returns an httptest server that records the incoming request into
// got and replies with status and body.
func newServer(t *testing.T, status int, body []byte, got *capturedRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		got.method = r.Method
		got.contentType = r.Header.Get("Content-Type")
		got.accept = r.Header.Get("Accept")
		got.authHeader = r.Header.Get("Authorization")
		got.form = r.PostForm
		w.WriteHeader(status)
		if body != nil {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// REV-001: revoking a token returns HTTP 200 with an empty body and Revoke
// reports success (nil). The POSTed form carries the token as
// application/x-www-form-urlencoded.
func TestRevoke_SuccessEmptyBody(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "revoke-success-empty.json"), &got)

	err := Revoke(context.Background(), srv.URL, "cid", "secret", "the-token", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q", got.contentType)
	}
	if got.accept != "application/json" {
		t.Errorf("accept = %q, want application/json", got.accept)
	}
	if v := got.form.Get("token"); v != "the-token" {
		t.Errorf("token form param = %q, want the-token", v)
	}
}

// REV-001: a 200 response carrying a JSON object body ("{}") is also treated as
// success — the body is ignored (RFC 7009 §2.2).
func TestRevoke_SuccessEmptyObjectBody(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "revoke-success-empty-object.json"), &got)

	if err := Revoke(context.Background(), srv.URL, "cid", "secret", "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// REV-001: the server returns 200 regardless of token validity and MUST NOT
// differentiate (§2.1 anti-scanning). Revoking an unknown/invalid/expired token
// — and revoking the same token twice — both succeed.
func TestRevoke_SuccessRegardlessOfValidity(t *testing.T) {
	var got capturedRequest
	// The endpoint always answers 200 with an empty body no matter the token.
	srv := newServer(t, http.StatusOK, nil, &got)

	for _, tok := range []string{"valid-token", "already-revoked-token", "expired", "never-existed"} {
		if err := Revoke(context.Background(), srv.URL, "cid", "secret", tok, WithInsecureAllowHTTP()); err != nil {
			t.Errorf("Revoke(%q) = %v, want nil (200 regardless of validity)", tok, err)
		}
	}
	// Double-revoke of the same token is idempotent from the caller's view.
	if err := Revoke(context.Background(), srv.URL, "cid", "secret", "valid-token", WithInsecureAllowHTTP()); err != nil {
		t.Errorf("second Revoke = %v, want nil", err)
	}
}

// REV-001 (variant): any 2xx (e.g. 204 No Content) is success without a body.
func TestRevoke_Success204(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusNoContent, nil, &got)

	if err := Revoke(context.Background(), srv.URL, "cid", "secret", "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke on 204: %v", err)
	}
}

// REV-002: token_type_hint is sent when configured and the token param is always
// present (§2.1).
func TestRevoke_TokenTypeHint(t *testing.T) {
	for _, hint := range []string{"access_token", "refresh_token"} {
		t.Run(hint, func(t *testing.T) {
			var got capturedRequest
			srv := newServer(t, http.StatusOK, nil, &got)

			err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok",
				WithTokenTypeHint(hint), WithInsecureAllowHTTP())
			if err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			if got.form.Get("token_type_hint") != hint {
				t.Errorf("token_type_hint = %q, want %q", got.form.Get("token_type_hint"), hint)
			}
			if got.form.Get("token") != "tok" {
				t.Errorf("token = %q, want tok", got.form.Get("token"))
			}
		})
	}
}

// REV-002 (variant): without WithTokenTypeHint no hint parameter is sent.
func TestRevoke_NoHintByDefault(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, nil, &got)

	if err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.form.Has("token_type_hint") {
		t.Errorf("token_type_hint present unexpectedly: %q", got.form.Get("token_type_hint"))
	}
}

// REV-003: an HTTP 400 unsupported_token_type surfaces a typed RevocationError,
// and errors.Is matches the sentinel (§2.2.1).
func TestRevoke_UnsupportedTokenType(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusBadRequest, fixture(t, "error-unsupported-token-type.json"), &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var re *RevocationError
	if !errors.As(err, &re) {
		t.Fatalf("error = %T, want *RevocationError", err)
	}
	if re.Code != "unsupported_token_type" {
		t.Errorf("code = %q, want unsupported_token_type", re.Code)
	}
	if re.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", re.StatusCode)
	}
	if !errors.Is(err, ErrRevocationResponse) {
		t.Error("errors.Is(err, ErrRevocationResponse) = false")
	}
}

// REV-004: an HTTP 401 invalid_client surfaces a typed RevocationError (§2.2.1).
func TestRevoke_InvalidClient(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusUnauthorized, fixture(t, "error-invalid-client.json"), &got)

	err := Revoke(context.Background(), srv.URL, "cid", "wrong", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var re *RevocationError
	if !errors.As(err, &re) {
		t.Fatalf("error = %T, want *RevocationError", err)
	}
	if re.Code != "invalid_client" {
		t.Errorf("code = %q, want invalid_client", re.Code)
	}
	if re.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", re.StatusCode)
	}
	if re.ErrorDescription != "Client authentication failed" {
		t.Errorf("error_description = %q", re.ErrorDescription)
	}
	if !errors.Is(err, ErrRevocationResponse) {
		t.Error("errors.Is(err, ErrRevocationResponse) = false")
	}
}

// REV-005: the revocation_endpoint is resolved from a discovery document and
// used by Revoke (RFC 8414 §2).
func TestRevoke_DiscoveryEndpointResolution(t *testing.T) {
	var got capturedRequest
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Rewrite the fixture's revocation_endpoint to this server.
		var doc map[string]any
		if err := json.Unmarshal(fixture(t, "discovery-with-revocation.json"), &doc); err != nil {
			t.Errorf("unmarshal discovery fixture: %v", err)
		}
		doc["issuer"] = base
		doc["revocation_endpoint"] = base + "/revoke"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.form = r.PostForm
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL

	cfg, err := discovery.FetchConfiguration(context.Background(), base, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if cfg.RevocationEndpoint != base+"/revoke" {
		t.Fatalf("revocation_endpoint = %q, want %q", cfg.RevocationEndpoint, base+"/revoke")
	}

	if err := Revoke(context.Background(), cfg.RevocationEndpoint, "cid", "sec", "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke via discovered endpoint: %v", err)
	}
	if got.form.Get("token") != "tok" {
		t.Errorf("discovered endpoint received token = %q", got.form.Get("token"))
	}
}

// client_secret_basic is the default — the request carries a Basic header with
// form-urlencoded credentials and none appear in the body (RFC 6749 §2.3.1).
func TestRevoke_ClientSecretBasicDefault(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, nil, &got)

	// Credentials with reserved characters prove §2.3.1 form-urlencoding.
	id, secret := "cli ent", "s/e:cr et"
	if err := Revoke(context.Background(), srv.URL, id, secret, "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !strings.HasPrefix(got.authHeader, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic header", got.authHeader)
	}
	wantUser, wantPass := url.QueryEscape(id), url.QueryEscape(secret)
	gotUser, gotPass, ok := parseBasic(t, got.authHeader)
	if !ok || gotUser != wantUser || gotPass != wantPass {
		t.Errorf("basic creds = %q/%q, want %q/%q", gotUser, gotPass, wantUser, wantPass)
	}
	if got.form.Has("client_id") || got.form.Has("client_secret") {
		t.Errorf("credentials leaked into body: %v", got.form)
	}
}

// client_secret_post puts credentials in the body and sets no Basic header.
func TestRevoke_ClientSecretPost(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, nil, &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok",
		WithClientAuth(ClientSecretPost), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.authHeader != "" {
		t.Errorf("Authorization = %q, want empty for client_secret_post", got.authHeader)
	}
	if got.form.Get("client_id") != "cid" || got.form.Get("client_secret") != "sec" {
		t.Errorf("body creds = %q/%q", got.form.Get("client_id"), got.form.Get("client_secret"))
	}
}

// Adversarial: an http:// endpoint is rejected unless WithInsecureAllowHTTP is
// set — revocation carries a token over the wire and belongs over TLS.
func TestRevoke_RejectsHTTPWithoutOptIn(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, nil, &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok")
	if err == nil {
		t.Fatal("expected https-required error for http:// endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "https required") {
		t.Errorf("error = %v, want https-required", err)
	}
}

// Adversarial: revocation endpoints are protected, so a request without any
// client credentials is rejected before hitting the network.
func TestRevoke_RequiresClientAuth(t *testing.T) {
	err := Revoke(context.Background(), "https://as.example.com/revoke", "", "", "tok")
	if err == nil {
		t.Fatal("expected client-auth error, got nil")
	}
	if !strings.Contains(err.Error(), "client authentication") {
		t.Errorf("error = %v, want client authentication required", err)
	}
}

// Adversarial: a half-credential pair (only one of client_id/client_secret) is
// rejected before the network, since both auth methods need the full pair.
func TestRevoke_RejectsHalfCredentials(t *testing.T) {
	cases := []struct{ id, secret string }{
		{"cid", ""}, // missing secret
		{"", "sec"}, // missing id
	}
	for _, c := range cases {
		err := Revoke(context.Background(), "https://as.example.com/revoke", c.id, c.secret, "tok")
		if err == nil {
			t.Fatalf("id=%q secret=%q: expected client-auth error, got nil", c.id, c.secret)
		}
		if !strings.Contains(err.Error(), "client authentication") {
			t.Errorf("id=%q secret=%q: error = %v, want client authentication required", c.id, c.secret, err)
		}
	}
}

// Adversarial: a non-2xx response without a recognisable OAuth error body is a
// RequestError carrying the status, not a RevocationError.
func TestRevoke_NonOAuthErrorBody(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusInternalServerError, []byte("upstream exploded"), &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrRevocationResponse) {
		t.Error("plain 500 misclassified as an OAuth error response")
	}
	var re *RequestError
	if !errors.As(err, &re) || re.StatusCode != http.StatusInternalServerError {
		t.Errorf("error = %v, want RequestError with status 500", err)
	}
}

// Adversarial: an oversized error body is capped and rejected rather than read
// into memory unboundedly.
func TestRevoke_OversizedErrorBody(t *testing.T) {
	huge := make([]byte, maxBodyBytes+16)
	for i := range huge {
		huge[i] = 'a'
	}
	var got capturedRequest
	srv := newServer(t, http.StatusBadRequest, huge, &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected oversized-body error, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest", err)
	}
}

// WithExtraParams adds provider-specific parameters but can never override the
// reserved request/auth params.
func TestRevoke_ExtraParamsCannotOverrideReserved(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, nil, &got)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "real-token",
		WithExtraParams(map[string]string{
			"token":     "attacker-token",
			"client_id": "attacker",
			"resource":  "https://api.example.com",
		}),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got.form.Get("token") != "real-token" {
		t.Errorf("token overridden by extra param: %q", got.form.Get("token"))
	}
	if got.form.Has("client_id") {
		t.Errorf("client_id injected into body via extra param: %q", got.form.Get("client_id"))
	}
	if got.form.Get("resource") != "https://api.example.com" {
		t.Errorf("non-reserved extra param dropped: %q", got.form.Get("resource"))
	}
}

// WithTimeout bounds a slow endpoint.
func TestRevoke_TimeoutHonored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	err := Revoke(context.Background(), srv.URL, "cid", "sec", "tok",
		WithTimeout(20*time.Millisecond), WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest from timeout", err)
	}
}

// Adversarial: a malformed endpoint URL is a configuration RequestError, not a
// panic.
func TestRevoke_MalformedEndpoint(t *testing.T) {
	err := Revoke(context.Background(), "://not a url", "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error for malformed endpoint, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest", err)
	}
}

// parseBasic decodes a "Basic <base64>" header into its username and password.
func parseBasic(t *testing.T, header string) (user, pass string, ok bool) {
	t.Helper()
	req := &http.Request{Header: http.Header{"Authorization": {header}}}
	return req.BasicAuth()
}
