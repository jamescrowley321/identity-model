package introspection

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

// fixture reads a shared conformance fixture from spec/test-fixtures/introspection.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/introspection; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "introspection", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// capturedRequest records what the test introspection endpoint received so
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// INTR-001: introspecting an active token returns active=true plus all standard
// §2.2 metadata, and unknown members remain reachable via Extra.
func TestIntrospect_ActiveToken(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-response.json"), &got)

	ir, err := Introspect(context.Background(), srv.URL, "cid", "secret", "the-token", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
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

	if !ir.Active {
		t.Fatal("Active = false, want true")
	}
	if ir.Scope != "read write dolphin" || ir.ClientID != "l238j323ds-23ij4" {
		t.Errorf("scope/client_id = %q/%q", ir.Scope, ir.ClientID)
	}
	if ir.Username != "jdoe" || ir.TokenType != "Bearer" {
		t.Errorf("username/token_type = %q/%q", ir.Username, ir.TokenType)
	}
	if ir.Exp != 1419356238 || ir.Iat != 1419350238 || ir.Nbf != 1419350238 {
		t.Errorf("exp/iat/nbf = %d/%d/%d", ir.Exp, ir.Iat, ir.Nbf)
	}
	if ir.Sub != "Z5O3upPC88QrAjx00dis" || ir.Iss != "https://server.example.com/" {
		t.Errorf("sub/iss = %q/%q", ir.Sub, ir.Iss)
	}
	if ir.Jti != "d3f5c9a1-2b7e-4c1a-9e8f-0a1b2c3d4e5f" {
		t.Errorf("jti = %q", ir.Jti)
	}
	if !ir.Aud.Contains("https://protected.example.net/resource") {
		t.Errorf("aud = %v", ir.Aud)
	}
	if v, ok := ir.Extra["extension_field"]; !ok || v != "twenty-seven" {
		t.Errorf("extra[extension_field] = %v (ok=%v)", v, ok)
	}
}

// INTR-002: an inactive/expired/revoked token returns active=false and no other
// member is required to be present.
func TestIntrospect_InactiveToken(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "inactive-response.json"), &got)

	ir, err := Introspect(context.Background(), srv.URL, "cid", "secret", "expired", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if ir.Active {
		t.Error("Active = true, want false")
	}
	if ir.Scope != "" || ir.ClientID != "" || ir.Sub != "" || ir.Exp != 0 || len(ir.Aud) != 0 {
		t.Errorf("inactive response carried metadata: %+v", ir)
	}
}

// INTR-002 (variant): an active response MAY omit all optional metadata.
func TestIntrospect_ActiveMinimal(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	ir, err := Introspect(context.Background(), srv.URL, "cid", "secret", "tok", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !ir.Active {
		t.Error("Active = false, want true")
	}
	if ir.Scope != "" || ir.Exp != 0 || len(ir.Extra) != 0 {
		t.Errorf("minimal active response carried extra data: %+v", ir)
	}
}

// INTR-003: client_secret_basic is the default — the request carries a Basic
// header with form-urlencoded credentials and none appear in the body.
func TestIntrospect_ClientSecretBasicDefault(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	// Credentials with reserved characters prove §2.3.1 form-urlencoding.
	id, secret := "cli ent", "s/e:cr et"
	if _, err := Introspect(context.Background(), srv.URL, id, secret, "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Introspect: %v", err)
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

// INTR-003: client_secret_post puts credentials in the body and sets no Basic
// header.
func TestIntrospect_ClientSecretPost(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok",
		WithClientAuth(ClientSecretPost), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if got.authHeader != "" {
		t.Errorf("Authorization = %q, want empty for client_secret_post", got.authHeader)
	}
	if got.form.Get("client_id") != "cid" || got.form.Get("client_secret") != "sec" {
		t.Errorf("body creds = %q/%q", got.form.Get("client_id"), got.form.Get("client_secret"))
	}
}

// INTR-004: token_type_hint is sent when configured and the token param is
// always present.
func TestIntrospect_TokenTypeHint(t *testing.T) {
	for _, hint := range []string{"access_token", "refresh_token"} {
		t.Run(hint, func(t *testing.T) {
			var got capturedRequest
			srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

			_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok",
				WithTokenTypeHint(hint), WithInsecureAllowHTTP())
			if err != nil {
				t.Fatalf("Introspect: %v", err)
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

// INTR-004 (variant): without WithTokenTypeHint no hint parameter is sent.
func TestIntrospect_NoHintByDefault(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	if _, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if got.form.Has("token_type_hint") {
		t.Errorf("token_type_hint present unexpectedly: %q", got.form.Get("token_type_hint"))
	}
}

// INTR-005: an HTTP 401 with an OAuth error body surfaces a typed
// IntrospectionError carrying error=invalid_client, and errors.Is matches the
// sentinel.
func TestIntrospect_ErrorResponse(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusUnauthorized, fixture(t, "error-invalid-client.json"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "wrong", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ie *IntrospectionError
	if !errors.As(err, &ie) {
		t.Fatalf("error = %T, want *IntrospectionError", err)
	}
	if ie.Code != "invalid_client" {
		t.Errorf("code = %q, want invalid_client", ie.Code)
	}
	if ie.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", ie.StatusCode)
	}
	if ie.ErrorDescription != "Client authentication failed" {
		t.Errorf("error_description = %q", ie.ErrorDescription)
	}
	if !errors.Is(err, ErrIntrospectionResponse) {
		t.Error("errors.Is(err, ErrIntrospectionResponse) = false")
	}
}

// INTR-006: the introspection_endpoint is resolved from a discovery document
// and used by Introspect.
func TestIntrospect_DiscoveryEndpointResolution(t *testing.T) {
	// Serve both the discovery document (with introspection_endpoint pointing at
	// this same server's /introspect) and the introspection response.
	var got capturedRequest
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Rewrite the fixture's introspection_endpoint to this server.
		var doc map[string]any
		if err := json.Unmarshal(fixture(t, "discovery-with-introspection.json"), &doc); err != nil {
			t.Errorf("unmarshal discovery fixture: %v", err)
		}
		doc["issuer"] = base
		doc["introspection_endpoint"] = base + "/introspect"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture(t, "active-minimal.json"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL

	cfg, err := discovery.FetchConfiguration(context.Background(), base, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if cfg.IntrospectionEndpoint != base+"/introspect" {
		t.Fatalf("introspection_endpoint = %q, want %q", cfg.IntrospectionEndpoint, base+"/introspect")
	}

	ir, err := Introspect(context.Background(), cfg.IntrospectionEndpoint, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect via discovered endpoint: %v", err)
	}
	if !ir.Active {
		t.Error("Active = false via discovered endpoint")
	}
	if got.form.Get("token") != "tok" {
		t.Errorf("discovered endpoint received token = %q", got.form.Get("token"))
	}
}

// Adversarial: a non-JSON 200 body surfaces a RequestError, not a silent
// zero-value Introspection.
func TestIntrospect_MalformedBody(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, []byte("<html>not json</html>"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest", err)
	}
}

// Adversarial: a non-2xx response without a recognisable OAuth error body is a
// RequestError carrying the status, not an IntrospectionError.
func TestIntrospect_NonOAuthErrorBody(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusInternalServerError, []byte("upstream exploded"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrIntrospectionResponse) {
		t.Error("plain 500 misclassified as an OAuth error response")
	}
	var re *RequestError
	if !errors.As(err, &re) || re.StatusCode != http.StatusInternalServerError {
		t.Errorf("error = %v, want RequestError with status 500", err)
	}
}

// Adversarial: an http:// endpoint is rejected unless WithInsecureAllowHTTP is
// set (RFC-alignment: introspection carries bearer tokens over TLS).
func TestIntrospect_RejectsHTTPWithoutOptIn(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok")
	if err == nil {
		t.Fatal("expected https-required error for http:// endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "https required") {
		t.Errorf("error = %v, want https-required", err)
	}
}

// Adversarial: introspection endpoints are protected, so a request without any
// client credentials is rejected before hitting the network.
func TestIntrospect_RequiresClientAuth(t *testing.T) {
	_, err := Introspect(context.Background(), "https://as.example.com/introspect", "", "", "tok")
	if err == nil {
		t.Fatal("expected client-auth error, got nil")
	}
	if !strings.Contains(err.Error(), "client authentication") {
		t.Errorf("error = %v, want client authentication required", err)
	}
}

// Adversarial: an oversized response body is capped and rejected rather than
// read into memory unboundedly.
func TestIntrospect_OversizedBody(t *testing.T) {
	huge := append([]byte(`{"active":true,"pad":"`), make([]byte, maxBodyBytes+16)...)
	for i := range huge[len(`{"active":true,"pad":"`):] {
		huge[len(`{"active":true,"pad":"`)+i] = 'a'
	}
	var got capturedRequest
	srv := newServer(t, http.StatusOK, huge, &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected oversized-body error, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest", err)
	}
}

// WithExtraParams adds provider-specific parameters but can never override the
// reserved request/auth params.
func TestIntrospect_ExtraParamsCannotOverrideReserved(t *testing.T) {
	var got capturedRequest
	srv := newServer(t, http.StatusOK, fixture(t, "active-minimal.json"), &got)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "real-token",
		WithExtraParams(map[string]string{
			"token":     "attacker-token",
			"client_id": "attacker",
			"resource":  "https://api.example.com",
		}),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("Introspect: %v", err)
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
func TestIntrospect_TimeoutHonored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	t.Cleanup(srv.Close)

	_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok",
		WithTimeout(20*time.Millisecond), WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("error = %v, want ErrRequest from timeout", err)
	}
}

// parseBasic decodes an "Basic <base64>" header into its username and password.
func parseBasic(t *testing.T, header string) (user, pass string, ok bool) {
	t.Helper()
	req := &http.Request{Header: http.Header{"Authorization": {header}}}
	return req.BasicAuth()
}

// Adversarial: a half-credential pair (only one of client_id/client_secret) is
// rejected before the network, since both auth methods need the full pair.
func TestIntrospect_RejectsHalfCredentials(t *testing.T) {
	cases := []struct{ id, secret string }{
		{"cid", ""}, // missing secret
		{"", "sec"}, // missing id
	}
	for _, c := range cases {
		_, err := Introspect(context.Background(), "https://as.example.com/introspect", c.id, c.secret, "tok")
		if err == nil {
			t.Fatalf("id=%q secret=%q: expected client-auth error, got nil", c.id, c.secret)
		}
		if !strings.Contains(err.Error(), "client authentication") {
			t.Errorf("id=%q secret=%q: error = %v, want client authentication required", c.id, c.secret, err)
		}
	}
}

// Adversarial: a 2xx body omitting the REQUIRED "active" member (RFC 7662 §2.2)
// is rejected as malformed rather than decoding to a silent Active=false.
func TestIntrospect_RejectsBodyMissingActive(t *testing.T) {
	for _, body := range []string{`{}`, `{"scope":"read"}`, `null`, `{"active":null}`} {
		var got capturedRequest
		srv := newServer(t, http.StatusOK, []byte(body), &got)
		_, err := Introspect(context.Background(), srv.URL, "cid", "sec", "tok", WithInsecureAllowHTTP())
		if err == nil {
			t.Fatalf("body=%s: expected missing-active error, got nil", body)
		}
		if !strings.Contains(err.Error(), "active") {
			t.Errorf("body=%s: error = %v, want missing-active", body, err)
		}
		if !errors.Is(err, ErrRequest) {
			t.Errorf("body=%s: error = %v, want ErrRequest", body, err)
		}
	}
}
