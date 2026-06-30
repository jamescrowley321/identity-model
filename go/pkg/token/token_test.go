package token

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// capturedRequest records what the test token endpoint received, so assertions
// can inspect the method, headers and decoded form body.
type capturedRequest struct {
	method      string
	contentType string
	accept      string
	authHeader  string
	form        url.Values
}

// newTokenServer returns an httptest server that records the incoming request
// into got and replies with status and body.
func newTokenServer(t *testing.T, status int, body string, got *capturedRequest) *httptest.Server {
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
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const successBody = `{"access_token":"at-123","token_type":"Bearer","expires_in":3600,"scope":"api"}`

// CC-001: client credentials grant returns a typed TokenResponse.
func TestClientCredentials_Success(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	resp, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q", got.contentType)
	}
	if g := got.form.Get("grant_type"); g != grantClientCredentials {
		t.Errorf("grant_type = %q, want %q", g, grantClientCredentials)
	}
	if resp.AccessToken != "at-123" || resp.TokenType != "Bearer" {
		t.Errorf("response = %+v", resp)
	}
	if resp.ExpiresIn != 3600 || resp.Scope != "api" {
		t.Errorf("expires_in/scope = %d/%q", resp.ExpiresIn, resp.Scope)
	}
}

// CC-002: client_secret_basic is the default — credentials in a Basic header,
// form-urlencoded before base64, and absent from the body.
func TestClientCredentials_BasicAuthDefault(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	// Use credentials with reserved characters to prove §2.3.1 form-urlencoding.
	id, secret := "cli ent", "s/e:cr et"
	if _, err := ClientCredentials(context.Background(), srv.URL, id, secret, WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	user, pass, ok := parseBasicAuth(got.authHeader)
	if !ok {
		t.Fatalf("missing/invalid Basic auth header: %q", got.authHeader)
	}
	if user != url.QueryEscape(id) || pass != url.QueryEscape(secret) {
		t.Errorf("basic creds = %q/%q, want form-urlencoded %q/%q", user, pass, url.QueryEscape(id), url.QueryEscape(secret))
	}
	if got.form.Has("client_id") || got.form.Has("client_secret") {
		t.Errorf("client creds must not appear in body with basic auth: %v", got.form)
	}
}

// CC-003: client_secret_post puts credentials in the body, no Basic header.
func TestClientCredentials_PostAuth(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithClientAuth(ClientSecretPost), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if got.authHeader != "" {
		t.Errorf("unexpected Authorization header with post auth: %q", got.authHeader)
	}
	if got.form.Get("client_id") != "cid" || got.form.Get("client_secret") != "secret" {
		t.Errorf("post creds missing from body: %v", got.form)
	}
}

// CC-004 / ACG-005: a non-2xx OAuth error body decodes into a typed TokenError.
func TestTokenRequest_ErrorResponse(t *testing.T) {
	var got capturedRequest
	body := `{"error":"invalid_client","error_description":"bad secret","error_uri":"https://e/x"}`
	srv := newTokenServer(t, http.StatusUnauthorized, body, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret", WithInsecureAllowHTTP())
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TokenError", err)
	}
	if te.Code != "invalid_client" || te.ErrorDescription != "bad secret" || te.ErrorURI != "https://e/x" {
		t.Errorf("token error = %+v", te)
	}
	if te.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", te.StatusCode)
	}
	if !errors.Is(err, ErrTokenResponse) {
		t.Errorf("errors.Is(ErrTokenResponse) = false")
	}
}

// A non-2xx response without an OAuth error body surfaces as RequestError.
func TestTokenRequest_NonOAuthErrorBody(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusBadGateway, "upstream down", &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret", WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want *RequestError", err)
	}
	if re.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", re.StatusCode)
	}
	if !errors.Is(err, ErrRequest) {
		t.Errorf("errors.Is(ErrRequest) = false")
	}
}

// CC-005: WithScopes sends a single space-delimited scope parameter.
func TestClientCredentials_Scopes(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithScopes("api", "profile"), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if g := got.form.Get("scope"); g != "api profile" {
		t.Errorf("scope = %q, want %q", g, "api profile")
	}
}

// CC-006: WithExtraParams and WithHTTPClient are applied to the request.
func TestClientCredentials_ExtraParamsAndHTTPClient(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	// A custom client with a marker on its transport proves WithHTTPClient is used.
	marker := &markerTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: marker}

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithExtraParams(map[string]string{"resource": "https://api.example", "audience": "aud1"}),
		WithHTTPClient(client), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if got.form.Get("resource") != "https://api.example" || got.form.Get("audience") != "aud1" {
		t.Errorf("extra params missing: %v", got.form)
	}
	if !marker.used {
		t.Errorf("custom http client was not used")
	}
}

// Extra params must not override reserved grant parameters.
func TestClientCredentials_ExtraParamsCannotOverrideGrant(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithExtraParams(map[string]string{"grant_type": "evil"}), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if g := got.form.Get("grant_type"); g != grantClientCredentials {
		t.Errorf("grant_type overridden to %q", g)
	}
}

// ACG-001: authorization code grant POSTs code + redirect_uri and returns tokens.
func TestAuthorizationCode_Success(t *testing.T) {
	var got capturedRequest
	body := `{"access_token":"at-9","token_type":"Bearer","expires_in":120,"id_token":"idt"}`
	srv := newTokenServer(t, http.StatusOK, body, &got)

	resp, err := AuthorizationCode(context.Background(), srv.URL, "pub-cid", "auth-code-xyz",
		"http://localhost:8080/callback", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("AuthorizationCode: %v", err)
	}
	if got.form.Get("grant_type") != grantAuthorizationCode {
		t.Errorf("grant_type = %q", got.form.Get("grant_type"))
	}
	if got.form.Get("code") != "auth-code-xyz" {
		t.Errorf("code = %q", got.form.Get("code"))
	}
	if got.form.Get("redirect_uri") != "http://localhost:8080/callback" {
		t.Errorf("redirect_uri = %q", got.form.Get("redirect_uri"))
	}
	// Public client: client_id in body, no Basic header.
	if got.form.Get("client_id") != "pub-cid" {
		t.Errorf("client_id = %q, want pub-cid", got.form.Get("client_id"))
	}
	if got.authHeader != "" {
		t.Errorf("public client must not send Basic auth: %q", got.authHeader)
	}
	if resp.AccessToken != "at-9" || resp.IDToken != "idt" {
		t.Errorf("response = %+v", resp)
	}
}

// ACG-004: WithCodeVerifier adds the code_verifier form parameter.
func TestAuthorizationCode_CodeVerifier(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 App B
	_, err := AuthorizationCode(context.Background(), srv.URL, "pub-cid", "code", "",
		WithCodeVerifier(verifier), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("AuthorizationCode: %v", err)
	}
	if got.form.Get("code_verifier") != verifier {
		t.Errorf("code_verifier = %q, want %q", got.form.Get("code_verifier"), verifier)
	}
	// redirect_uri omitted when empty.
	if got.form.Has("redirect_uri") {
		t.Errorf("redirect_uri should be omitted when empty")
	}
}

// An invalid PKCE verifier is rejected before any request is made.
func TestAuthorizationCode_InvalidCodeVerifier(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := AuthorizationCode(context.Background(), srv.URL, "cid", "code", "",
		WithCodeVerifier("too-short"), WithInsecureAllowHTTP())
	if !errors.Is(err, ErrInvalidCodeVerifier) {
		t.Fatalf("error = %v, want ErrInvalidCodeVerifier", err)
	}
	if got.method != "" {
		t.Errorf("request should not have been sent for an invalid verifier")
	}
}

// An https endpoint is required unless WithInsecureAllowHTTP is set.
func TestTokenRequest_HTTPSRequired(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret")
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("error = %v, want ErrRequest (https required)", err)
	}
	if got.method != "" {
		t.Errorf("request should not have reached an http endpoint")
	}
}

// expires_in is tolerated as a numeric string (some providers send one).
func TestTokenResponse_ExpiresInString(t *testing.T) {
	var got capturedRequest
	body := `{"access_token":"at","token_type":"Bearer","expires_in":"900","custom":"v"}`
	srv := newTokenServer(t, http.StatusOK, body, &got)

	resp, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret", WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expires_in = %d, want 900", resp.ExpiresIn)
	}
	if resp.Extra["custom"] != "v" {
		t.Errorf("extra custom = %v, want v", resp.Extra["custom"])
	}
}

// expires_in is optional (RFC 6749 §5.1): a null, empty-string, or fractional
// value must not discard an otherwise valid token. Regression for review-fix.
func TestTokenResponse_ExpiresInTolerant(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int64
	}{
		{"null", `{"access_token":"at","token_type":"Bearer","expires_in":null}`, 0},
		{"empty_string", `{"access_token":"at","token_type":"Bearer","expires_in":""}`, 0},
		{"float", `{"access_token":"at","token_type":"Bearer","expires_in":3600.0}`, 3600},
		{"float_string", `{"access_token":"at","token_type":"Bearer","expires_in":"3600.0"}`, 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got capturedRequest
			srv := newTokenServer(t, http.StatusOK, tc.body, &got)
			resp, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret", WithInsecureAllowHTTP())
			if err != nil {
				t.Fatalf("ClientCredentials: %v", err)
			}
			if resp.AccessToken != "at" {
				t.Errorf("access_token = %q, want at", resp.AccessToken)
			}
			if resp.ExpiresIn != tc.want {
				t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tc.want)
			}
		})
	}
}

// Extra params must not inject reserved client-auth parameters. On the Basic
// path client_id is absent from the body, so a guard keyed only on form.Has
// would let WithExtraParams smuggle a contradicting client_id. Regression.
func TestClientCredentials_ExtraParamsCannotInjectClientID(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithExtraParams(map[string]string{"client_id": "evil", "client_secret": "evil"}),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	// Basic-auth identity is authoritative; no client_id/client_secret in body.
	if got.form.Has("client_id") || got.form.Has("client_secret") {
		t.Errorf("reserved client-auth params injected into body: %v", got.form)
	}
	user, _, _ := parseBasicAuth(got.authHeader)
	if user != "cid" {
		t.Errorf("Basic auth user = %q, want cid", user)
	}
}

// A custom timeout bounds the request.
func TestTokenRequest_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(successBody))
	}))
	t.Cleanup(srv.Close)

	_, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithTimeout(20*time.Millisecond), WithInsecureAllowHTTP())
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
}

// markerTransport records whether it round-tripped a request.
type markerTransport struct {
	base http.RoundTripper
	used bool
}

func (m *markerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.used = true
	return m.base.RoundTrip(r)
}

// parseBasicAuth decodes an "Authorization: Basic" header into its username and
// password components.
func parseBasicAuth(header string) (user, pass string, ok bool) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", header)
	return r.BasicAuth()
}
