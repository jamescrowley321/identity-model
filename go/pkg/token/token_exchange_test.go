package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exchangeFixture reads a shared conformance fixture from
// spec/test-fixtures/token-exchange. The token exchange unit tests are driven by
// the same fixtures the conformance suite (token-exchange.json) references, so
// the Go behaviour and the cross-language contract cannot drift apart.
func exchangeFixture(t *testing.T, name string) string {
	t.Helper()
	// test file lives at go/pkg/token; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "token-exchange", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// EXCH-001: a basic (impersonation) exchange POSTs the token-exchange grant with
// only the subject token and parses the issued-token trio from the 200 response.
func TestTokenExchange_ImpersonationSuccess(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	resp, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if g := got.form.Get("grant_type"); g != grantTokenExchange {
		t.Errorf("grant_type = %q, want %q", g, grantTokenExchange)
	}
	if got.form.Get("subject_token") != "subject-tok" {
		t.Errorf("subject_token = %q", got.form.Get("subject_token"))
	}
	if got.form.Get("subject_token_type") != TokenTypeAccessToken {
		t.Errorf("subject_token_type = %q, want %q", got.form.Get("subject_token_type"), TokenTypeAccessToken)
	}
	// Impersonation carries no actor token.
	if got.form.Has("actor_token") || got.form.Has("actor_token_type") {
		t.Errorf("impersonation must not send actor token: %v", got.form)
	}
	if resp.AccessToken == "" {
		t.Errorf("empty access_token: %+v", resp)
	}
	if resp.IssuedTokenType != TokenTypeAccessToken {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, TokenTypeAccessToken)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 3600 {
		t.Errorf("token_type/expires_in = %q/%d", resp.TokenType, resp.ExpiresIn)
	}
}

// EXCH-002: a delegation exchange sends both the subject and actor tokens (with
// their types) in the request body.
func TestTokenExchange_Delegation(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-delegation-success.json"), &got)

	resp, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithActorToken("actor-tok", TokenTypeJWT), WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange delegation: %v", err)
	}
	if got.form.Get("subject_token") != "subject-tok" || got.form.Get("subject_token_type") != TokenTypeAccessToken {
		t.Errorf("subject token missing: %v", got.form)
	}
	if got.form.Get("actor_token") != "actor-tok" {
		t.Errorf("actor_token = %q, want actor-tok", got.form.Get("actor_token"))
	}
	if got.form.Get("actor_token_type") != TokenTypeJWT {
		t.Errorf("actor_token_type = %q, want %q", got.form.Get("actor_token_type"), TokenTypeJWT)
	}
	if resp.AccessToken == "" || resp.IssuedTokenType == "" {
		t.Errorf("response = %+v", resp)
	}
}

// EXCH-003: each of the six RFC 8693 §3 token type URIs is serialized verbatim
// as subject_token_type, with no abbreviation. Also asserts the exported
// constants exactly match the fixture-declared URI set.
func TestTokenExchange_AllTokenTypeURIsVerbatim(t *testing.T) {
	var fixtureURIs struct {
		URIs []string `json:"token_type_uris"`
	}
	if err := json.Unmarshal([]byte(exchangeFixture(t, "token-type-uris.json")), &fixtureURIs); err != nil {
		t.Fatalf("decode token-type-uris fixture: %v", err)
	}
	consts := []string{
		TokenTypeAccessToken, TokenTypeRefreshToken, TokenTypeIDToken,
		TokenTypeSAML1, TokenTypeSAML2, TokenTypeJWT,
	}
	if len(fixtureURIs.URIs) != len(consts) {
		t.Fatalf("fixture has %d URIs, package exports %d", len(fixtureURIs.URIs), len(consts))
	}
	for i, want := range fixtureURIs.URIs {
		if consts[i] != want {
			t.Errorf("constant[%d] = %q, want fixture URI %q", i, consts[i], want)
		}
	}

	for _, uri := range fixtureURIs.URIs {
		var got capturedRequest
		srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)
		_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
			"subject-tok", uri, WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("TokenExchange with %s: %v", uri, err)
		}
		if got.form.Get("subject_token_type") != uri {
			t.Errorf("subject_token_type = %q, want verbatim %q", got.form.Get("subject_token_type"), uri)
		}
	}
}

// EXCH-004: requested_token_type, audience, and resource are all sent in the
// request body; the response issued_token_type MAY differ from what was asked.
func TestTokenExchange_RequestedTypeAudienceResource(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithRequestedTokenType(TokenTypeAccessToken),
		WithAudience("https://api.example.com"),
		WithResource("https://rs.example.com"),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got.form.Get("requested_token_type") != TokenTypeAccessToken {
		t.Errorf("requested_token_type = %q", got.form.Get("requested_token_type"))
	}
	if got.form.Get("audience") != "https://api.example.com" {
		t.Errorf("audience = %q", got.form.Get("audience"))
	}
	if got.form.Get("resource") != "https://rs.example.com" {
		t.Errorf("resource = %q", got.form.Get("resource"))
	}
}

// EXCH-004 (repeatable params): resource and audience MAY each appear more than
// once (RFC 8693 §2.1); every value is sent as its own repeated parameter.
func TestTokenExchange_ResourceAudienceRepeat(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithResource("https://rs1.example.com", "https://rs2.example.com"),
		WithAudience("aud-a", "aud-b"),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if r := got.form["resource"]; len(r) != 2 || r[0] != "https://rs1.example.com" || r[1] != "https://rs2.example.com" {
		t.Errorf("resource = %v, want two repeated values", r)
	}
	if a := got.form["audience"]; len(a) != 2 || a[0] != "aud-a" || a[1] != "aud-b" {
		t.Errorf("audience = %v, want two repeated values", a)
	}
}

// EXCH-005: a successful response whose token_type is N_A (a non-bearer issued
// token, RFC 8693 §2.2.1) is parsed without error.
func TestTokenExchange_ParseNATokenType(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-n_a-token-type.json"), &got)

	resp, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange N_A: %v", err)
	}
	if resp.TokenType != "N_A" {
		t.Errorf("token_type = %q, want N_A", resp.TokenType)
	}
	if resp.IssuedTokenType != TokenTypeSAML2 {
		t.Errorf("issued_token_type = %q, want %q", resp.IssuedTokenType, TokenTypeSAML2)
	}
	if resp.AccessToken == "" {
		t.Errorf("empty access_token: %+v", resp)
	}
}

// EXCH-006: an HTTP 400 OAuth error body is surfaced as a typed TokenError.
func TestTokenExchange_ErrorResponse(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusBadRequest, exchangeFixture(t, "exchange-error-invalid-grant.json"), &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"expired-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error = %v, want *TokenError", err)
	}
	if te.Code != "invalid_grant" {
		t.Errorf("error code = %q, want invalid_grant", te.Code)
	}
	if te.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", te.StatusCode)
	}
	if !errors.Is(err, ErrTokenResponse) {
		t.Errorf("errors.Is(ErrTokenResponse) = false")
	}
}

// A missing subject_token is rejected locally before any request is sent
// (RFC 8693 §2.1 REQUIRED parameter).
func TestTokenExchange_MissingSubjectToken(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"", TokenTypeAccessToken, WithInsecureAllowHTTP())
	if !errors.Is(err, ErrInvalidTokenExchange) {
		t.Fatalf("error = %v, want ErrInvalidTokenExchange", err)
	}
	if got.method != "" {
		t.Errorf("no request should be sent for an empty subject_token")
	}
}

// A missing subject_token_type is rejected locally (RFC 8693 §2.1 REQUIRED).
func TestTokenExchange_MissingSubjectTokenType(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", "", WithInsecureAllowHTTP())
	if !errors.Is(err, ErrInvalidTokenExchange) {
		t.Fatalf("error = %v, want ErrInvalidTokenExchange", err)
	}
	if got.method != "" {
		t.Errorf("no request should be sent for an empty subject_token_type")
	}
}

// An actor_token without its actor_token_type is rejected locally: RFC 8693 §2.1
// makes actor_token_type REQUIRED whenever actor_token is present.
func TestTokenExchange_ActorTokenRequiresType(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithActorToken("actor-tok", ""), WithInsecureAllowHTTP())
	if !errors.Is(err, ErrInvalidTokenExchange) {
		t.Fatalf("error = %v, want ErrInvalidTokenExchange", err)
	}
	if got.method != "" {
		t.Errorf("no request should be sent when actor_token_type is missing")
	}
}

// WithExtraParams must not be able to override the identity-critical exchange
// parameters (subject_token, actor_token and their types).
func TestTokenExchange_ExtraParamsCannotOverrideIdentity(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-delegation-success.json"), &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithActorToken("actor-tok", TokenTypeJWT),
		WithExtraParams(map[string]string{
			"subject_token":      "evil-subject",
			"subject_token_type": "evil-type",
			"actor_token":        "evil-actor",
			"actor_token_type":   "evil-actor-type",
			"grant_type":         "evil-grant",
		}),
		WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got.form.Get("subject_token") != "subject-tok" || got.form.Get("subject_token_type") != TokenTypeAccessToken {
		t.Errorf("subject identity overridden: %v", got.form)
	}
	if got.form.Get("actor_token") != "actor-tok" || got.form.Get("actor_token_type") != TokenTypeJWT {
		t.Errorf("actor identity overridden: %v", got.form)
	}
	if got.form.Get("grant_type") != grantTokenExchange {
		t.Errorf("grant_type overridden to %q", got.form.Get("grant_type"))
	}
}

// The default client authentication is client_secret_basic; the credentials
// travel in a Basic header, absent from the body.
func TestTokenExchange_BasicAuthDefault(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	if _, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	user, _, ok := parseBasicAuth(got.authHeader)
	if !ok || user != "cid" {
		t.Errorf("Basic auth user = %q (ok=%v), want cid", user, ok)
	}
	if got.form.Has("client_id") || got.form.Has("client_secret") {
		t.Errorf("client creds must not appear in body with basic auth: %v", got.form)
	}
}

// WithClientAuth(ClientSecretPost) puts the credentials in the body, no Basic
// header.
func TestTokenExchange_PostAuth(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	if _, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithClientAuth(ClientSecretPost), WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got.authHeader != "" {
		t.Errorf("unexpected Authorization header with post auth: %q", got.authHeader)
	}
	if got.form.Get("client_id") != "cid" || got.form.Get("client_secret") != "secret" {
		t.Errorf("post creds missing from body: %v", got.form)
	}
}

// An https endpoint is required unless WithInsecureAllowHTTP is set.
func TestTokenExchange_HTTPSRequired(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken)
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("error = %v, want ErrRequest (https required)", err)
	}
	if got.method != "" {
		t.Errorf("request should not have reached an http endpoint")
	}
}

// A 2xx exchange response missing the required access_token is a RequestError,
// not a silently-empty success (RFC 8693 §2.2 REQUIRES access_token).
func TestTokenExchange_MissingAccessToken(t *testing.T) {
	var got capturedRequest
	body := `{"issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}`
	srv := newTokenServer(t, http.StatusOK, body, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want *RequestError", err)
	}
}

// A 200 that omits issued_token_type is non-conformant (RFC 8693 §2.2 REQUIRES
// it); the exchange rejects it rather than returning an empty IssuedTokenType.
func TestTokenExchange_MissingIssuedTokenType(t *testing.T) {
	var got capturedRequest
	body := `{"access_token":"issued-tok","token_type":"Bearer"}`
	srv := newTokenServer(t, http.StatusOK, body, &got)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want *RequestError for missing issued_token_type", err)
	}
}

// An oversized response body is rejected rather than buffered without bound
// (memory-exhaustion guard, maxBodyBytes).
func TestTokenExchange_OversizedBody(t *testing.T) {
	huge := `{"access_token":"` + strings.Repeat("a", (1<<20)+16) + `"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(huge))
	}))
	t.Cleanup(srv.Close)

	_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want *RequestError for oversized body", err)
	}
}

// A 200 response is rejected unless it carries a non-empty token_type: RFC 6749
// §5.1 makes it REQUIRED and RFC 8693 §2.2.1 restates it for the exchange, where
// its value is also the bearer test (token_type != "N_A"). Without the guard a
// non-bearer credential returned with no token_type would be sent as a Bearer
// token. Matches the Python reference, which rejects a missing/empty token_type.
func TestTokenExchange_RejectsMissingTokenType(t *testing.T) {
	const issued = `"issued_token_type":"urn:ietf:params:oauth:token-type:access_token"`
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "token_type absent",
			body:    `{"access_token":"issued-tok",` + issued + `}`,
			wantErr: true,
		},
		{
			name:    "token_type empty string",
			body:    `{"access_token":"issued-tok","token_type":"",` + issued + `}`,
			wantErr: true,
		},
		{
			name:    "token_type null",
			body:    `{"access_token":"issued-tok","token_type":null,` + issued + `}`,
			wantErr: true,
		},
		{
			name:    "token_type present",
			body:    `{"access_token":"issued-tok","token_type":"Bearer",` + issued + `}`,
			wantErr: false,
		},
		{
			name:    "token_type N_A is a value, not an absence",
			body:    `{"access_token":"issued-tok","token_type":"N_A",` + issued + `}`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got capturedRequest
			srv := newTokenServer(t, http.StatusOK, tt.body, &got)

			resp, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
				"subject-tok", TokenTypeAccessToken, WithInsecureAllowHTTP())
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("TokenExchange: %v", err)
				}
				if resp.TokenType == "" {
					t.Errorf("token_type = %q, want the response value", resp.TokenType)
				}
				return
			}
			var re *RequestError
			if !errors.As(err, &re) {
				t.Fatalf("error = %v, want *RequestError for missing token_type", err)
			}
			// "missing issued_token_type" also contains "token_type", so assert the
			// exact message to prove which guard fired.
			const wantMsg = "missing token_type"
			if re.Err == nil || re.Err.Error() != wantMsg {
				t.Errorf("error = %v, want %q", re.Err, wantMsg)
			}
			if resp != nil {
				t.Errorf("response = %+v, want nil on rejection", resp)
			}
		})
	}
}

// A supplied-but-empty actor token is a caller error, not a request for
// impersonation. Dropping it from the form would silently downgrade delegation
// to impersonation (RFC 8693 §1.1), so it is rejected locally before any request
// is sent. Matches the Python reference ("actor_token must not be empty when
// provided"). Omitting WithActorToken entirely is how impersonation is asked for.
func TestTokenExchange_SuppliedEmptyActorTokenRejected(t *testing.T) {
	tests := []struct {
		name       string
		opts       []Option
		wantErr    bool
		wantActor  string
		wantTyp    string
		wantNoPair bool
	}{
		{
			name:    "empty actor token with a type",
			opts:    []Option{WithActorToken("", TokenTypeJWT)},
			wantErr: true,
		},
		{
			name:    "empty actor token and empty type",
			opts:    []Option{WithActorToken("", "")},
			wantErr: true,
		},
		{
			name:    "actor token without a type",
			opts:    []Option{WithActorToken("actor-tok", "")},
			wantErr: true,
		},
		{
			name:      "both supplied",
			opts:      []Option{WithActorToken("actor-tok", TokenTypeJWT)},
			wantActor: "actor-tok",
			wantTyp:   TokenTypeJWT,
		},
		{
			name:       "option omitted requests impersonation",
			opts:       nil,
			wantNoPair: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got capturedRequest
			srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-delegation-success.json"), &got)

			opts := append([]Option{}, tt.opts...)
			opts = append(opts, WithInsecureAllowHTTP())
			_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
				"subject-tok", TokenTypeAccessToken, opts...)

			if tt.wantErr {
				if !errors.Is(err, ErrInvalidTokenExchange) {
					t.Fatalf("error = %v, want ErrInvalidTokenExchange", err)
				}
				if got.method != "" {
					t.Errorf("no request must be sent for an invalid actor token, got %s with form %v", got.method, got.form)
				}
				return
			}
			if err != nil {
				t.Fatalf("TokenExchange: %v", err)
			}
			if tt.wantNoPair {
				if got.form.Has("actor_token") || got.form.Has("actor_token_type") {
					t.Errorf("impersonation must not send an actor pair: %v", got.form)
				}
				return
			}
			if got.form.Get("actor_token") != tt.wantActor {
				t.Errorf("actor_token = %q, want %q", got.form.Get("actor_token"), tt.wantActor)
			}
			if got.form.Get("actor_token_type") != tt.wantTyp {
				t.Errorf("actor_token_type = %q, want %q", got.form.Get("actor_token_type"), tt.wantTyp)
			}
		})
	}
}

// On the exchange path resource, audience and requested_token_type are sourced
// from the exchange's own options, so a colliding WithExtraParams key is
// rejected before the request is built rather than dropped from the form.
// Dropping it would convert an injection attempt into the silent loss of a
// restriction: the pinned rows below would send no targeting at all, get a 200,
// and hand back a token broader than the caller asked for with no signal.
func TestTokenExchange_ExtraParamsCannotSetTargeting(t *testing.T) {
	tests := []struct {
		name string
		key  string
		evil string
		pin  Option
	}{
		{
			name: "requested_token_type unpinned",
			key:  "requested_token_type",
			evil: TokenTypeRefreshToken,
		},
		{
			name: "requested_token_type pinned",
			key:  "requested_token_type",
			evil: TokenTypeRefreshToken,
			pin:  WithRequestedTokenType(TokenTypeAccessToken),
		},
		{
			name: "audience unpinned",
			key:  "audience",
			evil: "https://evil.example.com",
		},
		{
			name: "audience pinned",
			key:  "audience",
			evil: "https://evil.example.com",
			pin:  WithAudience("https://api.example.com"),
		},
		{
			name: "resource unpinned",
			key:  "resource",
			evil: "https://evil.example.com",
		},
		{
			name: "resource pinned",
			key:  "resource",
			evil: "https://evil.example.com",
			pin:  WithResource("https://rs.example.com"),
		},
		// Reservation is enforced on the normalized key: an authorization server
		// whose form parser folds case or trims surrounding whitespace (ASP.NET
		// IFormCollection, Duende IdentityServer) would read these as the reserved
		// parameter itself, so a byte-exact guard would let them through.
		{
			name: "audience mixed case",
			key:  "Audience",
			evil: "https://evil.example.com",
		},
		{
			name: "audience leading space",
			key:  " audience",
			evil: "https://evil.example.com",
		},
		{
			name: "requested_token_type upper case",
			key:  "REQUESTED_TOKEN_TYPE",
			evil: TokenTypeRefreshToken,
		},
		{
			name: "resource trailing space, pinned",
			key:  "resource ",
			evil: "https://evil.example.com",
			pin:  WithResource("https://rs.example.com"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got capturedRequest
			srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

			opts := []Option{WithExtraParams(map[string]string{tt.key: tt.evil}), WithInsecureAllowHTTP()}
			if tt.pin != nil {
				opts = append([]Option{tt.pin}, opts...)
			}
			resp, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
				"subject-tok", TokenTypeAccessToken, opts...)

			if !errors.Is(err, ErrInvalidTokenExchange) {
				t.Fatalf("error = %v, want ErrInvalidTokenExchange for extra param %q", err, tt.key)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error %q does not name the offending key %q", err, tt.key)
			}
			if resp != nil {
				t.Errorf("response = %+v, want nil on rejection", resp)
			}
			if got.method != "" {
				t.Errorf("no request must be sent for a reserved extra param, got %s with form %v", got.method, got.form)
			}
		})
	}
}

// When several extras collide the rejection must name a stable key: Go map
// iteration order is randomized, so the keys are sorted and the lowest is
// reported. Repeated to make an unsorted implementation fail reliably.
func TestTokenExchange_ExtraParamsCollisionErrorIsStable(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	const want = "token: invalid token exchange request: audience must be set via its option " +
		"(WithResource/WithAudience/WithRequestedTokenType), not WithExtraParams"
	for i := 0; i < 50; i++ {
		_, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
			"subject-tok", TokenTypeAccessToken,
			WithExtraParams(map[string]string{
				"resource":             "https://evil.example.com",
				"audience":             "https://evil.example.com",
				"requested_token_type": TokenTypeRefreshToken,
			}), WithInsecureAllowHTTP())
		if !errors.Is(err, ErrInvalidTokenExchange) {
			t.Fatalf("error = %v, want ErrInvalidTokenExchange", err)
		}
		if err.Error() != want {
			t.Fatalf("iteration %d: error = %q, want %q", i, err, want)
		}
	}
}

// A non-reserved extra param must still reach the exchange request. The
// reservation is keyed on three specific parameters, not a blanket drop of every
// extra on this grant: an over-broad implementation would discard every
// provider-specific extension on an exchange and no other test would notice.
func TestTokenExchange_NonReservedExtraParamsReachRequest(t *testing.T) {
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, exchangeFixture(t, "exchange-impersonation-success.json"), &got)

	extras := map[string]string{"tenant": "t1", "acr_values": "mfa"}
	if _, err := TokenExchange(context.Background(), srv.URL, "cid", "secret",
		"subject-tok", TokenTypeAccessToken,
		WithExtraParams(extras), WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	for k, want := range extras {
		if g := got.form.Get(k); g != want {
			t.Errorf("%s = %q, want %q on the exchange request", k, g, want)
		}
	}
}

// The exchange-path reservation is scoped to the exchange: a grant with no
// option of its own for these keys may still set them via WithExtraParams (e.g.
// an RFC 8707 resource on the client credentials grant). Regression guard for
// the rationale the exchange-only split preserves.
func TestClientCredentials_ExtraParamsCanSetTargeting(t *testing.T) {
	extras := map[string]string{
		"resource":             "https://api.example.com",
		"audience":             "https://aud.example.com",
		"requested_token_type": TokenTypeAccessToken,
	}
	var got capturedRequest
	srv := newTokenServer(t, http.StatusOK, successBody, &got)

	if _, err := ClientCredentials(context.Background(), srv.URL, "cid", "secret",
		WithExtraParams(extras), WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	for k, want := range extras {
		if g := got.form.Get(k); g != want {
			t.Errorf("%s = %q, want %q on the client credentials grant", k, g, want)
		}
	}
}
