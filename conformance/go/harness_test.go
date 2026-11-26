package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	testClientID     = "conformance-rp"
	testClientSecret = "conformance-rp-secret"
	testSub          = "user-1"
)

// signingKey is one RSA key the fake OP publishes and may sign with.
type signingKey struct {
	kid  string
	priv *rsa.PrivateKey
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signingKey{kid: kid, priv: priv}
}

// fakeOP is a minimal OpenID Provider standing in for the OIDF suite: it serves
// discovery, a JWKS, a token endpoint (client_secret_basic) and UserInfo, and
// lets each test mutate the ID Token it issues.
type fakeOP struct {
	t   *testing.T
	srv *httptest.Server

	mu              sync.Mutex
	discoveryIssuer string // "" = the real issuer
	published       []signingKey
	signer          *signingKey // nil = alg none
	omitKid         bool
	mutate          func(claims map[string]any)
	userinfoSub     string
	nonces          map[string]string // code -> nonce
	jwksFetches     int
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	op := &fakeOP{t: t, nonces: map[string]string{}, userinfoSub: testSub}
	key := newSigningKey(t, "k1")
	op.published = []signingKey{key}
	op.signer = &key
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", op.discovery)
	mux.HandleFunc("GET /jwks", op.jwks)
	mux.HandleFunc("POST /token", op.token)
	mux.HandleFunc("GET /userinfo", op.userinfo)
	op.srv = httptest.NewTLSServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

func (op *fakeOP) issuer() string { return op.srv.URL }

func (op *fakeOP) discovery(w http.ResponseWriter, _ *http.Request) {
	op.mu.Lock()
	iss := op.discoveryIssuer
	op.mu.Unlock()
	if iss == "" {
		iss = op.issuer()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                op.issuer() + "/authorize",
		"token_endpoint":                        op.issuer() + "/token",
		"userinfo_endpoint":                     op.issuer() + "/userinfo",
		"jwks_uri":                              op.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (op *fakeOP) jwks(w http.ResponseWriter, _ *http.Request) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.jwksFetches++
	set := jose.JSONWebKeySet{}
	for _, k := range op.published {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "RS256", Use: "sig"})
	}
	writeJSON(w, http.StatusOK, set)
}

func (op *fakeOP) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != testClientID || secret != testClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	op.mu.Lock()
	nonce, known := op.nonces[r.PostForm.Get("code")]
	op.mu.Unlock()
	if !known {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": op.issuer(), "sub": testSub, "aud": testClientID,
		"iat": now, "exp": now + 300, "nonce": nonce,
	}
	op.mu.Lock()
	if op.mutate != nil {
		op.mutate(claims)
	}
	idToken := op.sign(claims)
	op.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-1", "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	})
}

// sign is called with op.mu held.
func (op *fakeOP) sign(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		op.t.Fatalf("marshal claims: %v", err)
	}
	if op.signer == nil {
		head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		return head + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	}
	var key any = jose.JSONWebKey{Key: op.signer.priv, KeyID: op.signer.kid}
	if op.omitKid {
		key = op.signer.priv
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		op.t.Fatalf("signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		op.t.Fatalf("sign: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		op.t.Fatalf("serialize: %v", err)
	}
	return out
}

func (op *fakeOP) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer at-1" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	op.mu.Lock()
	sub := op.userinfoSub
	op.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"sub": sub, "email": "user@example.com"})
}

func (op *fakeOP) set(f func(op *fakeOP)) {
	op.mu.Lock()
	defer op.mu.Unlock()
	f(op)
}

// rig is a harness under test wired to a fake OP.
type rig struct {
	t      *testing.T
	op     *fakeOP
	rp     *httptest.Server
	logDir string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	op := newFakeOP(t)
	logDir := t.TempDir()
	client := op.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h := newServer(serverConfig{
		rpBaseURL:       "http://rp.test",
		opFacingBaseURL: "http://rp.test",
		logDir:          logDir,
		httpClient:      client,
	})
	rp := httptest.NewServer(h.routes())
	t.Cleanup(rp.Close)
	return &rig{t: t, op: op, rp: rp, logDir: logDir}
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (rg *rig) get(path string, q url.Values) *http.Response {
	rg.t.Helper()
	u := rg.rp.URL + path
	if q != nil {
		u += "?" + q.Encode()
	}
	resp, err := noRedirect.Get(u)
	if err != nil {
		rg.t.Fatalf("GET %s: %v", path, err)
	}
	rg.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func authorizeParams(issuer, testID, testName string) url.Values {
	return url.Values{
		"issuer": {issuer}, "client_id": {testClientID}, "client_secret": {testClientSecret},
		"test_id": {testID}, "test_name": {testName}, "profile": {"basic-rp"},
		"use_pkce": {"false"}, "skip_userinfo": {"false"}, "use_request_uri": {"false"},
		"fapi2": {"false"}, "jarm": {"false"}, "mtls": {"false"}, "signed_request": {"false"},
	}
}

// authorize drives /authorize and returns the OP authorization request params.
func (rg *rig) authorize(testID string, extra url.Values) url.Values {
	rg.t.Helper()
	q := authorizeParams(rg.op.issuer(), testID, testID)
	for k, v := range extra {
		q[k] = v
	}
	resp := rg.get("/authorize", q)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		rg.t.Fatalf("/authorize status %d: %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		rg.t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != rg.op.issuer()+"/authorize" {
		rg.t.Fatalf("redirected to %q, want the OP authorization endpoint", got)
	}
	return loc.Query()
}

// login runs a full flow: /authorize, the OP issuing a code, then /callback.
func (rg *rig) login(testID string) *http.Response {
	rg.t.Helper()
	params := rg.authorize(testID, nil)
	code := "code-" + testID
	rg.op.set(func(op *fakeOP) { op.nonces[code] = params.Get("nonce") })
	return rg.get("/callback", url.Values{"code": {code}, "state": {params.Get("state")}})
}

func (rg *rig) result(testID string) (int, map[string]any) {
	rg.t.Helper()
	resp := rg.get("/results/"+testID, nil)
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		rg.t.Fatalf("decode result: %v", err)
	}
	return resp.StatusCode, body
}

func (rg *rig) wantResult(testID string, want map[string]any) {
	rg.t.Helper()
	status, got := rg.result(testID)
	if status != http.StatusOK {
		rg.t.Fatalf("/results/%s status %d, body %v", testID, status, got)
	}
	if reason, ok := got["error"].(string); ok {
		// Compare the reason class (the text before the first colon) exactly;
		// the detail after it is for humans.
		got["error"] = strings.SplitN(reason, ":", 2)[0]
	}
	if !reflect.DeepEqual(got, want) {
		rg.t.Fatalf("/results/%s = %v, want %v", testID, got, want)
	}
}

func success(testID string) map[string]any {
	return map[string]any{"test_id": testID, "status": "success"}
}

func rejected(testID, reason string) map[string]any {
	return map[string]any{"test_id": testID, "status": "error", "error": reason}
}

func TestHealth(t *testing.T) {
	rg := newRig(t)
	resp := rg.get("/health", nil)
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]any{"status": "ok", "service": "conformance-rp-go", "op_facing_base_url": "http://rp.test"}
	if resp.StatusCode != http.StatusOK || !reflect.DeepEqual(body, want) {
		t.Fatalf("/health = %d %v, want 200 %v", resp.StatusCode, body, want)
	}
}

func TestResultsNotFound(t *testing.T) {
	rg := newRig(t)
	status, _ := rg.result("never-run")
	if status != http.StatusNotFound {
		t.Fatalf("status %d, want 404", status)
	}
}

func TestAuthorizeSendsStateNonceAndRedirectURI(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-auth", nil)
	for _, name := range []string{"state", "nonce"} {
		if len(params.Get(name)) < 32 {
			t.Fatalf("%s %q is too short", name, params.Get(name))
		}
	}
	want := map[string]string{
		"response_type": "code", "client_id": testClientID,
		"redirect_uri": "http://rp.test/callback", "scope": "openid profile email address phone",
	}
	for name, value := range want {
		if params.Get(name) != value {
			t.Fatalf("%s = %q, want %q", name, params.Get(name), value)
		}
	}
	if params.Has("code_challenge") {
		t.Fatalf("code_challenge sent without use_pkce")
	}
	status, _ := rg.result("t-auth")
	if status != http.StatusNotFound {
		t.Fatalf("a flow that has not reached the callback recorded a result (status %d)", status)
	}
}

func TestAuthorizePKCE(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-pkce", url.Values{"use_pkce": {"true"}})
	if params.Get("code_challenge_method") != "S256" || params.Get("code_challenge") == "" {
		t.Fatalf("PKCE params missing: %v", params)
	}
}

func TestAuthorizeRefusesUnsupportedFlows(t *testing.T) {
	rg := newRig(t)
	for _, flag := range []string{"fapi2", "jarm", "mtls", "signed_request", "use_request_uri"} {
		q := authorizeParams(rg.op.issuer(), "t-"+flag, "t-"+flag)
		q.Set(flag, "true")
		if resp := rg.get("/authorize", q); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s=true: status %d, want 400", flag, resp.StatusCode)
		}
	}
}

func TestLoginAccepted(t *testing.T) {
	rg := newRig(t)
	resp := rg.login("t-ok")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "user@example.com") {
		t.Fatalf("callback page does not show the UserInfo claims: %s", body)
	}
	rg.wantResult("t-ok", success("t-ok"))
}

func TestLoginRejections(t *testing.T) {
	cases := map[string]struct {
		setup  func(op *fakeOP)
		status int
		reason string
	}{
		"invalid-iss": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["iss"] = "https://evil.example" }
		}, status: http.StatusBadRequest, reason: reasonInvalidIssuer},
		"invalid-aud": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["aud"] = "someone-else" }
		}, status: http.StatusBadRequest, reason: reasonInvalidAudience},
		"missing-iat": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { delete(c, "iat") }
		}, status: http.StatusBadRequest, reason: reasonInvalidIssuedAt},
		"missing-sub": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { delete(c, "sub") }
		}, status: http.StatusBadRequest, reason: reasonInvalidSubject},
		"nonce-invalid": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["nonce"] = "not-the-nonce" }
		}, status: http.StatusBadRequest, reason: reasonNonceMismatch},
		"idtoken-sig-none": {setup: func(op *fakeOP) { op.signer = nil },
			status: http.StatusBadRequest, reason: reasonAlgNone},
		"invalid-sig-rs256": {setup: func(op *fakeOP) {
			// Signed by a key that is not published, under a published kid.
			rogue := newSigningKey(op.t, op.published[0].kid)
			op.signer = &rogue
		}, status: http.StatusBadRequest, reason: reasonInvalidSignature},
		"kid-absent-multiple-jwks": {setup: func(op *fakeOP) {
			op.published = append(op.published, newSigningKey(op.t, "k2"))
			op.omitKid = true
		}, status: http.StatusBadRequest, reason: reasonKeySelection},
		"userinfo-invalid-sub": {setup: func(op *fakeOP) { op.userinfoSub = "someone-else" },
			status: http.StatusBadRequest, reason: reasonUserInfoValidation},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rg := newRig(t)
			rg.op.set(tc.setup)
			resp := rg.login(name)
			if resp.StatusCode != tc.status {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("callback status %d, want %d: %s", resp.StatusCode, tc.status, body)
			}
			rg.wantResult(name, rejected(name, tc.reason))
		})
	}
}

func TestKidAbsentSingleKeyAccepted(t *testing.T) {
	rg := newRig(t)
	rg.op.set(func(op *fakeOP) { op.omitKid = true })
	if resp := rg.login("t-kidless"); resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", resp.StatusCode)
	}
	rg.wantResult("t-kidless", success("t-kidless"))
}

func TestSkipUserInfo(t *testing.T) {
	rg := newRig(t)
	rg.op.set(func(op *fakeOP) { op.userinfoSub = "someone-else" })
	params := rg.authorize("t-skip", url.Values{"skip_userinfo": {"true"}})
	rg.op.set(func(op *fakeOP) { op.nonces["c"] = params.Get("nonce") })
	resp := rg.get("/callback", url.Values{"code": {"c"}, "state": {params.Get("state")}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", resp.StatusCode)
	}
	rg.wantResult("t-skip", success("t-skip"))
}

func TestFormPostCallback(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-form", nil)
	rg.op.set(func(op *fakeOP) { op.nonces["c"] = params.Get("nonce") })
	form := url.Values{"code": {"c"}, "state": {params.Get("state")}}
	resp, err := http.PostForm(rg.rp.URL+"/callback", form)
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", resp.StatusCode)
	}
	rg.wantResult("t-form", success("t-form"))
}

func TestUnknownStateFiledUnderLastFlow(t *testing.T) {
	rg := newRig(t)
	rg.authorize("t-state", nil)
	resp := rg.get("/callback", url.Values{"code": {"c"}, "state": {"forged"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	rg.wantResult("t-state", rejected("t-state", reasonStateValidation))
}

func TestStateIsSingleUse(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-replay", nil)
	rg.op.set(func(op *fakeOP) { op.nonces["c"] = params.Get("nonce") })
	cb := url.Values{"code": {"c"}, "state": {params.Get("state")}}
	if resp := rg.get("/callback", cb); resp.StatusCode != http.StatusOK {
		t.Fatalf("first callback status %d", resp.StatusCode)
	}
	if resp := rg.get("/callback", cb); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status %d, want 400", resp.StatusCode)
	}
	// A rejection after a recorded success cannot turn the verdict into a pass.
	rg.wantResult("t-replay", map[string]any{"test_id": "t-replay", "status": "conflict", "error": reasonStateValidation})
}

func TestOPErrorResponse(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-operr", nil)
	resp := rg.get("/callback", url.Values{"error": {"access_denied"}, "state": {params.Get("state")}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	rg.wantResult("t-operr", rejected("t-operr", "access_denied"))
}

func TestDiscoverIssuerMismatch(t *testing.T) {
	rg := newRig(t)
	rg.op.set(func(op *fakeOP) { op.discoveryIssuer = "https://other.example" })
	q := url.Values{"issuer": {rg.op.issuer()}, "test_id": {"t-mm"}, "test_name": {"t-mm"}, "profile": {"config-rp"}}
	if resp := rg.get("/discover", q); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	rg.wantResult("t-mm", rejected("t-mm", reasonIssuerMismatch))
}

func TestAuthorizeIssuerMismatch(t *testing.T) {
	rg := newRig(t)
	rg.op.set(func(op *fakeOP) { op.discoveryIssuer = "https://other.example" })
	if resp := rg.get("/authorize", authorizeParams(rg.op.issuer(), "t-amm", "t-amm")); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	rg.wantResult("t-amm", rejected("t-amm", reasonIssuerMismatch))
}

func TestDiscoverAccepted(t *testing.T) {
	rg := newRig(t)
	q := url.Values{"issuer": {rg.op.issuer()}, "test_id": {"t-disc"}, "test_name": {"t-disc"}, "profile": {"config-rp"}}
	if resp := rg.get("/discover", q); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	rg.wantResult("t-disc", success("t-disc"))
}

// The signing-key-rotation module logs in twice and rotates the OP key in
// between: the second login must refresh the cached JWKS on the unknown kid.
func TestKeyRotationRefreshesCachedJWKS(t *testing.T) {
	rg := newRig(t)
	if resp := rg.login("t-rot"); resp.StatusCode != http.StatusOK {
		t.Fatalf("first login status %d", resp.StatusCode)
	}
	rg.op.set(func(op *fakeOP) {
		next := newSigningKey(op.t, "k2")
		op.published = []signingKey{next}
		op.signer = &next
	})
	if resp := rg.login("t-rot"); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("second login status %d: %s", resp.StatusCode, body)
	}
	rg.wantResult("t-rot", success("t-rot"))
	var fetches int
	rg.op.set(func(op *fakeOP) { fetches = op.jwksFetches })
	if fetches != 2 {
		t.Fatalf("JWKS fetched %d times, want 2 (cached, then one refresh on the new kid)", fetches)
	}
}

func TestClearCache(t *testing.T) {
	rg := newRig(t)
	resp, err := http.Post(rg.rp.URL+"/clear-cache", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /clear-cache: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestPerTestLogWritten(t *testing.T) {
	rg := newRig(t)
	rg.login("oidcc-client-test")
	data, err := os.ReadFile(filepath.Join(rg.logDir, "basic-rp", "oidcc-client-test.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "ACCEPTED") {
		t.Fatalf("log has no ACCEPTED line:\n%s", data)
	}
}
