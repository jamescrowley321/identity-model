package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
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

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
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
	// endpoints overrides discovery metadata members by name.
	endpoints    map[string]string
	published    []signingKey
	signer       *signingKey // nil = alg none
	omitKid      bool
	mutate       func(claims map[string]any)
	userinfoSub  string
	nonces       map[string]string // code -> nonce
	jwksFetches  int
	discoFetches int
	// tokenHook, when set, runs at the start of every token request, outside
	// op.mu, so a test can hold a callback on the token endpoint.
	tokenHook func()
	// tokenType, when set, replaces token_type "Bearer"; noTokenType omits it.
	tokenType   string
	noTokenType bool
	// signAlg, when set, replaces RS256 as the signing alg; jwkNoAlg
	// publishes the keys without an "alg" member.
	signAlg  jose.SignatureAlgorithm
	jwkNoAlg bool
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
	op.discoFetches++
	iss := op.discoveryIssuer
	overrides := maps.Clone(op.endpoints)
	op.mu.Unlock()
	if iss == "" {
		iss = op.issuer()
	}
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                op.issuer() + "/authorize",
		"token_endpoint":                        op.issuer() + "/token",
		"userinfo_endpoint":                     op.issuer() + "/userinfo",
		"jwks_uri":                              op.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	for k, v := range overrides {
		doc[k] = v
	}
	writeJSON(w, http.StatusOK, doc)
}

func (op *fakeOP) jwks(w http.ResponseWriter, _ *http.Request) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.jwksFetches++
	set := jose.JSONWebKeySet{}
	alg := "RS256"
	if op.jwkNoAlg {
		alg = ""
	}
	for _, k := range op.published {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: alg, Use: "sig"})
	}
	writeJSON(w, http.StatusOK, set)
}

func (op *fakeOP) token(w http.ResponseWriter, r *http.Request) {
	op.mu.Lock()
	hook := op.tokenHook
	op.mu.Unlock()
	if hook != nil {
		hook()
	}
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
	body := map[string]any{
		"access_token": "at-1", "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
	}
	if op.tokenType != "" {
		body["token_type"] = op.tokenType
	}
	if op.noTokenType {
		delete(body, "token_type")
	}
	op.mu.Unlock()
	writeJSON(w, http.StatusOK, body)
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
	alg := jose.RS256
	if op.signAlg != "" {
		alg = op.signAlg
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
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
	return newRigWith(t, nil)
}

// newRigWith is newRig with configure applied to the harness config; it gets
// the fake OP so it can refer to the OP's issuer.
func newRigWith(t *testing.T, configure func(cfg *serverConfig, op *fakeOP)) *rig {
	t.Helper()
	// The library's discovery and JWKS caches are process-wide and keyed by
	// URL; httptest reuses ports, so a test could otherwise read an earlier
	// test's cached document or keys.
	discovery.ClearCache()
	jwks.ClearCache()
	t.Cleanup(func() {
		discovery.ClearCache()
		jwks.ClearCache()
	})
	op := newFakeOP(t)
	logDir := t.TempDir()
	client := op.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg := serverConfig{
		rpBaseURL:       "http://rp.test",
		opFacingBaseURL: "http://rp.test",
		logDir:          logDir,
		httpClient:      client,
	}
	if configure != nil {
		configure(&cfg, op)
	}
	h := newServer(cfg)
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
		"at-hash-mismatch": {setup: func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["at_hash"] = atHash("some-other-access-token") }
		}, status: http.StatusBadRequest, reason: reasonInvalidAtHash},
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

// atHash is the OIDC Core §3.3.2.11 at_hash of accessToken under RS256.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// A token-endpoint ID Token may omit at_hash (§3.1.3.6); one that carries it
// must match the access token returned with it.
func TestAtHashMatchingAccepted(t *testing.T) {
	rg := newRig(t)
	rg.op.set(func(op *fakeOP) {
		op.mutate = func(c map[string]any) { c["at_hash"] = atHash("at-1") }
	})
	if resp := rg.login("t-athash"); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback status %d: %s", resp.StatusCode, body)
	}
	rg.wantResult("t-athash", success("t-athash"))
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
	// The rejection is in that test's rp-log, where its reason is checked.
	data, err := os.ReadFile(filepath.Join(rg.logDir, "basic-rp", "t-state.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "REJECTED: "+reasonStateValidation) {
		t.Fatalf("log has no state_validation rejection:\n%s", data)
	}
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

// A replay that arrives while the original callback is still waiting on the
// OP is rejected; the original callback's later success must not erase that
// rejection, so the test's verdict is a conflict in this order too.
func TestReplayDuringPendingCallbackIsConflict(t *testing.T) {
	rg := newRig(t)
	params := rg.authorize("t-race", nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	rg.op.set(func(op *fakeOP) {
		op.nonces["c"] = params.Get("nonce")
		op.tokenHook = func() {
			once.Do(func() { close(entered) })
			<-release
		}
	})
	cb := url.Values{"code": {"c"}, "state": {params.Get("state")}}

	first := make(chan int, 1)
	go func() {
		resp, err := noRedirect.Get(rg.rp.URL + "/callback?" + cb.Encode())
		if err != nil {
			first <- 0
			return
		}
		_ = resp.Body.Close()
		first <- resp.StatusCode
	}()
	<-entered
	if resp := rg.get("/callback", cb); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status %d, want 400", resp.StatusCode)
	}
	close(release)
	if status := <-first; status != http.StatusOK {
		t.Fatalf("original callback status %d, want 200", status)
	}
	rg.wantResult("t-race", map[string]any{"test_id": "t-race", "status": "conflict", "error": reasonStateValidation})
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

// allowOnly restricts the harness to origin's issuers.
func allowOnly(origin string) func(cfg *serverConfig, _ *fakeOP) {
	return func(cfg *serverConfig, _ *fakeOP) { cfg.allowedIssuerOrigins = []string{origin} }
}

func TestIssuerAllowlist(t *testing.T) {
	t.Run("discover refuses an issuer outside the allowlist", func(t *testing.T) {
		rg := newRigWith(t, allowOnly("https://suite.example"))
		q := url.Values{"issuer": {rg.op.issuer()}, "test_id": {"t-deny"}, "test_name": {"t-deny"}, "profile": {"config-rp"}}
		if resp := rg.get("/discover", q); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", resp.StatusCode)
		}
		rg.wantResult("t-deny", rejected("t-deny", reasonIssuerNotAllowed))
		rg.op.mu.Lock()
		fetches := rg.op.discoFetches
		rg.op.mu.Unlock()
		if fetches != 0 {
			t.Fatalf("OP contacted %d times, want none", fetches)
		}
	})
	t.Run("authorize refuses an issuer outside the allowlist", func(t *testing.T) {
		rg := newRigWith(t, allowOnly("https://suite.example"))
		if resp := rg.get("/authorize", authorizeParams(rg.op.issuer(), "t-adeny", "t-adeny")); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", resp.StatusCode)
		}
		rg.wantResult("t-adeny", rejected("t-adeny", reasonIssuerNotAllowed))
	})
	t.Run("an allowlisted issuer logs in", func(t *testing.T) {
		rg := newRigWith(t, func(cfg *serverConfig, op *fakeOP) {
			cfg.allowedIssuerOrigins = []string{"https://suite.example", op.issuer()}
		})
		if resp := rg.login("t-allow"); resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("callback status %d: %s", resp.StatusCode, body)
		}
		rg.wantResult("t-allow", success("t-allow"))
	})
	for _, member := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		t.Run("refuses a discovered "+member+" outside the allowlist", func(t *testing.T) {
			rg := newRigWith(t, func(cfg *serverConfig, op *fakeOP) {
				cfg.allowedIssuerOrigins = []string{op.issuer()}
				op.endpoints = map[string]string{member: "https://evil.example/" + member}
			})
			id := "t-ep-" + member
			if resp := rg.get("/discover", url.Values{"issuer": {rg.op.issuer()}, "test_id": {id}, "test_name": {id}, "profile": {"config-rp"}}); resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("discover status %d, want 502", resp.StatusCode)
			}
			rg.wantResult(id, rejected(id, reasonIssuerNotAllowed))
			aid := id + "-authz"
			if resp := rg.get("/authorize", authorizeParams(rg.op.issuer(), aid, aid)); resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("authorize status %d, want 502", resp.StatusCode)
			}
			rg.wantResult(aid, rejected(aid, reasonIssuerNotAllowed))
		})
	}
	t.Run("an empty allowlist follows off-origin endpoints", func(t *testing.T) {
		rg := newRigWith(t, func(_ *serverConfig, op *fakeOP) {
			op.endpoints = map[string]string{"userinfo_endpoint": "https://evil.example/userinfo"}
		})
		q := url.Values{"issuer": {rg.op.issuer()}, "test_id": {"t-open"}, "test_name": {"t-open"}, "profile": {"config-rp"}}
		if resp := rg.get("/discover", q); resp.StatusCode != http.StatusOK {
			t.Fatalf("discover status %d, want 200", resp.StatusCode)
		}
		rg.wantResult("t-open", success("t-open"))
	})
	t.Run("an allowlisted issuer without a userinfo_endpoint logs in", func(t *testing.T) {
		rg := newRigWith(t, func(cfg *serverConfig, op *fakeOP) {
			cfg.allowedIssuerOrigins = []string{op.issuer()}
			op.endpoints = map[string]string{"userinfo_endpoint": ""}
		})
		if resp := rg.login("t-nouserinfo"); resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("callback status %d: %s", resp.StatusCode, body)
		}
		rg.wantResult("t-nouserinfo", success("t-nouserinfo"))
	})
}

func TestIssuerAllowed(t *testing.T) {
	allow := []string{"https://suite.example", "https://localhost:8443"}
	cases := map[string]struct {
		allow  []string
		issuer string
		want   bool
	}{
		"empty allowlist allows any issuer": {allow: nil, issuer: "https://anything.example/x", want: true},
		"origin match":                      {allow: allow, issuer: "https://suite.example/test/a/plan/", want: true},
		"origin with port":                  {allow: allow, issuer: "https://localhost:8443/test/", want: true},
		"host differs":                      {allow: allow, issuer: "https://suite.example.evil.test/", want: false},
		"prefix trick with userinfo":        {allow: allow, issuer: "https://suite.example@evil.test/", want: false},
		"port differs":                      {allow: allow, issuer: "https://localhost:9443/", want: false},
		"scheme differs":                    {allow: allow, issuer: "http://suite.example/", want: false},
		"host case-insensitive":             {allow: allow, issuer: "https://SUITE.example/", want: true},
		"unparseable":                       {allow: allow, issuer: "://", want: false},
		"empty issuer":                      {allow: allow, issuer: "", want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := issuerAllowed(tc.allow, tc.issuer); got != tc.want {
				t.Fatalf("issuerAllowed(%v, %q) = %v, want %v", tc.allow, tc.issuer, got, tc.want)
			}
		})
	}
}

// An oversized form_post body is refused before it is buffered.
func TestCallbackBodyLimited(t *testing.T) {
	rg := newRig(t)
	rg.authorize("t-big", nil)
	body := "state=" + strings.Repeat("a", maxCallbackBody+1)
	resp, err := http.Post(rg.rp.URL+"/callback", "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /callback: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}
	rg.wantResult("t-big", rejected("t-big", reasonCallbackParse))
}

func TestParseAllowedOrigins(t *testing.T) {
	cases := map[string]struct {
		in      string
		want    []string
		wantErr bool
	}{
		"unset":                {in: "", want: nil},
		"two origins, trimmed": {in: " https://suite.example , https://localhost:8443/ ", want: []string{"https://suite.example", "https://localhost:8443"}},
		"path rejected":        {in: "https://suite.example/test", wantErr: true},
		"no scheme rejected":   {in: "suite.example", wantErr: true},
		"empty entry ignored":  {in: "https://suite.example,,", want: []string{"https://suite.example"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseAllowedOrigins(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// wantNoResult asserts that nothing is recorded for testID.
func (rg *rig) wantNoResult(testID string) {
	rg.t.Helper()
	if status, got := rg.result(testID); status != http.StatusNotFound {
		rg.t.Fatalf("/results/%s status %d, body %v, want 404", testID, status, got)
	}
}

// bodyOf reads resp's body.
func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

// A flow still waiting on the OP when a newer flow of the same test starts
// must not record its outcome into the newer flow's slot: its success is
// discarded, and the newer flow's own outcome is the verdict.
func TestStaleInFlightFlowCannotRecordIntoNewerFlow(t *testing.T) {
	rg := newRig(t)
	paramsA := rg.authorize("t-gen", nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	rg.op.set(func(op *fakeOP) {
		op.nonces["code-a"] = paramsA.Get("nonce")
		op.tokenHook = func() {
			blocked := false
			once.Do(func() { blocked = true; close(entered) })
			if blocked {
				<-release
			}
		}
	})
	type outcome struct {
		status int
		body   string
	}
	first := make(chan outcome, 1)
	go func() {
		cb := url.Values{"code": {"code-a"}, "state": {paramsA.Get("state")}}
		resp, err := noRedirect.Get(rg.rp.URL + "/callback?" + cb.Encode())
		if err != nil {
			first <- outcome{}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		first <- outcome{status: resp.StatusCode, body: string(data)}
	}()
	<-entered

	paramsB := rg.authorize("t-gen", nil)
	close(release)
	got := <-first
	if got.status != http.StatusBadRequest || !strings.Contains(got.body, reasonStaleFlow) {
		t.Fatalf("stale callback = %d %q, want 400 %s", got.status, got.body, reasonStaleFlow)
	}
	rg.wantNoResult("t-gen")

	rg.op.set(func(op *fakeOP) { op.nonces["code-b"] = paramsB.Get("nonce") })
	if resp := rg.get("/callback", url.Values{"code": {"code-b"}, "state": {paramsB.Get("state")}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("current callback status %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	rg.wantResult("t-gen", success("t-gen"))
}

// A superseded flow's callback that arrives after the newer flow started is
// turned away before any OP call, and is not read as a forged state against
// the newer flow.
func TestLateCallbackOfSupersededFlow(t *testing.T) {
	rg := newRig(t)
	paramsA := rg.authorize("t-late", nil)
	paramsB := rg.authorize("t-late", nil)
	var tokenCalls int
	var mu sync.Mutex
	rg.op.set(func(op *fakeOP) {
		op.nonces["code-a"] = paramsA.Get("nonce")
		op.nonces["code-b"] = paramsB.Get("nonce")
		op.tokenHook = func() { mu.Lock(); tokenCalls++; mu.Unlock() }
	})
	resp := rg.get("/callback", url.Values{"code": {"code-a"}, "state": {paramsA.Get("state")}})
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, reasonStaleFlow) {
		t.Fatalf("superseded callback = %d %q, want 400 %s", resp.StatusCode, body, reasonStaleFlow)
	}
	mu.Lock()
	calls := tokenCalls
	mu.Unlock()
	if calls != 0 {
		t.Fatalf("superseded callback made %d token requests, want none", calls)
	}
	rg.wantNoResult("t-late")

	if resp := rg.get("/callback", url.Values{"code": {"code-b"}, "state": {paramsB.Get("state")}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("current callback status %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	rg.wantResult("t-late", success("t-late"))
}

// The two logins of a key-rotation module run one after the other on one
// test_id; the second flow's outcome is the verdict.
func TestSequentialLoginsOnOneTest(t *testing.T) {
	rg := newRig(t)
	if resp := rg.login("t-two"); resp.StatusCode != http.StatusOK {
		t.Fatalf("first login status %d", resp.StatusCode)
	}
	rg.op.set(func(op *fakeOP) { op.mutate = func(c map[string]any) { c["aud"] = "someone-else" } })
	if resp := rg.login("t-two"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second login status %d, want 400", resp.StatusCode)
	}
	rg.wantResult("t-two", rejected("t-two", reasonInvalidAudience))
}

func TestRepeatedCallbackParams(t *testing.T) {
	cases := []struct {
		name  string
		param string
	}{
		{name: "state", param: "state"},
		{name: "code", param: "code"},
		{name: "error", param: "error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rg := newRig(t)
			params := rg.authorize("t-dup", nil)
			rg.op.set(func(op *fakeOP) { op.nonces["c"] = params.Get("nonce") })
			cb := url.Values{"code": {"c"}, "state": {params.Get("state")}}
			if tc.param == "error" {
				cb.Set("error", "access_denied")
			}
			cb[tc.param] = append(cb[tc.param], cb.Get(tc.param))
			if resp := rg.get("/callback", cb); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
			rg.wantResult("t-dup", rejected("t-dup", reasonCallbackParse))
		})
	}
}

func TestTokenType(t *testing.T) {
	cases := []struct {
		name   string
		set    func(op *fakeOP)
		status int
		want   func(testID string) map[string]any
	}{
		{name: "lowercase bearer", set: func(op *fakeOP) { op.tokenType = "bearer" }, status: http.StatusOK,
			want: success},
		{name: "missing", set: func(op *fakeOP) { op.noTokenType = true }, status: http.StatusBadRequest,
			want: func(id string) map[string]any { return rejected(id, reasonTokenExchange) }},
		{name: "not bearer", set: func(op *fakeOP) { op.tokenType = "N_A" }, status: http.StatusBadRequest,
			want: func(id string) map[string]any { return rejected(id, reasonTokenExchange) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rg := newRig(t)
			rg.op.set(tc.set)
			if resp := rg.login("t-tt"); resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			rg.wantResult("t-tt", tc.want("t-tt"))
		})
	}
}

// azp is checked (Core §3.1.3.7 steps 4-5): a token whose azp names another
// party is rejected, and one whose azp is this client is accepted.
func TestAZPValidated(t *testing.T) {
	cases := map[string]struct {
		mutate func(c map[string]any)
		want   func(testID string) map[string]any
	}{
		"azp-other-party": {
			mutate: func(c map[string]any) { c["azp"] = "someone-else" },
			want:   func(id string) map[string]any { return rejected(id, reasonInvalidAudience) },
		},
		"multi-aud-no-azp": {
			mutate: func(c map[string]any) { c["aud"] = []string{testClientID, "someone-else"} },
			want:   func(id string) map[string]any { return rejected(id, reasonInvalidAudience) },
		},
		"azp-this-client": {
			mutate: func(c map[string]any) { c["azp"] = testClientID },
			want:   success,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rg := newRig(t)
			rg.op.set(func(op *fakeOP) { op.mutate = tc.mutate })
			_ = rg.login(name)
			rg.wantResult(name, tc.want(name))
		})
	}
}

// A /discover retry after a rejection is a new flow: its outcome replaces the
// earlier one instead of merging into a conflict.
func TestDiscoverRetryStartsNewFlow(t *testing.T) {
	rg := newRig(t)
	q := url.Values{"issuer": {rg.op.issuer()}, "test_id": {"t-retry"}, "test_name": {"t-retry"}, "profile": {"config-rp"}}
	rg.op.set(func(op *fakeOP) { op.discoveryIssuer = "https://other.example" })
	if resp := rg.get("/discover", q); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("first discover status %d, want 502", resp.StatusCode)
	}
	rg.wantResult("t-retry", rejected("t-retry", reasonIssuerMismatch))
	rg.op.set(func(op *fakeOP) { op.discoveryIssuer = "" })
	if resp := rg.get("/discover", q); resp.StatusCode != http.StatusOK {
		t.Fatalf("retry discover status %d, want 200", resp.StatusCode)
	}
	rg.wantResult("t-retry", success("t-retry"))
}

// The static clients register no id_token_signed_response_alg, so the ID Token
// must be RS256 (OIDC Registration §2): another RSA alg the key could verify
// is still rejected, and alg none keeps its own reason.
func TestIDTokenAlgPinnedToRS256(t *testing.T) {
	cases := map[string]struct {
		configure func(op *fakeOP)
		want      func(testID string) map[string]any
	}{
		"rs512-jwk-without-alg": {
			configure: func(op *fakeOP) { op.signAlg = jose.RS512; op.jwkNoAlg = true },
			want:      func(id string) map[string]any { return rejected(id, reasonInvalidAlgorithm) },
		},
		"rs256-jwk-without-alg": {
			configure: func(op *fakeOP) { op.jwkNoAlg = true },
			want:      success,
		},
		"alg-none": {
			configure: func(op *fakeOP) { op.signer = nil },
			want:      func(id string) map[string]any { return rejected(id, reasonAlgNone) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rg := newRig(t)
			rg.op.set(tc.configure)
			_ = rg.login(name)
			rg.wantResult(name, tc.want(name))
		})
	}
}
