// Command rp-go is the Go Relying-Party harness for OIDF conformance. It exposes
// the HTTP contract the conformance orchestration runner (conformance/run_tests.py)
// drives, performing the OIDC authorization-code login flow against the suite's
// OP entirely through the identity-model Go client library (go/pkg/*). Each
// accept/reject decision is written as per-test OIDF "clientSideData" evidence.
//
// It is a test harness, not shipped library code: it trusts the suite's
// self-signed cert and binds a fixed port. The library packages under go/pkg do
// the real protocol work; this program only wires them into the suite's flow.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// defaultScope mirrors the py-identity-model harness so the OP returns the
// standard claim set for the UserInfo leg.
const defaultScope = "openid profile email address phone"

// session holds the state of one in-flight authorization-code flow, keyed by the
// OAuth state parameter. It is single-use: /callback pops it.
type session struct {
	issuer       string
	state        string
	nonce        string
	codeVerifier string // empty unless PKCE was used
	clientID     string
	clientSecret string // empty for a public client
	redirectURI  string
	skipUserinfo bool
	testName     string // per-test evidence routing (recovered here in /callback)
	profile      string
	testID       string
}

// rp is the harness: an HTTP server plus a concurrent-safe session store and the
// shared cert-trusting HTTP client threaded into every library call.
type rp struct {
	rpBaseURL  string
	httpClient *http.Client
	ev         *evidence

	mu       sync.Mutex
	sessions map[string]*session
}

func main() {
	rpBase := envOr("RP_BASE_URL", "http://localhost:8888")
	addr := envOr("RP_HOST", "0.0.0.0") + ":" + envOr("RP_PORT", "8888")

	r := &rp{
		rpBaseURL:  rpBase,
		httpClient: buildHTTPClient(),
		ev:         newEvidence(os.Getenv("RP_LOG_DIR")),
		sessions:   make(map[string]*session),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", r.health)
	mux.HandleFunc("GET /health", r.health)
	mux.HandleFunc("POST /clear-cache", r.clearCache)
	mux.HandleFunc("GET /discover", r.discover)
	mux.HandleFunc("GET /authorize", r.authorize)
	mux.HandleFunc("GET /callback", r.callback)
	mux.HandleFunc("POST /callback", r.callback)

	log.Printf("conformance rp-go listening on %s (rp_base_url=%s)", addr, rpBase)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// health reports liveness (GET / and GET /health).
func (r *rp) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "conformance-rp"})
}

// clearCache resets the discovery and JWKS caches between test modules. This is
// load-bearing: every test in a plan shares one issuer/jwks_uri while the OP
// rotates its signing keys per test, so without a reset the RP would serve a
// stale key set (and the refresh-on-kid-miss can be throttled by the cooldown
// when tests run in quick succession), wrongly rejecting valid tokens.
func (r *rp) clearCache(w http.ResponseWriter, _ *http.Request) {
	discovery.ClearCache()
	jwks.ClearCache()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "cleared": []string{"discovery", "jwks"}})
}

// discover drives a discovery-only test: fetch + validate the OP metadata.
func (r *rp) discover(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	issuer := q.Get("issuer")
	profile, testName := q.Get("profile"), q.Get("test_name")

	if issuer == "" {
		r.ev.reject(profile, testName, "discovery request missing issuer")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_issuer", "detail": "missing issuer"})
		return
	}
	cfg, err := r.fetchDiscovery(req.Context(), issuer)
	if err != nil {
		r.ev.reject(profile, testName, "discovery fetch/validation failed: "+err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "discovery_failed", "detail": err.Error()})
		return
	}
	r.ev.accept(profile, testName, fmt.Sprintf("discovery document fetched and validated for issuer %q", cfg.Issuer))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "issuer": cfg.Issuer})
}

// authorize begins an auth-code flow: discover the OP, build the authorization
// request, store the session, and 302-redirect to the OP. The runner's HTTP
// client follows the redirect to the OP and back to /callback.
func (r *rp) authorize(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	issuer := q.Get("issuer")
	clientID := q.Get("client_id")
	profile, testName, testID := q.Get("profile"), q.Get("test_name"), q.Get("test_id")

	if issuer == "" || clientID == "" {
		r.ev.reject(profile, testName, "authorize request missing issuer or client_id")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "detail": "missing issuer or client_id"})
		return
	}

	cfg, err := r.fetchDiscovery(req.Context(), issuer)
	if err != nil {
		r.ev.reject(profile, testName, "discovery failed in authorize: "+err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "discovery_failed", "detail": err.Error()})
		return
	}
	// OIDC Discovery 1.0 §4.3: the document's issuer must match the requested one.
	if cfg.Issuer != issuer {
		r.ev.reject(profile, testName, fmt.Sprintf("issuer mismatch: requested %q, document declares %q", issuer, cfg.Issuer))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "issuer_mismatch", "detail": "discovery issuer does not match requested issuer"})
		return
	}
	if cfg.AuthorizationEndpoint == "" {
		r.ev.reject(profile, testName, "discovery document missing authorization_endpoint")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "missing_endpoint", "detail": "no authorization_endpoint"})
		return
	}

	state, nonce := randToken(), randToken()
	redirectURI := r.rpBaseURL + "/callback"
	scope := defaultScope
	if s := q.Get("scope"); s != "" {
		scope = s
	}

	var codeVerifier, challenge string
	if strings.EqualFold(q.Get("use_pkce"), "true") {
		if codeVerifier, err = token.GenerateCodeVerifier(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pkce", "detail": err.Error()})
			return
		}
		challenge = token.S256Challenge(codeVerifier)
	}

	r.mu.Lock()
	r.sessions[state] = &session{
		issuer: issuer, state: state, nonce: nonce, codeVerifier: codeVerifier,
		clientID: clientID, clientSecret: q.Get("client_secret"), redirectURI: redirectURI,
		skipUserinfo: strings.EqualFold(q.Get("skip_userinfo"), "true"),
		testName:     testName, profile: profile, testID: testID,
	}
	r.mu.Unlock()

	authURL := buildAuthorizationURL(cfg.AuthorizationEndpoint, clientID, redirectURI, scope, state, nonce, challenge)
	r.ev.accept(profile, testName, fmt.Sprintf("discovery issuer %q matches expected; redirecting to OP", issuer))
	http.Redirect(w, req, authURL, http.StatusFound)
}

// callback completes the flow (GET query mode and POST form_post mode both route
// here): validate state, exchange the code, validate the ID token and nonce, and
// optionally call UserInfo — recording accept/reject evidence at each step.
func (r *rp) callback(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		htmlError(w, http.StatusBadRequest, "Callback Error", "failed to parse callback")
		return
	}
	// Both query (GET) and form (POST) params land in req.Form after ParseForm.
	state := req.Form.Get("state")
	code := req.Form.Get("code")
	oauthErr := req.Form.Get("error")

	r.mu.Lock()
	sess := r.sessions[state]
	delete(r.sessions, state)
	r.mu.Unlock()

	if state == "" || sess == nil {
		htmlError(w, http.StatusBadRequest, "Error", "unknown or missing state parameter")
		return
	}
	profile, testName := sess.profile, sess.testName

	if oauthErr != "" {
		r.ev.reject(profile, testName, "OP returned error response: "+oauthErr+" ("+req.Form.Get("error_description")+")")
		htmlError(w, http.StatusBadRequest, "OP Error", oauthErr+": "+req.Form.Get("error_description"))
		return
	}
	if code == "" {
		r.ev.reject(profile, testName, "authorization callback missing code parameter")
		htmlError(w, http.StatusBadRequest, "Callback Error", "authorization callback missing code parameter")
		return
	}

	ctx := req.Context()
	cfg, err := r.fetchDiscovery(ctx, sess.issuer)
	if err != nil {
		r.ev.reject(profile, testName, "discovery failed in callback: "+err.Error())
		htmlError(w, http.StatusBadGateway, "Discovery Error", err.Error())
		return
	}
	if cfg.TokenEndpoint == "" {
		r.ev.reject(profile, testName, "discovery document missing token_endpoint")
		htmlError(w, http.StatusBadGateway, "Discovery Error", "discovery document missing token_endpoint")
		return
	}

	// Token exchange through the library. Confidential clients present the
	// secret via client_secret_basic (WithClientSecret); PKCE verifier attached
	// when present.
	opts := []token.Option{token.WithHTTPClient(r.httpClient), token.WithInsecureAllowHTTP()}
	if sess.clientSecret != "" {
		opts = append(opts, token.WithClientSecret(sess.clientSecret))
	}
	if sess.codeVerifier != "" {
		opts = append(opts, token.WithCodeVerifier(sess.codeVerifier))
	}
	tok, err := token.AuthorizationCode(ctx, cfg.TokenEndpoint, sess.clientID, code, sess.redirectURI, opts...)
	if err != nil {
		r.ev.reject(profile, testName, "token exchange failed: "+err.Error())
		htmlError(w, http.StatusBadRequest, "Token Exchange Failed", err.Error())
		return
	}

	var sub string
	if tok.IDToken != "" {
		claims, verr := r.validateIDToken(ctx, tok.IDToken, cfg, sess)
		if verr != nil {
			r.ev.reject(profile, testName, "id_token validation failed: "+verr.Error())
			htmlError(w, http.StatusBadRequest, "ID Token Validation Failed", verr.Error())
			return
		}
		sub = claims.Subject
		r.ev.accept(profile, testName, "id_token validated by identity-model (signature, issuer, audience, nonce, expiry)")
	}

	// UserInfo leg (unless skipped or unavailable). Subject consistency is
	// enforced by the library when we pass the ID token sub.
	if tok.AccessToken != "" && cfg.UserInfoEndpoint != "" && !sess.skipUserinfo {
		uiOpts := []userinfo.Option{userinfo.WithHTTPClient(r.httpClient)}
		if sub != "" {
			uiOpts = append(uiOpts, userinfo.WithSubjectValidation(sub))
		}
		if _, uerr := userinfo.Fetch(ctx, cfg.UserInfoEndpoint, tok.AccessToken, uiOpts...); uerr != nil {
			r.ev.reject(profile, testName, "userinfo validation failed: "+uerr.Error())
			htmlError(w, http.StatusBadRequest, "UserInfo Validation Failed", uerr.Error())
			return
		}
		r.ev.accept(profile, testName, "userinfo fetched and sub matches id_token")
	}

	r.ev.accept(profile, testName, fmt.Sprintf("authentication successful for issuer=%s, sub=%s", sess.issuer, sub))
	htmlOK(w, "Authentication Successful",
		fmt.Sprintf("<p>Subject: %s</p><p>Issuer: %s</p>", html.EscapeString(sub), html.EscapeString(sess.issuer)))
}

// validateIDToken fetches the OP's JWKS (through the cert-trusting client, so
// the library's refresh-on-kid-miss / key-rotation path is preserved) and
// validates the ID token: signature, issuer, audience, nonce, and required sub.
func (r *rp) validateIDToken(ctx context.Context, idToken string, cfg *discovery.ProviderConfiguration, sess *session) (*jwt.Claims, error) {
	keySet, err := jwks.FetchKeySet(ctx, cfg.JWKSURI, jwks.WithHTTPClient(r.httpClient), jwks.WithInsecureAllowHTTP())
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	return jwt.Validate(ctx, idToken, keySet,
		jwt.WithExpectedIssuer(cfg.Issuer),
		jwt.WithExpectedAudience(sess.clientID),
		jwt.WithExpectedNonce(sess.nonce),
		jwt.WithRequiredClaims("sub"),
	)
}

// fetchDiscovery fetches + validates the OP metadata for issuer through the
// cert-trusting client. HTTP issuers are permitted (WithInsecureAllowHTTP) for
// the local suite; the suite is normally behind TLS.
func (r *rp) fetchDiscovery(ctx context.Context, issuer string) (*discovery.ProviderConfiguration, error) {
	return discovery.FetchConfiguration(ctx, issuer,
		discovery.WithHTTPClient(r.httpClient), discovery.WithInsecureAllowHTTP())
}

// buildAuthorizationURL constructs the OIDC authorization request (RFC 6749
// §4.1.1 + OIDC Core §3.1.2.1). The library has no builder for this, so the
// harness assembles it directly.
func buildAuthorizationURL(endpoint, clientID, redirectURI, scope, state, nonce, codeChallenge string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// buildHTTPClient returns the HTTP client used for every library call. It trusts
// the suite's self-signed cert via SSL_CERT_FILE, falling back to skipping
// verification for the local self-signed suite when no cert file is provided.
func buildHTTPClient() *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certFile := os.Getenv("SSL_CERT_FILE"); certFile != "" {
		if pem, err := os.ReadFile(certFile); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tlsCfg.RootCAs = pool
			} else {
				tlsCfg.InsecureSkipVerify = true // unparseable cert: local suite only
			}
		} else {
			tlsCfg.InsecureSkipVerify = true
		}
	} else {
		tlsCfg.InsecureSkipVerify = true // local self-signed conformance suite
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}
}

// randToken returns a 32-byte URL-safe random string for state/nonce.
func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is fatal for security-sensitive values.
		panic(fmt.Sprintf("rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func htmlOK(w http.ResponseWriter, title, bodyHTML string) {
	writeHTML(w, http.StatusOK, "<h1>"+html.EscapeString(title)+"</h1>"+bodyHTML)
}

// htmlError renders an escaped error page with the given status. IdP-origin
// detail is escaped to avoid reflected XSS.
func htmlError(w http.ResponseWriter, status int, title, detail string) {
	writeHTML(w, status, "<h1>"+html.EscapeString(title)+"</h1><p>"+html.EscapeString(detail)+"</p>")
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>")); err != nil {
		log.Printf("write html: %v", err)
	}
}
