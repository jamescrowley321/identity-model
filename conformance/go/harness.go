package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

const (
	statusSuccess  = "success"
	statusError    = "error"
	statusConflict = "conflict"

	defaultScope = "openid profile email address phone"
	// maxPending bounds the authorization flows awaiting a callback; the runner
	// drives one module at a time, so older flows are abandoned.
	maxPending = 64
	// maxCallbackBody bounds a form_post authorization response; a real one
	// (code, state, maybe session_state) is far smaller.
	maxCallbackBody = 64 << 10
	// flowTimeout bounds the OP calls one request makes.
	flowTimeout = 60 * time.Second
)

// serverConfig is the harness's environment.
type serverConfig struct {
	// rpBaseURL is the browser-facing base: redirect_uri is <rpBaseURL>/callback.
	rpBaseURL string
	// opFacingBaseURL is the base the OP would use server-to-server, reported by
	// /health so a hosted run can check it.
	opFacingBaseURL string
	// logDir is RP_LOG_DIR ("" disables per-test log files).
	logDir string
	// httpClient makes every request to the OP.
	httpClient *http.Client
	// allowedIssuerOrigins, when non-empty, is the only set of issuer origins
	// the harness contacts (RP_ALLOWED_ISSUER_ORIGINS).
	allowedIssuerOrigins []string
}

// result is a module's recorded outcome, served by /results/{test_id}.
type result struct {
	TestID string `json:"test_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// session is one authorization flow between /authorize and /callback.
type session struct {
	state        string
	nonce        string
	codeVerifier string
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	skipUserInfo bool
	testID       string
	testName     string
	profile      string
	provider     *discovery.ProviderConfiguration
}

type server struct {
	cfg serverConfig

	mu      sync.Mutex
	pending []*session
	results map[string]result
	// lastTestID is the test of the most recent /authorize: a rejection that
	// carries no usable state is filed under it, and logged to that test's
	// rp-log (lastProfile, lastTestName).
	lastTestID   string
	lastProfile  string
	lastTestName string
}

func newServer(cfg serverConfig) *server {
	return &server{cfg: cfg, results: map[string]result{}}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.health)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /clear-cache", s.clearCache)
	mux.HandleFunc("GET /discover", s.discover)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /callback", s.callback)
	mux.HandleFunc("GET /results/{test_id}", s.getResult)
	return mux
}

func (s *server) logger(profile, test string) *slog.Logger {
	return newTestLogger(s.cfg.logDir, profile, test)
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":             "ok",
		"service":            "conformance-rp-go",
		"op_facing_base_url": s.cfg.opFacingBaseURL,
	})
}

// clearCache drops the library's discovery and JWKS caches; the runner calls
// it before every module because the suite reconfigures the OP between them.
// Nothing else clears them, so the two logins of a key-rotation module share
// the JWKS cache.
func (s *server) clearCache(w http.ResponseWriter, _ *http.Request) {
	discovery.ClearCache()
	jwks.ClearCache()
	slog.Info("cleared discovery and JWKS caches")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "cleared": []string{"discovery", "jwks"}})
}

func (s *server) getResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	res, ok := s.results[r.PathValue("test_id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) record(testID, status, reason, detail string) {
	if testID == "" {
		return
	}
	res := result{TestID: testID, Status: status}
	if reason != "" {
		res.Error = reason + ": " + detail
	}
	s.mu.Lock()
	s.mergeLocked(res)
	s.mu.Unlock()
}

// mergeLocked records res, called with s.mu held. Outcomes of one flow merge
// rather than overwrite, so the verdict does not depend on arrival order: the
// first rejection stands over later ones, and a success together with a
// rejection, in either order, is a conflict (which the runner always fails),
// keeping the rejection's reason. /authorize clears the slot for a new flow.
func (s *server) mergeLocked(res result) {
	prior, ok := s.results[res.TestID]
	switch {
	case !ok:
		s.results[res.TestID] = res
	case prior.Status == statusConflict, prior.Status == res.Status:
		// Keep the first outcome: a conflict stays a conflict, the first
		// rejection stands, and a repeated success changes nothing.
	case prior.Status == statusSuccess:
		s.results[res.TestID] = result{TestID: res.TestID, Status: statusConflict,
			Error: res.Error + " (after a recorded success)"}
	default:
		s.results[res.TestID] = result{TestID: res.TestID, Status: statusConflict,
			Error: prior.Error + " (then a success in the same flow)"}
	}
}

// errIssuerNotAllowed is fetchProvider's refusal of an issuer outside the
// allowlist; classify maps it to reasonIssuerNotAllowed.
var errIssuerNotAllowed = errors.New("issuer origin is not in RP_ALLOWED_ISSUER_ORIGINS")

// fetchProvider runs discovery for issuer, matching the document's issuer
// exactly (OIDC Discovery 1.0 §4.3). An issuer outside a configured allowlist
// is refused before any request is made.
func (s *server) fetchProvider(ctx context.Context, issuer string) (*discovery.ProviderConfiguration, error) {
	if !issuerAllowed(s.cfg.allowedIssuerOrigins, issuer) {
		return nil, errIssuerNotAllowed
	}
	return discovery.FetchConfiguration(ctx, issuer, discovery.WithHTTPClient(s.cfg.httpClient))
}

// discover fetches and validates discovery only (Config RP discovery modules).
func (s *server) discover(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	testID := q.Get("test_id")
	log := s.logger(q.Get("profile"), q.Get("test_name"))
	ctx, cancel := context.WithTimeout(r.Context(), flowTimeout)
	defer cancel()

	provider, err := s.fetchProvider(ctx, q.Get("issuer"))
	if err != nil {
		s.refuse(w, log, testID, classify(err, reasonDiscoveryFailed), err.Error())
		return
	}
	s.record(testID, statusSuccess, "", "")
	log.Info("ACCEPTED: discovery document fetched and validated", "issuer", provider.Issuer)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "issuer": provider.Issuer})
}

// authorize starts an authorization code flow and redirects to the OP.
func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	testID := q.Get("test_id")
	sess := &session{
		issuer:       q.Get("issuer"),
		clientID:     q.Get("client_id"),
		clientSecret: q.Get("client_secret"),
		redirectURI:  strings.TrimRight(s.cfg.rpBaseURL, "/") + "/callback",
		skipUserInfo: q.Get("skip_userinfo") == "true",
		testID:       testID,
		testName:     q.Get("test_name"),
		profile:      q.Get("profile"),
	}
	log := s.logger(sess.profile, sess.testName)

	// A new flow starts with no recorded outcome, so a flow that never reaches
	// the callback cannot be read as an earlier flow's result.
	s.mu.Lock()
	delete(s.results, testID)
	s.lastTestID = testID
	s.lastProfile = sess.profile
	s.lastTestName = sess.testName
	s.mu.Unlock()

	for _, flag := range []string{"fapi2", "jarm", "mtls", "signed_request", "use_request_uri"} {
		if q.Get(flag) == "true" {
			s.reject(w, log, testID, reasonUnsupportedFlow, flag+" flows are not driven by this harness")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), flowTimeout)
	defer cancel()
	provider, err := s.fetchProvider(ctx, sess.issuer)
	if err != nil {
		s.refuse(w, log, testID, classify(err, reasonDiscoveryFailed), err.Error())
		return
	}
	sess.provider = provider

	if err := sess.newSecrets(q.Get("use_pkce") == "true"); err != nil {
		s.refuse(w, log, testID, reasonRPError, err.Error())
		return
	}
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {sess.clientID},
		"redirect_uri":  {sess.redirectURI},
		"scope":         {defaultScope},
		"state":         {sess.state},
		"nonce":         {sess.nonce},
	}
	if scope := q.Get("scope"); scope != "" {
		params.Set("scope", scope)
	}
	if sess.codeVerifier != "" {
		params.Set("code_challenge", token.S256Challenge(sess.codeVerifier))
		params.Set("code_challenge_method", token.ChallengeMethodS256)
	}

	authURL, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil || provider.AuthorizationEndpoint == "" {
		s.refuse(w, log, testID, reasonMissingEndpoint, "discovery has no usable authorization_endpoint")
		return
	}
	merged := authURL.Query()
	for k, v := range params {
		merged[k] = v
	}
	authURL.RawQuery = merged.Encode()

	s.addPending(sess)
	log.Info("ACCEPTED: discovery issuer matches; redirecting to OP", "issuer", sess.issuer)
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// callback handles the authorization response: query string (GET) or
// form_post body (POST).
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCallbackBody)
	if err := r.ParseForm(); err != nil {
		s.rejectUnattributed(w, reasonCallbackParse, err.Error())
		return
	}
	form := r.Form
	sess := s.takePending(form.Get("state"))
	if sess == nil {
		s.rejectUnattributed(w, reasonStateValidation, "unknown or missing state")
		return
	}
	log := s.logger(sess.profile, sess.testName)

	if opErr := form.Get("error"); opErr != "" {
		s.reject(w, log, sess.testID, opErr, "OP returned an error response: "+form.Get("error_description"))
		return
	}
	code := form.Get("code")
	if code == "" {
		s.reject(w, log, sess.testID, reasonMissingCode, "authorization response has no code")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), flowTimeout)
	defer cancel()
	provider := sess.provider

	tokenOpts := []token.Option{token.WithHTTPClient(s.cfg.httpClient)}
	if sess.clientSecret != "" {
		// client_secret_basic is the library default (RFC 6749 §2.3.1).
		tokenOpts = append(tokenOpts, token.WithClientSecret(sess.clientSecret))
	}
	if sess.codeVerifier != "" {
		tokenOpts = append(tokenOpts, token.WithCodeVerifier(sess.codeVerifier))
	}
	tokens, err := token.AuthorizationCode(ctx, provider.TokenEndpoint, sess.clientID, code, sess.redirectURI, tokenOpts...)
	if err != nil {
		s.reject(w, log, sess.testID, classify(err, reasonTokenExchange), err.Error())
		return
	}
	if tokens.IDToken == "" {
		s.reject(w, log, sess.testID, reasonIDTokenValidation, "token response has no id_token")
		return
	}

	keySet, err := jwks.FetchKeySet(ctx, provider.JWKSURI, jwks.WithHTTPClient(s.cfg.httpClient))
	if err != nil {
		s.reject(w, log, sess.testID, classify(err, reasonJWKSFailed), err.Error())
		return
	}
	claims, err := idtoken.ValidateIDToken(ctx, tokens.IDToken, keySet,
		idtoken.WithIssuer(sess.issuer),
		idtoken.WithClientID(sess.clientID),
		idtoken.WithNonce(sess.nonce),
		// A token-endpoint ID Token may omit at_hash (§3.1.3.6); a present one
		// must match the access token (§3.3.2.11).
		idtoken.WithAccessToken(tokens.AccessToken),
		idtoken.WithAccessTokenIssuedWithIDToken(false),
	)
	if err != nil {
		s.reject(w, log, sess.testID, classify(err, reasonIDTokenValidation), err.Error())
		return
	}
	log.Info("ACCEPTED: id_token validated (signature, iss, aud, iat, exp, sub, nonce)", "sub", claims.Subject)

	var userClaims map[string]any
	if !sess.skipUserInfo && provider.UserInfoEndpoint != "" && tokens.AccessToken != "" {
		info, err := userinfo.Fetch(ctx, provider.UserInfoEndpoint, tokens.AccessToken,
			userinfo.WithHTTPClient(s.cfg.httpClient),
			userinfo.WithSubjectValidation(claims.Subject),
		)
		if err != nil {
			s.reject(w, log, sess.testID, classify(err, reasonUserInfoValidation), err.Error())
			return
		}
		userClaims = info.Claims()
		log.Info("ACCEPTED: UserInfo fetched; sub matches the id_token")
	}

	s.record(sess.testID, statusSuccess, "", "")
	log.Info("ACCEPTED: authentication successful", "issuer", sess.issuer, "sub", claims.Subject)
	writeSuccess(w, claims, userClaims)
}

// reject records a rejection the RP decided and answers 400.
func (s *server) reject(w http.ResponseWriter, log *slog.Logger, testID, reason, detail string) {
	log.Error("REJECTED: "+reason, "detail", detail)
	s.record(testID, statusError, reason, detail)
	writeError(w, reason, detail)
}

// refuse records a flow the RP deliberately refused (discovery failure, issuer
// mismatch, missing endpoint) and answers 502.
func (s *server) refuse(w http.ResponseWriter, log *slog.Logger, testID, reason, detail string) {
	log.Error("REJECTED: "+reason, "detail", detail)
	s.record(testID, statusError, reason, detail)
	writeJSON(w, http.StatusBadGateway, map[string]string{"error": reason, "detail": detail})
}

// rejectUnattributed handles a rejection with no usable session (unknown
// state). It is filed under the most recent flow's test and merged like any
// other outcome, so it never turns that test's verdict into a pass: nothing
// recorded → the rejection; a rejection recorded → the first stands; a success
// recorded, before or after → conflict.
func (s *server) rejectUnattributed(w http.ResponseWriter, reason, detail string) {
	s.mu.Lock()
	testID, profile, testName := s.lastTestID, s.lastProfile, s.lastTestName
	if testID != "" {
		s.mergeLocked(result{TestID: testID, Status: statusError, Error: reason + ": " + detail})
	}
	s.mu.Unlock()
	s.logger(profile, testName).Error("REJECTED: "+reason, "detail", detail, "unattributed", true)
	writeError(w, reason, detail)
}

func (s *server) addPending(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, sess)
	if len(s.pending) > maxPending {
		s.pending = s.pending[len(s.pending)-maxPending:]
	}
}

// takePending removes and returns the flow whose state equals state, or nil.
// Every pending state is compared in constant time, with no early exit, so the
// comparison leaks nothing about a guessed state.
func (s *server) takePending(state string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	match := -1
	for i, p := range s.pending {
		if subtle.ConstantTimeCompare([]byte(p.state), []byte(state)) == 1 {
			match = i
		}
	}
	if match < 0 {
		return nil
	}
	sess := s.pending[match]
	s.pending = append(s.pending[:match], s.pending[match+1:]...)
	return sess
}

// newSecrets generates the flow's state and nonce, and a PKCE code verifier
// when pkce is set.
func (sess *session) newSecrets(pkce bool) error {
	var err error
	if sess.state, err = randomToken(); err != nil {
		return err
	}
	if sess.nonce, err = randomToken(); err != nil {
		return err
	}
	if pkce {
		if sess.codeVerifier, err = token.GenerateCodeVerifier(); err != nil {
			return err
		}
	}
	return nil
}

// randomToken returns 32 bytes from crypto/rand, base64url-encoded.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		slog.Warn("write response", "error", err)
	}
}

// Pages are rendered with html/template: every value may come from the OP, so
// all of it is escaped.
var (
	errorTmpl = template.Must(template.New("error").Parse(
		`<h1>Rejected</h1><p>{{.Reason}}: {{.Detail}}</p>`))
	successTmpl = template.Must(template.New("success").Parse(
		`<h1>Authentication Successful</h1><p>Subject: {{.Subject}}</p><p>Issuer: {{.Issuer}}</p>` +
			`{{if .UserInfo}}<h2>UserInfo Claims</h2>{{range .UserInfo}}<p>{{.Name}}: {{.Value}}</p>{{end}}{{end}}`))
)

type claimLine struct {
	Name  string
	Value string
}

func writeHTML(w http.ResponseWriter, status int, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmpl.Execute(w, data); err != nil {
		slog.Warn("write response", "error", err)
	}
}

func writeError(w http.ResponseWriter, reason, detail string) {
	writeHTML(w, http.StatusBadRequest, errorTmpl, map[string]string{"Reason": reason, "Detail": detail})
}

// writeSuccess shows the validated ID Token and UserInfo claims (the suite's
// scope-userinfo-claims module looks for the RP displaying them).
func writeSuccess(w http.ResponseWriter, claims *jwt.Claims, userClaims map[string]any) {
	lines := make([]claimLine, 0, len(userClaims))
	for k, v := range userClaims {
		lines = append(lines, claimLine{Name: k, Value: fmt.Sprint(v)})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Name < lines[j].Name })
	writeHTML(w, http.StatusOK, successTmpl, map[string]any{
		"Subject": claims.Subject, "Issuer": claims.Issuer, "UserInfo": lines,
	})
}
