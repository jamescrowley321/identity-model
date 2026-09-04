package integrationtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// ErrNoDevInteractions marks a provider whose authorization endpoint did not
// hand off to node-oidc-provider's headless devInteractions pages; callers
// (tests) skip the end-to-end flow on such profiles instead of failing.
var ErrNoDevInteractions = errors.New(
	"provider does not expose node-oidc devInteractions; headless login unavailable")

// Static test account provisioned by infra/node-oidc-provider/provider.js.
// devInteractions accepts any credentials, but using the fixture account keeps
// the flow aligned with the Python suite's AuthCodeFlowConfig defaults.
const (
	devLoginHint     = "test-user"
	devLoginPassword = "test"
)

const maxFlowRedirects = 10

// AuthCodeResult carries the artifacts a completed headless flow delivered to
// the redirect URI.
type AuthCodeResult struct {
	Code  string
	State string
}

// PerformAuthCodeFlow drives a full authorization-code + PKCE authorize leg
// headlessly against node-oidc-provider's devInteractions (login + consent)
// and returns the code and state delivered to redirectURI. The token-endpoint
// exchange is the caller's job so tests exercise their own package API.
//
// Optional authorizeParams mutators set extra query parameters on the authorize
// request (e.g. nonce or max_age) so a caller can have the OP echo a nonce /
// auth_time into the minted ID Token. They are applied in order after the base
// parameters, so a mutator may override them.
func PerformAuthCodeFlow(
	ctx context.Context,
	authorizationEndpoint, clientID, redirectURI, scope, codeChallenge, state string,
	authorizeParams ...func(url.Values),
) (*AuthCodeResult, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar: %w", err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		// Redirects are followed manually so the loop can stop at the
		// (unserved) redirect URI instead of dialing it.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	for _, mutate := range authorizeParams {
		mutate(params)
	}
	authURL := authorizationEndpoint + "?" + params.Encode()

	resp, callback, err := followRedirects(ctx, client, "GET", authURL, nil, redirectURI)
	if err != nil {
		return nil, err
	}
	if callback == "" {
		// A >=400 rendered AT the authorization endpoint itself (no redirect)
		// is how node-oidc reports the regressions this suite must catch —
		// unknown client_id, redirect_uri mismatch — so it is a hard failure,
		// never a skip. (Error redirects back to redirect_uri are caught via
		// the callback's `error` param below.)
		authPath := ""
		if u, perr := url.Parse(authorizationEndpoint); perr == nil {
			authPath = u.Path
		}
		if resp.StatusCode >= http.StatusBadRequest && resp.Request.URL.Path == authPath {
			return nil, fmt.Errorf("authorization endpoint rejected the request: %d at %s",
				resp.StatusCode, resp.Request.URL)
		}
		// Providers without node-oidc's devInteractions redirect AWAY to a
		// real (or missing) browser login UI — e.g. IdentityServer's
		// /Account/Login 404s in the headless fixture. That shape means
		// "no headless login": signal skip, not failure.
		if resp.StatusCode >= http.StatusBadRequest ||
			!strings.Contains(resp.Request.URL.Path, "/interaction/") {
			return nil, fmt.Errorf("%w (landed on %s with status %d)",
				ErrNoDevInteractions, resp.Request.URL, resp.StatusCode)
		}
		// devInteractions login: a single endpoint dispatches on the
		// `prompt` field (mirrors the Python suite's _submit_login).
		resp, callback, err = followRedirects(ctx, client, "POST", resp.Request.URL.String(), url.Values{
			"prompt":   {"login"},
			"login":    {devLoginHint},
			"password": {devLoginPassword},
		}, redirectURI)
		if err != nil {
			return nil, err
		}
		if callback == "" && resp.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("login failed: %d at %s", resp.StatusCode, resp.Request.URL)
		}
	}
	if callback == "" && strings.Contains(resp.Request.URL.Path, "/interaction/") {
		// Second interaction page: consent.
		resp, callback, err = followRedirects(ctx, client, "POST", resp.Request.URL.String(), url.Values{
			"prompt": {"consent"},
		}, redirectURI)
		if err != nil {
			return nil, err
		}
		if callback == "" && resp.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("consent failed: %d at %s", resp.StatusCode, resp.Request.URL)
		}
	}
	if callback == "" {
		return nil, fmt.Errorf("auth code flow did not reach %s (stalled at %s)",
			redirectURI, resp.Request.URL)
	}

	cbURL, err := url.Parse(callback)
	if err != nil {
		return nil, fmt.Errorf("parse callback %q: %w", callback, err)
	}
	q := cbURL.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("authorization error at callback: %s (%s)",
			e, q.Get("error_description"))
	}
	code := q.Get("code")
	if code == "" {
		return nil, fmt.Errorf("callback carried no code: %s", callback)
	}
	return &AuthCodeResult{Code: code, State: q.Get("state")}, nil
}

// followRedirects issues one request and walks its redirect chain, stopping
// early when a Location targets redirectURI (returned as callback) so the
// unserved callback address is never dialed. The final response body is
// drained and closed; resp is returned for its Request.URL.
func followRedirects(
	ctx context.Context,
	client *http.Client,
	method, target string,
	form url.Values,
	redirectURI string,
) (resp *http.Response, callback string, err error) {
	var body io.Reader
	contentType := ""
	if form != nil {
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, "", err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	for hop := 0; ; hop++ {
		resp, err = client.Do(req)
		if err != nil {
			return nil, "", err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			// Error statuses are returned, not raised — the caller decides
			// whether a 4xx means "no headless UI" (skip) or a real failure.
			return resp, "", nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, "", fmt.Errorf("redirect without Location at %s", resp.Request.URL)
		}
		next, err := resp.Request.URL.Parse(loc)
		if err != nil {
			return nil, "", fmt.Errorf("resolve redirect %q: %w", loc, err)
		}
		if strings.HasPrefix(next.String(), redirectURI) {
			return resp, next.String(), nil
		}
		if hop >= maxFlowRedirects {
			return nil, "", fmt.Errorf("too many redirects (>%d), last %s", maxFlowRedirects, next)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return nil, "", err
		}
	}
}
