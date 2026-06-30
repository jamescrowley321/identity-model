package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	grantClientCredentials = "client_credentials"
	grantAuthorizationCode = "authorization_code"

	// maxBodyBytes caps the token response read to guard against an unbounded
	// body (memory-exhaustion DoS). Token responses are small.
	maxBodyBytes = 1 << 20
)

// ClientCredentials performs the OAuth 2.0 client credentials grant
// (RFC 6749 §4.4): it POSTs grant_type=client_credentials to tokenEndpoint and
// returns the typed [TokenResponse].
//
// By default the client authenticates with client_secret_basic; use
// [WithClientAuth] to switch to client_secret_post. Request the granted scope
// with [WithScopes] (CC-005). A non-2xx OAuth error response is returned as a
// typed [TokenError] (CC-004).
func ClientCredentials(ctx context.Context, tokenEndpoint, clientID, clientSecret string, opts ...Option) (*TokenResponse, error) {
	cfg := newConfig(opts...)

	form := url.Values{}
	form.Set("grant_type", grantClientCredentials)
	if len(cfg.scopes) > 0 {
		form.Set("scope", strings.Join(cfg.scopes, " "))
	}

	return doTokenRequest(ctx, cfg, tokenEndpoint, clientID, clientSecret, form)
}

// AuthorizationCode performs the OAuth 2.0 authorization code grant
// (RFC 6749 §4.1.3): it POSTs grant_type=authorization_code with code and
// redirect_uri to tokenEndpoint and returns the typed [TokenResponse].
//
// This entry point targets public clients (no client secret); identify the
// client with clientID, which is sent in the request body. Attach a PKCE
// verifier with [WithCodeVerifier] (RFC 7636 §4.5). A non-2xx OAuth error
// response is returned as a typed [TokenError].
func AuthorizationCode(ctx context.Context, tokenEndpoint, clientID, code, redirectURI string, opts ...Option) (*TokenResponse, error) {
	cfg := newConfig(opts...)

	if cfg.codeVerifier != "" && !validCodeVerifier(cfg.codeVerifier) {
		return nil, fmt.Errorf("%w: must be 43-128 unreserved characters", ErrInvalidCodeVerifier)
	}

	form := url.Values{}
	form.Set("grant_type", grantAuthorizationCode)
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	if cfg.codeVerifier != "" {
		form.Set("code_verifier", cfg.codeVerifier)
	}

	// A public client has no secret: pass an empty secret so doTokenRequest
	// identifies it via client_id in the body rather than a Basic header.
	return doTokenRequest(ctx, cfg, tokenEndpoint, clientID, "", form)
}

// doTokenRequest applies client authentication and extra parameters, POSTs the
// form to endpoint as application/x-www-form-urlencoded, and decodes the
// response: a 2xx body into [TokenResponse], otherwise an OAuth error body into
// [TokenError] (status checked before decode).
func doTokenRequest(ctx context.Context, cfg *config, endpoint, clientID, clientSecret string, form url.Values) (*TokenResponse, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, &RequestError{Op: "parse token endpoint", Err: err}
	}
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, &RequestError{Op: "token endpoint", Err: fmt.Errorf("https required for %q (use WithInsecureAllowHTTP for http)", endpoint)}
	}

	// Client authentication (RFC 6749 §2.3). A Basic header is set on the
	// request after it is built; post/public credentials go in the form body.
	useBasic := false
	switch {
	case clientSecret == "":
		// Public client: identify via client_id in the body.
		if clientID != "" {
			form.Set("client_id", clientID)
		}
	case cfg.authMethod == ClientSecretPost:
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	default: // ClientSecretBasic
		useBasic = true
	}

	// Extra params are applied last but never override reserved grant
	// parameters already present.
	for k, v := range cfg.extraParams {
		if form.Has(k) {
			continue
		}
		form.Set(k, v)
	}

	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &RequestError{Op: "build request", Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useBasic {
		// RFC 6749 §2.3.1: form-urlencode the credentials before HTTP Basic
		// encoding so reserved characters survive.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Op: fmt.Sprintf("post %s", endpoint), Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > maxBodyBytes {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: fmt.Errorf("response exceeds %d bytes", maxBodyBytes)}
	}

	// Status before decode: a non-2xx response is an OAuth error (RFC 6749 §5.2).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		te := &TokenError{StatusCode: resp.StatusCode}
		if err := json.Unmarshal(body, te); err == nil && te.Code != "" {
			return nil, te
		}
		return nil, &RequestError{Op: "token request", StatusCode: resp.StatusCode, Err: fmt.Errorf("non-OAuth error body: %s", snippet(body))}
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, &RequestError{Op: "decode token response", StatusCode: resp.StatusCode, Err: err}
	}
	if tr.AccessToken == "" {
		return nil, &RequestError{Op: "token response", StatusCode: resp.StatusCode, Err: fmt.Errorf("missing access_token")}
	}
	return &tr, nil
}

// snippet returns a short, single-line view of an unexpected response body for
// error messages.
func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
