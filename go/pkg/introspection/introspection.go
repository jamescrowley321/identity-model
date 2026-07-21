package introspection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes caps the introspection response read to guard against an
// unbounded body (memory-exhaustion DoS). Introspection responses are small.
const maxBodyBytes = 1 << 20

// reservedParams are owned by the request and client-authentication logic. They
// can never be set or overridden via [WithExtraParams], so caller-supplied
// extras cannot contradict the request's identity (e.g. injecting a body
// client_id that disagrees with the Basic-auth credentials) or the token being
// introspected.
var reservedParams = map[string]bool{
	"token":           true,
	"token_type_hint": true,
	"client_id":       true,
	"client_secret":   true,
}

// Introspect performs an OAuth 2.0 token introspection request (RFC 7662 §2.1):
// it POSTs token to introspectionEndpoint as application/x-www-form-urlencoded,
// authenticates the introspecting client, and returns the typed
// [Introspection]. Resolve introspectionEndpoint from the introspection_endpoint
// field of the discovery document (RFC 8414 §2).
//
// By default the client authenticates with client_secret_basic; use
// [WithClientAuth] to switch to client_secret_post. Attach the optional
// token_type_hint with [WithTokenTypeHint]. A non-2xx OAuth error response —
// typically an HTTP 401 invalid_client — is returned as a typed
// [IntrospectionError] (RFC 7662 §2.3).
func Introspect(ctx context.Context, introspectionEndpoint, clientID, clientSecret, token string, opts ...Option) (*Introspection, error) {
	cfg := newConfig(opts...)

	parsed, err := url.Parse(introspectionEndpoint)
	if err != nil {
		return nil, &RequestError{Op: "parse introspection endpoint", Err: err}
	}
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, &RequestError{Op: "introspection endpoint", Err: fmt.Errorf("https required for %q (use WithInsecureAllowHTTP for http)", introspectionEndpoint)}
	}
	if parsed.Host == "" {
		return nil, &RequestError{Op: "introspection endpoint", Err: fmt.Errorf("endpoint has no host: %q", introspectionEndpoint)}
	}

	form := url.Values{}
	form.Set("token", token)
	if cfg.tokenTypeHint != "" {
		form.Set("token_type_hint", cfg.tokenTypeHint)
	}

	// Client authentication (RFC 7662 §2.1, RFC 6749 §2.3). A Basic header is
	// set on the request after it is built; post credentials go in the body.
	useBasic := false
	switch {
	case clientID == "" || clientSecret == "":
		// Both client_secret_basic and client_secret_post require a full
		// credential pair; a half-credential would emit a malformed auth request
		// that only fails server-side, so reject it before hitting the network.
		return nil, &RequestError{Op: "client authentication", Err: fmt.Errorf("introspection endpoint requires client authentication with both client_id and client_secret (RFC 7662 §2.1)")}
	case cfg.authMethod == ClientSecretPost:
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	default: // ClientSecretBasic
		useBasic = true
	}

	// Extra params are applied last but never override the reserved request or
	// client-auth parameters (whether or not already present — on the Basic path
	// client_id is absent from the body yet must not be injectable).
	for k, v := range cfg.extraParams {
		if reservedParams[k] || form.Has(k) {
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

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, introspectionEndpoint, strings.NewReader(form.Encode()))
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
		return nil, &RequestError{Op: fmt.Sprintf("post %s", introspectionEndpoint), Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > maxBodyBytes {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: fmt.Errorf("response exceeds %d bytes", maxBodyBytes)}
	}

	// Status before decode: a non-2xx response is an OAuth error (RFC 7662 §2.3,
	// RFC 6749 §5.2).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		ie := &IntrospectionError{StatusCode: resp.StatusCode}
		if err := json.Unmarshal(body, ie); err == nil && ie.Code != "" {
			return nil, ie
		}
		return nil, &RequestError{Op: "introspection request", StatusCode: resp.StatusCode, Err: fmt.Errorf("non-OAuth error body: %s", snippet(body))}
	}

	var ir Introspection
	if err := json.Unmarshal(body, &ir); err != nil {
		return nil, &RequestError{Op: "decode introspection response", StatusCode: resp.StatusCode, Err: err}
	}
	return &ir, nil
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
