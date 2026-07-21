package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes caps the revocation error-response read to guard against an
// unbounded body (memory-exhaustion DoS). A revocation success carries no body
// and error bodies are small.
const maxBodyBytes = 1 << 20

// reservedParams are owned by the request and client-authentication logic. They
// can never be set or overridden via [WithExtraParams], so caller-supplied
// extras cannot contradict the request's identity (e.g. injecting a body
// client_id that disagrees with the Basic-auth credentials) or the token being
// revoked.
var reservedParams = map[string]bool{
	"token":           true,
	"token_type_hint": true,
	"client_id":       true,
	"client_secret":   true,
}

// Revoke performs an OAuth 2.0 token revocation request (RFC 7009 §2.1): it
// POSTs token to revocationEndpoint as application/x-www-form-urlencoded and
// authenticates the revoking client. Resolve revocationEndpoint from the
// revocation_endpoint field of the discovery document (RFC 8414 §2).
//
// By default the client authenticates with client_secret_basic; use
// [WithClientAuth] to switch to client_secret_post. Attach the optional
// token_type_hint with [WithTokenTypeHint].
//
// The server returns HTTP 200 regardless of whether the token was valid,
// expired, already revoked, or unknown, and MUST NOT differentiate between those
// cases (§2.1). Revoke therefore returns nil for any 2xx response without
// parsing a body. A non-2xx OAuth error response — an HTTP 401 invalid_client or
// HTTP 400 unsupported_token_type — is returned as a typed [RevocationError]
// (§2.2.1).
func Revoke(ctx context.Context, revocationEndpoint, clientID, clientSecret, token string, opts ...Option) error {
	cfg := newConfig(opts...)

	parsed, err := url.Parse(revocationEndpoint)
	if err != nil {
		return &RequestError{Op: "parse revocation endpoint", Err: err}
	}
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return &RequestError{Op: "revocation endpoint", Err: fmt.Errorf("https required for %q (use WithInsecureAllowHTTP for http)", revocationEndpoint)}
	}
	if parsed.Host == "" {
		return &RequestError{Op: "revocation endpoint", Err: fmt.Errorf("endpoint has no host: %q", revocationEndpoint)}
	}

	form := url.Values{}
	form.Set("token", token)
	if cfg.tokenTypeHint != "" {
		form.Set("token_type_hint", cfg.tokenTypeHint)
	}

	// Client authentication (RFC 7009 §2.1, RFC 6749 §2.3). A Basic header is set
	// on the request after it is built; post credentials go in the body.
	useBasic := false
	switch {
	case clientID == "" || clientSecret == "":
		// Both client_secret_basic and client_secret_post require a full
		// credential pair; a half-credential would emit a malformed auth request
		// that only fails server-side, so reject it before hitting the network.
		return &RequestError{Op: "client authentication", Err: fmt.Errorf("revocation endpoint requires client authentication with both client_id and client_secret (RFC 7009 §2.1)")}
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

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, revocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return &RequestError{Op: "build request", Err: err}
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
		return &RequestError{Op: fmt.Sprintf("post %s", revocationEndpoint), Err: err}
	}
	defer resp.Body.Close()

	// A revocation success (§2.2) carries no meaningful body. Any 2xx is success
	// regardless of token validity (§2.1); drain a bounded amount so the
	// connection can be reused, then return nil.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return nil
	}

	// Non-2xx is an OAuth error (RFC 7009 §2.2.1, RFC 6749 §5.2).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return &RequestError{Op: "read error response", StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > maxBodyBytes {
		return &RequestError{Op: "read error response", StatusCode: resp.StatusCode, Err: fmt.Errorf("response exceeds %d bytes", maxBodyBytes)}
	}

	re := &RevocationError{StatusCode: resp.StatusCode}
	if err := json.Unmarshal(body, re); err == nil && re.Code != "" {
		return re
	}
	return &RequestError{Op: "revocation request", StatusCode: resp.StatusCode, Err: fmt.Errorf("non-OAuth error body: %s", snippet(body))}
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
