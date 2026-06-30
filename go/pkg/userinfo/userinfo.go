package userinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes caps the UserInfo response read to guard against an unbounded
// body (memory-exhaustion DoS). UserInfo responses are small.
const maxBodyBytes = 1 << 20

// Fetch retrieves the end-user's claims from the OIDC UserInfo endpoint
// (OIDC Core 1.0 §5.3). It GETs userInfoEndpoint with an
// "Authorization: Bearer {accessToken}" header (RFC 6750 §2.1) and decodes the
// JSON response into a typed [UserInfoResponse], preserving any non-standard
// claims in the response's claim map.
//
// A non-2xx response is returned as a typed [UserInfoError] carrying the HTTP
// status and any WWW-Authenticate challenge. Supply the expected subject with
// [WithSubjectValidation] to require that the UserInfo "sub" matches the ID
// token's "sub"; a mismatch is reported as a [SubjectMismatchError].
func Fetch(ctx context.Context, userInfoEndpoint, accessToken string, opts ...Option) (*UserInfoResponse, error) {
	cfg := newConfig(opts...)

	parsed, err := url.Parse(userInfoEndpoint)
	if err != nil {
		return nil, &RequestError{Op: "parse userinfo endpoint", Err: err}
	}
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, &RequestError{Op: "userinfo endpoint", Err: fmt.Errorf("https required for %q (use WithInsecureAllowHTTP for http)", userInfoEndpoint)}
	}
	if parsed.Host == "" {
		return nil, &RequestError{Op: "userinfo endpoint", Err: fmt.Errorf("endpoint has no host: %q", userInfoEndpoint)}
	}
	if accessToken == "" {
		return nil, &RequestError{Op: "userinfo request", Err: fmt.Errorf("access token is required")}
	}

	reqCtx := ctx
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	} else {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, defaultRequestTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, &RequestError{Op: "build request", Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Op: fmt.Sprintf("get %s", userInfoEndpoint), Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > maxBodyBytes {
		return nil, &RequestError{Op: "read response", StatusCode: resp.StatusCode, Err: fmt.Errorf("response exceeds %d bytes", maxBodyBytes)}
	}

	// Status before decode: a non-2xx response is an error. A Bearer-protected
	// resource describes the failure in the WWW-Authenticate header (RFC 6750 §3).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &UserInfoError{
			StatusCode:      resp.StatusCode,
			WWWAuthenticate: resp.Header.Get("WWW-Authenticate"),
			Body:            snippet(body),
		}
	}

	// A signed or encrypted UserInfo response is served as application/jwt
	// (§5.3.2). That is out of scope for this client, which handles only the
	// JSON serialization; surface it as a descriptive error rather than failing
	// to parse opaque JWT bytes as JSON.
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType == "application/jwt" {
		return nil, &RequestError{Op: "userinfo response", StatusCode: resp.StatusCode, Err: fmt.Errorf("signed/encrypted UserInfo (application/jwt) is not supported")}
	}

	var ui UserInfoResponse
	if err := json.Unmarshal(body, &ui); err != nil {
		return nil, &RequestError{Op: "decode userinfo response", StatusCode: resp.StatusCode, Err: err}
	}
	if ui.Sub == "" {
		return nil, &RequestError{Op: "userinfo response", StatusCode: resp.StatusCode, Err: fmt.Errorf("missing sub claim")}
	}

	// Subject consistency: the UserInfo sub MUST match the ID token sub
	// (OIDC Core 1.0 §5.3.2) to defend against token substitution.
	if cfg.validateSub && ui.Sub != cfg.expectedSub {
		return nil, &SubjectMismatchError{Expected: cfg.expectedSub, Actual: ui.Sub}
	}

	return &ui, nil
}

// snippet returns a short, single-line view of an unexpected response body for
// error messages.
func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	// Truncate on a rune boundary so a multi-byte UTF-8 sequence in the body is
	// never cut in half, which would emit invalid UTF-8 in the diagnostic string.
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}
