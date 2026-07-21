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
	// grantTokenExchange is the RFC 8693 token exchange grant type URI.
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// maxBodyBytes caps the token response read to guard against an unbounded
	// body (memory-exhaustion DoS). Token responses are small.
	maxBodyBytes = 1 << 20
)

// Token type identifier URIs for RFC 8693 token exchange (RFC 8693 §3). They
// are used verbatim as the subject_token_type, actor_token_type,
// requested_token_type request parameters and the issued_token_type response
// field.
const (
	// TokenTypeAccessToken identifies an OAuth 2.0 access token.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// TokenTypeRefreshToken identifies an OAuth 2.0 refresh token.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	// TokenTypeIDToken identifies an OIDC ID token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// TokenTypeSAML1 identifies a SAML 1.1 assertion.
	TokenTypeSAML1 = "urn:ietf:params:oauth:token-type:saml1"
	// TokenTypeSAML2 identifies a SAML 2.0 assertion.
	TokenTypeSAML2 = "urn:ietf:params:oauth:token-type:saml2"
	// TokenTypeJWT identifies a JWT that is not one of the more specific types.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

// reservedParams are owned by the grant and client-authentication logic. They
// can never be set or overridden via [WithExtraParams], so that caller-supplied
// extras cannot contradict the request's identity (e.g. injecting a body
// client_id that disagrees with the Basic-auth credentials) or its grant shape.
// Note: resource, audience, and requested_token_type are intentionally NOT
// reserved. They are non-identity target/output hints that callers may also
// supply via WithExtraParams on any grant (e.g. an RFC 8707 resource on the
// client credentials grant); the token exchange grant sets them via its own
// options, and the extra-params loop skips any key already present in the form.
var reservedParams = map[string]bool{
	"grant_type":         true,
	"client_id":          true,
	"client_secret":      true,
	"code":               true,
	"redirect_uri":       true,
	"code_verifier":      true,
	"scope":              true,
	"subject_token":      true,
	"subject_token_type": true,
	"actor_token":        true,
	"actor_token_type":   true,
}

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

// TokenExchange performs the OAuth 2.0 token exchange grant (RFC 8693 §2.1): it
// POSTs grant_type=urn:ietf:params:oauth:grant-type:token-exchange with the
// subject token to tokenEndpoint and returns the typed [TokenResponse],
// including the RFC 8693 §2.2 issued_token_type.
//
// subjectToken and subjectTokenType are REQUIRED. subjectTokenType is one of the
// TokenType* URIs (RFC 8693 §3). Supplying only the subject token requests an
// impersonation token; add [WithActorToken] for a delegation exchange
// (RFC 8693 §1.1). Target the exchange with [WithResource], [WithAudience],
// [WithScopes], and [WithRequestedTokenType].
//
// By default the client authenticates with client_secret_basic; use
// [WithClientAuth] to switch to client_secret_post. A non-2xx OAuth error
// response is returned as a typed [TokenError] (RFC 6749 §5.2).
func TokenExchange(ctx context.Context, tokenEndpoint, clientID, clientSecret, subjectToken, subjectTokenType string, opts ...Option) (*TokenResponse, error) {
	cfg := newConfig(opts...)

	if subjectToken == "" {
		return nil, fmt.Errorf("%w: subject_token is required", ErrInvalidTokenExchange)
	}
	if subjectTokenType == "" {
		return nil, fmt.Errorf("%w: subject_token_type is required", ErrInvalidTokenExchange)
	}
	// actor_token_type is REQUIRED whenever actor_token is present (RFC 8693 §2.1).
	if cfg.actorToken != "" && cfg.actorTokenType == "" {
		return nil, fmt.Errorf("%w: actor_token_type is required when actor_token is set", ErrInvalidTokenExchange)
	}

	form := url.Values{}
	form.Set("grant_type", grantTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenType)
	if cfg.actorToken != "" {
		form.Set("actor_token", cfg.actorToken)
		form.Set("actor_token_type", cfg.actorTokenType)
	}
	if cfg.requestedTokenType != "" {
		form.Set("requested_token_type", cfg.requestedTokenType)
	}
	if len(cfg.scopes) > 0 {
		form.Set("scope", strings.Join(cfg.scopes, " "))
	}
	// resource and audience MAY each appear more than once (RFC 8693 §2.1).
	for _, r := range cfg.resources {
		form.Add("resource", r)
	}
	for _, a := range cfg.audiences {
		form.Add("audience", a)
	}

	return doTokenRequest(ctx, cfg, tokenEndpoint, clientID, clientSecret, form)
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

	// Extra params are applied last but never override reserved grant or
	// client-auth parameters (whether or not they are already present in the
	// form — on the Basic path client_id is absent from the body yet must not
	// be injectable).
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
