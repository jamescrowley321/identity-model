package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
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

// reservedParams are owned by the grant and client-authentication logic on
// every grant. They can never be set or overridden via [WithExtraParams], so
// that caller-supplied extras cannot contradict the request's identity (e.g.
// injecting a body client_id that disagrees with the Basic-auth credentials) or
// its grant shape. Keys are matched after [normalizeParamKey], because a server
// whose form parser folds case or trims would otherwise accept "Client_ID" or
// " client_id" as the real parameter.
//
// resource, audience and requested_token_type are deliberately absent from this
// set: they are non-identity targeting hints that a caller may legitimately
// supply via [WithExtraParams] on a grant that has no dedicated option for them
// (e.g. an RFC 8707 resource on the client credentials grant). They are instead
// reserved on the token exchange path alone, via [exchangeReservedParams].
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
	// Private-key/secret JWT client authentication (RFC 7523 §2.2, RFC 7521
	// §4.2): an injected assertion would authenticate the request as a client
	// the caller was never issued credentials for.
	"client_assertion":      true,
	"client_assertion_type": true,
}

// exchangeReservedParams are reserved on the token exchange path only, in
// addition to [reservedParams]. RFC 8693 §2.1 makes resource, audience and
// requested_token_type part of how an exchange is targeted and what it asks to
// have issued, and [TokenExchange] sources all three from its own options
// ([WithResource], [WithAudience], [WithRequestedTokenType]). An extra param
// must therefore neither inject one the caller never pinned nor override one
// they did. Other grants are unaffected and may still set these keys via
// [WithExtraParams].
var exchangeReservedParams = map[string]bool{
	"resource":             true,
	"audience":             true,
	"requested_token_type": true,
}

// normalizeParamKey folds an extra-param key to the form the reserved sets are
// keyed in. Reservation is enforced on the normalized key because an
// authorization server's form parser is not required to be byte-exact: ASP.NET
// IFormCollection and Duende IdentityServer, among others, fold case and trim
// surrounding whitespace, so "Audience" or " audience" sent verbatim would reach
// such a server as the reserved parameter itself.
func normalizeParamKey(k string) string {
	return strings.ToLower(strings.TrimSpace(k))
}

// firstReservedExtra reports the lowest-sorted key of extras that grantReserved
// reserves, comparing keys via [normalizeParamKey]. Go map iteration order is
// randomized, so the keys are sorted to keep the reported key (and therefore the
// error message) stable when several collide.
func firstReservedExtra(extras map[string]string, grantReserved map[string]bool) (string, bool) {
	var collisions []string
	for k := range extras {
		if grantReserved[normalizeParamKey(k)] {
			collisions = append(collisions, k)
		}
	}
	if len(collisions) == 0 {
		return "", false
	}
	sort.Strings(collisions)
	return collisions[0], true
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

	return doTokenRequest(ctx, cfg, tokenEndpoint, clientID, clientSecret, form, nil)
}

// AuthorizationCode performs the OAuth 2.0 authorization code grant
// (RFC 6749 §4.1.3): it POSTs grant_type=authorization_code with code and
// redirect_uri to tokenEndpoint and returns the typed [TokenResponse].
//
// By default this targets a public client (no client secret): identify the
// client with clientID, which is sent in the request body, and attach a PKCE
// verifier with [WithCodeVerifier] (RFC 7636 §4.5). For a confidential client,
// supply the secret with [WithClientSecret]; it is presented via the configured
// [ClientAuthMethod] (client_secret_basic by default, or client_secret_post via
// [WithClientAuth]). A non-2xx OAuth error response is returned as a typed
// [TokenError].
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

	// cfg.clientSecret is "" for a public client (identified via client_id in
	// the body) or the confidential secret from [WithClientSecret], which
	// doTokenRequest presents per the configured ClientAuthMethod.
	return doTokenRequest(ctx, cfg, tokenEndpoint, clientID, cfg.clientSecret, form, nil)
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
	// A colliding extra param is rejected before anything is sent rather than
	// dropped from the form. Dropping it would turn an injection attempt into the
	// silent loss of a restriction: a caller who pinned an audience through
	// [WithExtraParams] would send no audience at all, get a 200, and receive a
	// token broader than the one they asked for with no signal that it happened.
	if k, ok := firstReservedExtra(cfg.extraParams, exchangeReservedParams); ok {
		return nil, fmt.Errorf("%w: %s must be set via its option (WithResource/WithAudience/WithRequestedTokenType), not WithExtraParams", ErrInvalidTokenExchange, k)
	}
	// An actor token counts as supplied when [WithActorToken] was applied, not
	// when the string happens to be non-empty: an empty actor token sourced from
	// an env lookup or header would otherwise be dropped from the form, silently
	// downgrading the requested delegation to an impersonation exchange whose
	// issued token carries the subject's full authority with no act claim
	// (RFC 8693 §1.1).
	if cfg.actorTokenSet {
		if cfg.actorToken == "" {
			return nil, fmt.Errorf("%w: actor_token must not be empty when provided", ErrInvalidTokenExchange)
		}
		// actor_token_type is REQUIRED whenever actor_token is present
		// (RFC 8693 §2.1).
		if cfg.actorTokenType == "" {
			return nil, fmt.Errorf("%w: actor_token_type is required when actor_token is set", ErrInvalidTokenExchange)
		}
	}

	form := url.Values{}
	form.Set("grant_type", grantTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenType)
	if cfg.actorTokenSet {
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

	resp, err := doTokenRequest(ctx, cfg, tokenEndpoint, clientID, clientSecret, form, exchangeReservedParams)
	if err != nil {
		return nil, err
	}
	// token_type is REQUIRED in a successful response (RFC 6749 §5.1, restated by
	// RFC 8693 §2.2.1); a 200 that omits it is non-conformant. Without it a
	// caller applying the §2.2.1 bearer test (token_type != "N_A") would treat an
	// unknown, possibly non-bearer credential as a Bearer token.
	if resp.TokenType == "" {
		return nil, &RequestError{Op: "token exchange response", Err: fmt.Errorf("missing token_type")}
	}
	// issued_token_type is REQUIRED in a successful token exchange response
	// (RFC 8693 §2.2); a 200 that omits it is non-conformant.
	if resp.IssuedTokenType == "" {
		return nil, &RequestError{Op: "token exchange response", Err: fmt.Errorf("missing issued_token_type")}
	}
	return resp, nil
}

// doTokenRequest applies client authentication and extra parameters, POSTs the
// form to endpoint as application/x-www-form-urlencoded, and decodes the
// response: a 2xx body into [TokenResponse], otherwise an OAuth error body into
// [TokenError] (status checked before decode).
//
// grantReserved names parameters reserved by the calling grant on top of the
// package-wide [reservedParams]; it may be nil for a grant that reserves nothing
// extra.
func doTokenRequest(ctx context.Context, cfg *config, endpoint, clientID, clientSecret string, form url.Values, grantReserved map[string]bool) (*TokenResponse, error) {
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
	// be injectable), nor any parameter the calling grant reserves for itself.
	// The grantReserved arm is defence in depth: [TokenExchange] rejects such a
	// key outright, so it is unreachable from there.
	for k, v := range cfg.extraParams {
		nk := normalizeParamKey(k)
		if reservedParams[nk] || grantReserved[nk] || form.Has(k) {
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
