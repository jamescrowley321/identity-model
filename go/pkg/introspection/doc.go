// Package introspection is a client for the OAuth 2.0 Token Introspection
// endpoint (RFC 7662).
//
// [Introspect] POSTs the token to the introspection endpoint as
// application/x-www-form-urlencoded, authenticates the introspecting client,
// and decodes the response into a typed [Introspection]. The only field
// guaranteed present is Active; the standard §2.2 metadata members (scope,
// client_id, username, token_type, exp, iat, nbf, sub, aud, iss, jti) are
// exposed as typed fields and any additional members remain reachable via
// [Introspection.Extra].
//
// The introspection endpoint is protected (§2.1). By default the client
// authenticates with client_secret_basic; use [WithClientAuth] to switch to
// client_secret_post. Attach the optional token_type_hint with
// [WithTokenTypeHint] (§2.1) — the server MAY use it to optimize lookup but MUST
// NOT fail on an incorrect hint.
//
// The endpoint URL SHOULD be resolved from the introspection_endpoint field of
// the Authorization Server Metadata / OIDC Discovery document (RFC 8414 §2)
// rather than configured by hand; see the discovery package's
// IntrospectionEndpoint.
//
// Errors are typed: an HTTP 401 (or any non-2xx) carrying an OAuth error body
// becomes an [IntrospectionError] with the error code (e.g. invalid_client) and
// the HTTP status (§2.3); transport, decode, and configuration failures become a
// [RequestError]. Both match the package sentinels via errors.Is.
//
// Example:
//
//	cfg, _ := discovery.FetchConfiguration(ctx, issuer)
//	resp, err := introspection.Introspect(ctx, cfg.IntrospectionEndpoint,
//		clientID, clientSecret, token,
//		introspection.WithTokenTypeHint("access_token"))
//	if err != nil {
//		var ie *introspection.IntrospectionError
//		if errors.As(err, &ie) {
//			log.Printf("introspection rejected (HTTP %d): %s", ie.StatusCode, ie.Code)
//		}
//		return err
//	}
//	if resp.Active {
//		fmt.Println(resp.Sub, resp.Scope, resp.Extra)
//	}
//
// The conformance suite for this package is spec/conformance/introspection.json
// (INTR-001..006).
package introspection
