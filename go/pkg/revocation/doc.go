// Package revocation is a client for the OAuth 2.0 Token Revocation endpoint
// (RFC 7009).
//
// [Revoke] POSTs the token to the revocation endpoint as
// application/x-www-form-urlencoded, authenticates the revoking client, and
// reports success or a typed error. A revocation success carries no response
// body: the server returns HTTP 200 regardless of whether the token was valid,
// expired, already revoked, or unknown, and MUST NOT differentiate between
// those cases so that a client cannot probe token state (§2.1). [Revoke]
// therefore returns nil for any 2xx response without attempting to parse a
// body.
//
// The revocation endpoint is protected (§2.1). By default the client
// authenticates with client_secret_basic; use [WithClientAuth] to switch to
// client_secret_post. Attach the optional token_type_hint with
// [WithTokenTypeHint] (§2.1) — the server MAY use it to optimize lookup but MUST
// accept the request even if the hint is incorrect.
//
// The endpoint URL SHOULD be resolved from the revocation_endpoint field of the
// Authorization Server Metadata / OIDC Discovery document (RFC 8414 §2) rather
// than configured by hand; see the discovery package's RevocationEndpoint.
//
// Errors are typed: a non-2xx response carrying an OAuth error body becomes a
// [RevocationError] with the error code (e.g. invalid_client on HTTP 401 or
// unsupported_token_type on HTTP 400) and the HTTP status (§2.2.1); transport
// and configuration failures become a [RequestError]. Both match the package
// sentinels via errors.Is.
//
// Example — revoking a refresh token during logout:
//
//	cfg, _ := discovery.FetchConfiguration(ctx, issuer)
//	err := revocation.Revoke(ctx, cfg.RevocationEndpoint,
//		clientID, clientSecret, refreshToken,
//		revocation.WithTokenTypeHint("refresh_token"))
//	if err != nil {
//		var re *revocation.RevocationError
//		if errors.As(err, &re) {
//			log.Printf("revocation rejected (HTTP %d): %s", re.StatusCode, re.Code)
//		}
//		return err
//	}
//	// Token is now revoked (or was already invalid — indistinguishable by design).
//
// The conformance suite for this package is spec/conformance/revocation.json
// (REV-001..005).
package revocation
