// Package token is a token endpoint client for the OAuth 2.0 client
// credentials and authorization code grants, including PKCE.
//
// [ClientCredentials] performs the client credentials grant (RFC 6749 §4.4),
// authenticating with client_secret_basic (default) or client_secret_post
// (RFC 6749 §2.3). [AuthorizationCode] performs the authorization code grant
// (RFC 6749 §4.1.3) for public clients, with optional PKCE via
// [WithCodeVerifier]. [GenerateCodeVerifier] and [S256Challenge] implement the
// PKCE transform (RFC 7636 §4.1–4.2).
//
// Successful responses decode into a typed [TokenResponse] (RFC 6749 §5.1);
// error responses decode into a typed [TokenError] (RFC 6749 §5.2). Requests
// are customised with the functional With* options.
//
// Behavioural contract: spec/conformance/client-credentials.json (CC-001..006)
// and spec/conformance/authorization-code.json (ACG-001..006); see also
// spec/capabilities.md.
package token
