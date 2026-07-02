// Package jwt validates compact-serialized JWTs: it verifies the JWS signature
// using the key resolved by the header kid from a [jwks.JSONWebKeySet] and
// checks the registered claims (iss, aud, exp, nbf, iat).
//
// The entry point is [Validate], configured with functional options
// ([WithExpectedIssuer], [WithExpectedAudience], [WithExpectedNonce],
// [WithClockSkew], [WithRequiredClaims], [WithAllowedAlgorithms]). It returns a
// typed [Claims] value exposing the registered claims plus generic accessors
// for custom claims.
//
// Security posture:
//   - The unsecured "none" algorithm is rejected unconditionally, before any
//     key resolution (RFC 7519 §7.2).
//   - Only asymmetric signature algorithms are accepted by default (RS/PS/ES
//     256/384/512); the symmetric HS* family is excluded so an attacker cannot
//     forge a token by signing with a provider's public key as an HMAC secret
//     (algorithm confusion).
//   - A kid absent from the cached key set triggers exactly one JWKS forced
//     refresh and retry before failing, handling key rotation (RFC 7517 §4.5).
//
// RFC / spec references: RFC 7519 (JWT), RFC 7515 (JWS), RFC 7518 (JWA),
// OIDC Core 1.0 §3.1.3.7 (ID Token Validation). The behavioural contract is in
// spec/capabilities.md and spec/conformance/validation.json (IDs JWT-001..013).
package jwt
