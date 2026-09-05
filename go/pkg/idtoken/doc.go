// Package idtoken validates OpenID Connect ID Tokens against the profile rules
// that make an ID Token an ID Token — the checks layered on top of the standard
// JWT validation performed by package jwt (signature via JWKS, iss/aud/iat/exp).
//
// It mirrors the OIDF-certified py-identity-model reference implementation
// (py/src/py_identity_model/core/id_token_logic.py) byte-for-byte, per OpenID
// Connect Core 1.0 §2, §3.1.3.7 and §3.3.2.11:
//
//   - sub is REQUIRED and must be non-empty (§2 / §3.1.3.7).
//   - azp authorized-party rules: a token with multiple audiences MUST carry an
//     azp; when present, azp MUST identify this client (§3.1.3.7 steps 4-6).
//   - nonce binding, when the caller supplies the nonce it sent on the
//     authorization request (§3.1.3.7 step 11).
//   - auth_time freshness against a requested max_age (§3.1.3.7 step 12).
//   - at_hash / c_hash token- and code-binding for the hybrid and
//     authorization-code flows (§3.3.2.11). The hash is selected from the ID
//     Token's verified JOSE-header alg and the check fails closed on an unknown
//     or missing alg.
//
// [ValidateIDToken] is the full network entry point: it runs the base JWT
// validation via [jwt.Validate] and then applies the profile. [ValidateClaims]
// is the pure, network-free claim validator (the analog of the reference
// validate_id_token_claims) that the cross-language conformance vectors drive.
//
// This package positively validates the ID-Token profile; it deliberately does
// not reject "access-token-looking" claim sets — that discrimination belongs in
// the relying-party middleware layer, not here.
package idtoken
