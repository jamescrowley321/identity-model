// Package idtoken validates OpenID Connect ID Tokens against the profile rules
// that make an ID Token an ID Token — the checks layered on top of the standard
// JWT validation performed by package jwt (signature via JWKS, iss/aud/iat/exp).
//
// It mirrors the OIDF-certified py-identity-model reference implementation
// (py/src/py_identity_model/core/id_token_logic.py) byte-for-byte, per OpenID
// Connect Core 1.0 §2, §3.1.3.7, §3.2.2.9 and §3.3.2.10:
//
//   - sub is REQUIRED and must be non-empty (§2).
//   - azp authorized-party rules (§3.1.3.7 steps 4-5, SHOULD), enforced as
//     library policy: a token with multiple audiences must carry an azp (Core
//     1.0 (2014) step 4 SHOULD; not in errata set 2), and a present azp must
//     identify this client (step 5).
//   - nonce binding, when the caller supplies the nonce it sent on the
//     authorization request (§3.1.3.7 step 11).
//   - auth_time presence when max_age was requested (§2, §3.1.2.1) and
//     freshness against it (§3.1.3.7 step 13, SHOULD).
//   - at_hash / c_hash token- and code-binding: at_hash per §3.2.2.9 item 3
//     (Hybrid via §3.3.2.9; in the Code Flow at_hash is OPTIONAL, §3.1.3.6, and
//     checking it is a MAY, §3.1.3.8), c_hash per §3.3.2.10 item 3; the claims
//     are defined in §3.3.2.11. Requiring the claim to be present once the
//     caller supplies the value is library policy. The hash is selected from the ID
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
