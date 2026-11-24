# JWT validation fixtures

Shared key material and static tokens for the `validation` conformance suite
(`spec/vectors/validation.json`, IDs `JWT-001`..`JWT-016`; `JWT-010` is retired, see `JWKS-004`).

| File | Purpose |
|------|---------|
| `signing-key.jwk.json` | RSA-2048 **private** JWK (`kid=test-key-1`, `alg=RS256`). Implementations mint signed test tokens with this key so each language signs with identical material. |
| `signing-key.pkcs1.der` | The **same** private key in PKCS#1 DER form (byte-for-byte derived from `signing-key.jwk.json`). Lets signers that consume DER/PEM (e.g. the Rust binding via `jsonwebtoken::EncodingKey::from_rsa_der`) load the shared key without a JWK-to-key crate. Binary DER, not armored PEM, to avoid tripping secret scanners. |
| `ed25519-signing-key.jwk.json` | Ed25519 **private** JWK (`kid=ed25519-key-1`, `alg=EdDSA`), for `JWT-015`. |
| `ed25519-signing-key.pkcs8.der` | The **same** Ed25519 key in PKCS#8 DER form, for signers that load DER (Rust: `EncodingKey::from_ed_der`). |
| `jwks.json` | The **public** JWK Set served to the validator. Resolving `kid=test-key-1` yields the key that verifies tokens signed with `signing-key.jwk.json`, and `kid=ed25519-key-1` the Ed25519 key. It also holds two keys below the strength floor for `JWT-014`: `weak-rsa-1024` (RSA, 1024 bits) and `weak-ec-p192` (EC P-192). A test that needs a single-key set builds its own. |
| `alg-none-token.txt` | A static unsigned JWT with header `alg:"none"`, for `JWT-003`. It must be rejected unconditionally. |
| `weak-rsa-1024-token.txt` | A static RS256 JWT signed by `weak-rsa-1024`, for `JWT-014`. Committed because some signers (aws-lc-rs) refuse to sign with a 1024-bit key. Its claims are valid until 2100, so only the key strength rejects it. |
| `weak-ec-p192-token.txt` | A static ES256-labelled JWT signed with the P-192 key `weak-ec-p192`, for `JWT-014`. No JOSE library signs with P-192, so it is committed. |
| `malformed-*-token.txt` | Static tokens that are not well-formed compact JWS, for `JWT-016`: one segment, a header that is not base64url, a header that is not JSON, a payload that is not JSON (validly signed by `signing-key.jwk.json`, so only the payload is at fault), and a signature that is not base64url. Each must be rejected with the malformed-token error. |

Signed tokens carrying time-based claims (`exp`, `nbf`, `iat`) are **minted at
test time** from `signing-key.jwk.json` rather than committed, so expiry stays
fresh and each case (expired, not-yet-valid, wrong issuer/audience, nonce, etc.)
can set the exact claim values it needs. These fixtures supply only the shared
key material plus the static `alg:none` and weak-key cases, whose outcome
doesn't depend on fresh claims.
