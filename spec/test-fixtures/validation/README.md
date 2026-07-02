# JWT validation fixtures

Shared key material and static tokens for the `validation` conformance suite
(`spec/conformance/validation.json`, IDs `JWT-001`..`JWT-013`).

| File | Purpose |
|------|---------|
| `signing-key.jwk.json` | RSA-2048 **private** JWK (`kid=test-key-1`, `alg=RS256`). Implementations mint signed test tokens with this key so each language signs with identical material. |
| `jwks.json` | The matching **public** JWK Set served to the validator. Resolving `kid=test-key-1` yields the key that verifies tokens signed with `signing-key.jwk.json`. |
| `alg-none-token.txt` | A static unsigned JWT with header `alg:"none"`, for `JWT-003`. It must be rejected unconditionally. |

Signed tokens carrying time-based claims (`exp`, `nbf`, `iat`) are **minted at
test time** from `signing-key.jwk.json` rather than committed, so expiry stays
fresh and each case (expired, not-yet-valid, wrong issuer/audience, nonce, etc.)
can set the exact claim values it needs. These fixtures supply only the shared
key material plus the one static `alg:none` case, which has no signature to
keep fresh.
