# identity-model — Capability Matrix

This is the **canonical, cross-language capability specification**. Every language binding implements these capabilities idiomatically and proves behavioral parity by passing the machine-readable conformance definitions in [`conformance/`](conformance/) against the shared provider in [`../infra`](../infra).

Normative keywords (MUST / SHOULD / MAY) follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Status Legend

- `implemented` — passes all conformance tests for this capability
- `in-progress` — partially implemented
- `planned` — specified, not yet implemented
- `n/a` — intentionally not applicable to this language

## Tiers & Status

| Tier | Capability | Spec | Conformance | Python | Go | Rust |
|------|-----------|------|-------------|--------|----|----|
| Core | OIDC Discovery | OIDC Discovery 1.0 §3–4 | `discovery.json` | implemented | planned | implemented |
| Core | JWKS Retrieval + Caching | RFC 7517, RFC 7518 | `jwks.json` | implemented | planned | implemented |
| Core | JWT Validation | RFC 7519, RFC 7515 | `validation.json` | implemented | planned | implemented |
| Core | Client Credentials | RFC 6749 §4.4 | `client-credentials.json` | implemented | planned | implemented |
| Core | Authorization Code + PKCE | RFC 6749 §4.1, RFC 7636 | `authorization-code.json` | planned | planned | implemented |
| Core | UserInfo | OIDC Core 1.0 §5.3 | `userinfo.json` | implemented | implemented | implemented |
| Extended | Token Introspection | RFC 7662 | `introspection.json` | planned | planned | planned |
| Extended | Token Revocation | RFC 7009 | `revocation.json` | planned | planned | planned |
| Extended | Token Exchange | RFC 8693 | `token-exchange.json` | planned | planned | planned |
| Extended | DPoP | RFC 9449 | `dpop.json` | planned | planned | planned |
| Advanced | PAR | RFC 9126 | — | planned | planned | planned |
| Advanced | RAR | RFC 9396 | — | planned | planned | planned |
| Advanced | CIBA | OpenID CIBA Core | — | planned | planned | planned |
| Advanced | JARM | OpenID JARM | — | planned | planned | planned |

> Python status reflects the reference implementation [`py-identity-model`](https://github.com/jamescrowley321/py-identity-model), which merges into `python/` at a later date. Go and Rust are scaffolded in this repo with implementation tracked per the conformance definitions.

## Capability Definitions (Core Tier)

### OIDC Discovery

- Implementations MUST fetch `{issuer}/.well-known/openid-configuration` per [OIDC Discovery 1.0 §4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest).
- The response MUST contain the required metadata fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` ([§3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)).
- The `issuer` in the response MUST exactly match the requested issuer ([§4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation)); a mismatch MUST error.
- Implementations MUST cache the parsed document with a configurable TTL. A cache hit MUST NOT make a network request; after TTL expiry the next call MUST re-fetch.
- Implementations MUST surface distinct, typed errors for transport failures, non-JSON bodies, and missing required fields. Unknown extra fields MUST be ignored, not rejected.

### JWKS Retrieval + Caching

- Implementations MUST fetch the JWK Set from `jwks_uri` and parse it per [RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517#section-5).
- Each key MUST expose `kty`, `kid`, `use`, `alg`; RSA keys expose `n`/`e`, EC keys expose `crv`/`x`/`y` ([RFC 7517 §4](https://www.rfc-editor.org/rfc/rfc7517#section-4)).
- Resolving a `kid` not in the cached set MUST trigger a forced refresh and retry before returning a key-not-found error (supports key rotation).
- The key set MUST be cached with a configurable TTL; concurrent fetches for the same URI SHOULD be deduplicated.

### JWT Validation

- Implementations MUST verify the JWS signature using the key resolved by `kid` ([RFC 7515 §4.1](https://www.rfc-editor.org/rfc/rfc7515#section-4.1)).
- `alg: "none"` MUST be rejected unconditionally ([RFC 7519 §7.2](https://www.rfc-editor.org/rfc/rfc7519#section-7.2)).
- Registered claims MUST be checked: `iss` (exact match), `aud` (contains expected), `exp` (not expired, configurable clock skew), `nbf` (not before), `iat` (present) ([RFC 7519 §4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1)).
- When an expected `nonce` is supplied, it MUST be validated ([OIDC Core 1.0 §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)).

### Client Credentials / Authorization Code + PKCE

- Client Credentials MUST send `grant_type=client_credentials` and support `client_secret_basic` (default) and `client_secret_post` auth ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4), [§2.3](https://www.rfc-editor.org/rfc/rfc6749#section-2.3)).
- PKCE verifiers MUST be 43–128 unreserved characters; the S256 challenge MUST equal `BASE64URL(SHA256(verifier))` ([RFC 7636 §4.1–4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.1)). Implementations MUST pass the RFC 7636 Appendix B test vectors.
- Token endpoint errors MUST be parsed into a typed error with `error`, `error_description`, `error_uri` ([RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)).

### UserInfo

- Implementations MUST GET the `userinfo_endpoint` with `Authorization: Bearer {token}` and return typed standard claims plus an overflow map ([OIDC Core 1.0 §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)).
- When an expected `sub` is supplied, the UserInfo `sub` MUST match the ID token `sub`; a mismatch MUST error ([§5.3.4](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)).

## Machine-Readable Schema

The status table above is also expressed per-capability for tooling (status generators, CI gates, docs site):

```yaml
capabilities:
  - name: "OIDC Discovery"
    tier: core
    spec_ref: "OpenID Connect Discovery 1.0"
    conformance_file: "spec/conformance/discovery.json"
    languages:
      python: { status: implemented }
      go: { status: planned }
      rust: { status: planned }
```
