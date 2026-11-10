# Token Validation

JWT validation with optional OpenID Connect auto-discovery.

For sender-constrained access tokens (DPoP `cnf.jkt`, mTLS `cnf["x5t#S256"]`),
pass `presentation=` and set `required_binding`; see
[DPoP: Resource Server Verification](dpop.md#resource-server-verification).

## Algorithm allowlists

The library keeps one JWS algorithm allowlist per purpose:

| Purpose | Set | Contents |
|---|---|---|
| Verify: every inbound JWS (access and ID tokens, DPoP proofs, signed introspection responses, JARM responses) | `DEFAULT_ALLOWED_ALGORITHMS` | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA |
| Sign: outbound JWTs (client assertions, request objects) | `SUPPORTED_SIGNING_ALGORITHMS` | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA |
| FAPI 2.0 | `FAPI2_ALLOWED_SIGNING_ALGORITHMS` | PS256, ES256, EdDSA |

`algorithms=None` means `DEFAULT_ALLOWED_ALGORITHMS` everywhere: discovery and
manual token validation, `DPoPVerificationOptions`, `SignedIntrospectionOptions`
and JARM. The verify set has no HMAC algorithm and never `none`, so a public key
is never used as an HMAC secret (RFC 8725 §2.1). It is defined separately from
the signing set, so a new signing algorithm never widens verification. The FAPI
2.0 set applies only where you pass it, or where the FAPI 2.0 profile and
validators check against it. An explicit `algorithms` list replaces the
default.

::: py_identity_model.core.jwt_signing.DEFAULT_ALLOWED_ALGORITHMS

::: py_identity_model.core.jwt_signing.SUPPORTED_SIGNING_ALGORITHMS

## Configuration

::: py_identity_model.core.models.TokenValidationConfig

## Sync API

::: py_identity_model.sync.token_validation.validate_token

## Async API

::: py_identity_model.aio.token_validation.validate_token
