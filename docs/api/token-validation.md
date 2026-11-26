# Token Validation

JWT validation with optional OpenID Connect auto-discovery.

For sender-constrained access tokens (DPoP `cnf.jkt`, mTLS `cnf["x5t#S256"]`),
pass `presentation=` and set `required_binding`. A bound access token
validated without `presentation=` is rejected (RFC 9449 §7.2, RFC 8705 §3);
`validate_id_token` and `validate_logout_token` do not check `cnf`. See
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

## Issuers

Which `iss` values `validate_token` accepts:

| Mode | Setting | `iss` is accepted when |
|---|---|---|
| Discovery | none (default) | it equals the discovery document's `issuer` |
| Discovery | `token_issuers` | it is one of the listed values |
| Manual (`perform_disco=False`) | `issuer` | it is one of the configured values |
| Manual (`perform_disco=False`) | none | always: `iss` is not checked, so set `issuer` |

In discovery mode the `iss` check cannot be turned off:
`options={"verify_iss": False}` raises `ConfigurationException`. `issuer` is
not used in discovery mode.

### A provider that issues several issuer values

Some providers sign tokens with more than one `iss` value from one key set.
Descope, for example, signs with the discovery issuer and also with the bare
project ID, which is not a URL and has no discovery document of its own. List
every value you accept in `token_issuers`; the discovery document still
supplies the keys:

```python
from py_identity_model import TokenValidationConfig, validate_token

DISCOVERY_ISSUER = "https://api.descope.com/P2exampleproject"

config = TokenValidationConfig(
    perform_disco=True,
    audience="my-api",
    token_issuers=[DISCOVERY_ISSUER, "P2exampleproject"],
)
claims = validate_token(
    token,
    config,
    disco_doc_address=f"{DISCOVERY_ISSUER}/.well-known/openid-configuration",
)
```

- A token whose `iss` is not in the list raises `InvalidIssuerException`.
- The list replaces the discovery issuer. To accept tokens that carry the
  discovery issuer, list it.
- The list belongs to one provider. Every listed value is accepted from the
  keys of the discovery document you point at, so never list another
  provider's issuer: use one `TokenValidationConfig` per provider.
- The discovery document's own `issuer` must be in the list. Otherwise
  validation raises `InvalidIssuerException`. To leave the discovery issuer
  out of the accepted `iss` values, pin it as the single entry of
  `allowed_issuers`:

    ```python
    config = TokenValidationConfig(
        perform_disco=True,
        token_issuers=["P2exampleproject"],
        allowed_issuers=[DISCOVERY_ISSUER],
    )
    ```

- These raise `ConfigurationException` before any request: an empty list, a
  blank or non-string entry, a value that is not a list, `token_issuers` with
  `perform_disco=False`, and `token_issuers` with an `allowed_issuers` that
  does not have exactly one entry.
- `validate_id_token` and `validate_logout_token` ignore `token_issuers`: an
  ID Token's or Logout Token's `iss` must equal the discovery issuer (OIDC
  Core §3.1.3.7 step 2, Back-Channel Logout 1.0 §2.6).

`allowed_issuers` is a separate setting. It names the discovery documents you
trust, by their `issuer`, for callers that build the discovery address from an
untrusted token. It never widens the `iss` values a token may carry.

## Token type

`validate_token` reads the JWT `typ` header before anything else and rejects a
token whose `typ` names another kind of JWT, so a signed introspection
response or a Logout Token that the issuer signed for your audience is not
accepted as an access token (RFC 9701 §8.1). It raises `AccessTokenTypeError`,
whose `kind` (an `AccessTokenTypeErrorKind`) names the rejected type:

| `typ` | `kind` |
|---|---|
| `token-introspection+jwt` | `TOKEN_INTROSPECTION` |
| `logout+jwt` | `LOGOUT` |
| `secevent+jwt` | `SECURITY_EVENT` |
| `dpop+jwt` | `DPOP_PROOF` |
| `oauth-authz-req+jwt` | `AUTHORIZATION_REQUEST` |
| `client-authentication+jwt` | `CLIENT_AUTHENTICATION` |

`typ` is compared case-insensitively, with or without the `application/`
prefix. Any other `typ`, including `at+jwt` (RFC 9068) and `JWT`, and a token
without `typ`, is accepted. `validate_id_token` and `validate_logout_token` do
not run this check.

::: py_identity_model.exceptions.AccessTokenTypeError

::: py_identity_model.exceptions.AccessTokenTypeErrorKind

## Configuration

::: py_identity_model.core.models.TokenValidationConfig

## Sync API

::: py_identity_model.sync.token_validation.validate_token

## Async API

::: py_identity_model.aio.token_validation.validate_token
