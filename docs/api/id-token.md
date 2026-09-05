# ID Token Validation

First-class validation of OpenID Connect ID Tokens. `validate_id_token` runs
the standard JWT validation (signature via discovery/JWKS, `iss`, `aud`,
`exp`) and then enforces the ID-token profile of OIDC Core 1.0 §3.1.3.7 /
§3.3.2.11 on top:

- **`sub`** — required and non-empty, always.
- **`azp`** — a multi-audience token must carry `azp`, and a present `azp`
  must equal your `client_id` (taken from `token_validation_config.audience`).
- **`nonce`** — when you pass `nonce=`, the claim must be present and equal
  (compared in constant time).
- **`auth_time` / `max_age`** — when you pass `max_age=`, `auth_time` must be
  present and recent enough (`now - auth_time <= max_age + leeway`).
- **`at_hash` / `c_hash`** — when you pass `access_token=` / `code=`, the
  corresponding left-half hash must match, computed under the token's
  signature-verified header `alg`. An unmappable algorithm fails closed.

The optional checks activate only when you supply the corresponding argument,
so validation is exactly as strict as the flow you are running. Set
`token_validation_config.audience` to your `client_id`.

```python
from py_identity_model import TokenValidationConfig, validate_id_token

claims = validate_id_token(
    id_token,
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,          # from the authorization request
    access_token=access_token,     # enforce at_hash (hybrid/implicit)
    code=authorization_code,       # enforce c_hash (hybrid)
    max_age=300,                   # require a recent authentication
)
```

Profile failures raise `IdTokenValidationException`; standard JWT failures
raise `TokenValidationException`. The former subclasses the latter, so
`except TokenValidationException` fails closed on both.

The Go library ships the same profile as
[`pkg/idtoken`](https://github.com/jamescrowley321/identity-model/tree/main/go/pkg/idtoken)
(`ValidateIDToken` / `ValidateClaims`) and the Rust library as
[`validate_id_token`](https://docs.rs/rs-identity-model) with
`IdTokenValidationOptions`; all three are driven by the shared conformance
vectors.

## Sync API

::: py_identity_model.sync.id_token.validate_id_token

## Async API

::: py_identity_model.aio.id_token.validate_id_token

## Claim-level building block

For callers that verify the JWT themselves, the profile checks are available
as a pure function over an already-validated claim set:

::: py_identity_model.core.id_token_logic.validate_id_token_claims

## Exceptions

::: py_identity_model.exceptions.IdTokenValidationException
