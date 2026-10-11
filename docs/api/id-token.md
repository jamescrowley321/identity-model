# ID Token Validation

First-class validation of OpenID Connect ID Tokens. `validate_id_token` runs
the standard JWT validation (signature via discovery/JWKS, `iss`, `aud`,
`exp`) and then enforces the ID-token profile of OIDC Core 1.0 §3.1.3.7 /
§3.3.2.11 on top:

- **`sub`** — required and non-empty, always.
- **`aud`** — every audience must be your `client_id` or one you list in
  `trusted_audiences=`, always (§3.1.3.7 step 3). The list only adds trusted
  audiences; it cannot turn the check off. A single-audience token equal to
  your `client_id` needs no list.
- **`azp`** — ignored by default. When you pass `validate_azp=True`, a
  multi-audience token must carry `azp`, and a present `azp` must equal your
  `client_id` (taken from `token_validation_config.audience`). OIDC Core 1.0
  errata set 2 makes neither a MUST (§3.1.3.7 steps 4-5) and §2 tells relying
  parties that use no extensions to ignore `azp`, so the default accepts
  cross-client tokens such as Google's, where `aud` is your backend and `azp`
  is the mobile client that obtained the token.
- **`nonce`** — when you pass `nonce=`, the claim must be present and equal
  (compared in constant time).
- **`auth_time` / `max_age`** — when you pass `max_age=`, `auth_time` must be
  present and recent enough (`now - auth_time <= max_age + leeway`).
- **`at_hash` / `c_hash`** — when you pass `access_token=` / `code=`, the
  hash claim must be present and match the value's left-half hash, computed
  under the token's signature-verified header `alg`. An unmappable algorithm
  fails closed. Presence is required because a value returned in the same
  authorization response as the ID Token (`id_token token`, `code id_token`,
  `code id_token token`) must be bound (§3.2.2.10, §3.3.2.11). An ID Token from
  the token endpoint may omit `at_hash` (§3.1.3.6): pass
  `access_token_issued_with_id_token=False` (or `code_issued_with_id_token=False`)
  when the value did not come back with the ID Token, and an absent claim is
  accepted while a present one must still match.

The optional checks activate only when you supply the corresponding argument,
so validation is exactly as strict as the flow you are running. Set
`token_validation_config.audience` to your `client_id`.

```python
from py_identity_model import TokenValidationConfig, validate_id_token

claims = validate_id_token(
    id_token,
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
    trusted_audiences=["https://api.example.com"],  # other audiences you trust
    validate_azp=True,             # opt in to the azp rules
    nonce=expected_nonce,          # from the authorization request
    access_token=access_token,     # bind at_hash (hybrid/implicit)
    code=authorization_code,       # bind c_hash (hybrid)
    max_age=300,                   # require a recent authentication
)
```

Profile failures raise `IdTokenValidationException`; standard JWT failures
raise `TokenValidationException`. The former subclasses the latter, so
`except TokenValidationException` fails closed on both. An untrusted audience
raises `UntrustedAudienceException`, a subclass of
`IdTokenValidationException` whose `details["untrusted_audiences"]` lists the
rejected values.

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

::: py_identity_model.exceptions.UntrustedAudienceException
