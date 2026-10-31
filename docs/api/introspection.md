# Token Introspection

OAuth 2.0 Token Introspection (RFC 7662) for validating tokens and obtaining metadata.

## Signed Responses (RFC 9701)

Set `signed_response` to ask for a signed JWT response and verify it. The
client sends `Accept: application/token-introspection+jwt` and accepts the
response only if its `typ` is `token-introspection+jwt`, its `alg` is allowed
(PS256, ES256 or EdDSA by default, FAPI 2.0 Message Signing §5.5.2), its
signature verifies with a key from `jwks`, `iss` is `issuer`, `aud` is the
`client_id`, and it has an `iat`. `claims` is then the JWT's
`token_introspection` object.

```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    JwksRequest,
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
    get_discovery_document,
    get_jwks,
    introspect_token,
)

disco = get_discovery_document(DiscoveryDocumentRequest(address=disco_address))
jwks = get_jwks(JwksRequest(address=disco.jwks_uri))

response = introspect_token(
    TokenIntrospectionRequest(
        address=disco.introspection_endpoint,
        token=access_token,
        client_id="my-api",
        client_secret=client_secret,
        signed_response=SignedIntrospectionOptions(issuer=disco.issuer, jwks=jwks),
    )
)
if response.is_successful and response.claims["active"]:
    ...
```

A refused response has `is_successful=False` and an `error_kind`
(`IntrospectionErrorKind`): `MALFORMED` (not a
`application/token-introspection+jwt` JWT, or no `token_introspection` object
with a boolean `active`), `INVALID_TYPE`, `UNSUPPORTED_ALGORITHM`, `SIGNATURE`
or `CLAIM_VALIDATION` (`iss`, `aud` or `iat`). An HTTP error response keeps
`error_kind=None` and the status in `error`.

The authorization server advertises its algorithms in
`DiscoveryDocumentResponse.introspection_signing_alg_values_supported`. Pass
`algorithms=` to allow a different asymmetric set; `none` and `HS*` are
refused.

## Request Model

::: py_identity_model.core.models.TokenIntrospectionRequest

## Response Model

::: py_identity_model.core.models.TokenIntrospectionResponse

::: py_identity_model.core.models.SignedIntrospectionOptions

::: py_identity_model.core.models.IntrospectionErrorKind

## Functions

::: py_identity_model.sync.introspection.introspect_token
