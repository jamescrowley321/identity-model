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

## Sender-Constrained Opaque Tokens

A resource server that authorizes an opaque access token through
introspection learns its binding from the response: `cnf.jkt` for a DPoP-bound
token (RFC 9449 §6.2) or `cnf["x5t#S256"]` for a certificate-bound token
(RFC 8705 §3.2). A resource server "MUST reject a DPoP-bound access token
received as a bearer token" (RFC 9449 §7.2), and "compares that certificate
hash to a hash of the client certificate … and rejects the request if they do
not match" (RFC 8705 §3.2). `check_introspection_binding` applies these checks
with the same rules and errors as `validate_token` (see
[DPoP](dpop.md#resource-server-verification)):

```python
from py_identity_model import (
    AuthorizationScheme,
    TokenIntrospectionRequest,
    TokenPresentation,
    check_introspection_binding,
    introspect_token,
)

scheme, _, access_token = request.headers["Authorization"].partition(" ")
response = introspect_token(
    TokenIntrospectionRequest(
        address=disco.introspection_endpoint,
        token=access_token,
        client_id="my-api",
        client_secret=client_secret,
    )
)
if not response.is_successful or response.claims["active"] is not True:
    ...  # 401
check_introspection_binding(
    response,
    access_token,
    TokenPresentation(
        scheme=(
            AuthorizationScheme.DPOP
            if scheme.lower() == "dpop"
            else AuthorizationScheme.BEARER
        ),
        method=request.method,
        url="https://api.example.com/orders",  # the URI the client addressed
        dpop_proof=request.headers.get("DPoP"),  # for cnf.jkt
        client_certificate=client_certificate,  # for cnf["x5t#S256"], from mTLS
    ),
)
```

- `cnf.jkt` with no presentation raises `DPoPValidationError` (`PROOF_REQUIRED`);
  with one, the scheme must be `DPoP` and the proof must be signed by the bound
  key, with `ath` the hash of the opaque token.
- `cnf["x5t#S256"]` with no presentation, no certificate or another
  certificate raises `CertificateBindingError`.
- An unbound token passes. `required_binding=TokenBinding.DPOP` or `MTLS`
  refuses it, and without a presentation raises `ConfigurationException`.
- `dpop=DPoPVerificationOptions(...)` sets the proof algorithms, `iat` window
  and replay cache.

It does not check `active`; an inactive response is not checked. A failed
response raises `FailedResponseAccessError`. `introspect_token` itself does not
run the check: it is also used by clients that hold no request presentation.

## Request Model

::: py_identity_model.core.models.TokenIntrospectionRequest

## Response Model

::: py_identity_model.core.models.TokenIntrospectionResponse

::: py_identity_model.core.models.SignedIntrospectionOptions

::: py_identity_model.core.models.IntrospectionErrorKind

## Functions

::: py_identity_model.sync.introspection.introspect_token

::: py_identity_model.core.token_binding.check_introspection_binding
