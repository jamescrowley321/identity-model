# Token Introspection

OAuth 2.0 Token Introspection (RFC 7662) for validating tokens and obtaining metadata.

## Signed Responses (RFC 9701)

Set `signed_response` to ask for a signed JWT response and verify it. The
client sends `Accept: application/token-introspection+jwt` and accepts the
response only if its `typ` is `token-introspection+jwt`, its `alg` is allowed,
its signature verifies with one of the authorization server's keys, `iss` is
the issuer, `aud` is the `client_id`, and it has an `iat`. `claims` is then the
JWT's `token_introspection` object, and `jwt_claims` holds the other verified
claims of the JWT (`iss`, `aud`, `iat`, ...).

With `discovery_address`, the issuer, keys and allowed algorithms come from
the discovery document. The keys are fetched through the validation cache
(`cache=`, default: the default cache), and a `kid` the cached keys don't have
triggers one refresh, so key rotation is picked up as it is by
`validate_token`:

```python
from py_identity_model import (
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
    introspect_token,
)

response = introspect_token(
    TokenIntrospectionRequest(
        address=introspection_endpoint,
        token=access_token,
        client_id="my-api",
        client_secret=client_secret,
        signed_response=SignedIntrospectionOptions(discovery_address=disco_address),
    )
)
if response.is_successful and response.claims["active"]:
    ...
```

Alternatively pass fixed `issuer` and `jwks` (for example from `get_jwks`).
Those keys are never refreshed.

With no `algorithms`, a response must use an algorithm the discovery document
advertises in `introspection_signing_alg_values_supported` that is also in
`DEFAULT_ALLOWED_ALGORITHMS`, or any of `DEFAULT_ALLOWED_ALGORITHMS` when
nothing is advertised or the keys are fixed (see
[Algorithm allowlists](token-validation.md#algorithm-allowlists)). An
advertised value that is not a list allows nothing. Pass `algorithms=` to
allow a different asymmetric set instead, such as
`FAPI2_ALLOWED_SIGNING_ALGORITHMS` for FAPI 2.0 (Message Signing §5.5.2);
`none` and `HS*` are refused. `leeway=` (seconds) tolerates an authorization
server whose clock runs ahead when checking `iat`.

A refused response has `is_successful=False` and an `error_kind`
(`IntrospectionErrorKind`): `MALFORMED` (not a
`application/token-introspection+jwt` JWT, or no `token_introspection` object
with a boolean `active`), `INVALID_TYPE`, `UNSUPPORTED_ALGORITHM`, `SIGNATURE`
(no key for the JWT, or a signature that does not verify) or
`CLAIM_VALIDATION` (`iss`, `aud` or `iat`). An HTTP error response, or a
discovery document or JWK Set that can't be fetched, keeps `error_kind=None`
and the reason in `error`.

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

scheme, _, access_token = request.headers.get("Authorization", "").partition(" ")
schemes = {"bearer": AuthorizationScheme.BEARER, "dpop": AuthorizationScheme.DPOP}
if scheme.lower() not in schemes or not access_token:
    ...  # 401
response = introspect_token(
    TokenIntrospectionRequest(
        address=disco.introspection_endpoint,
        token=access_token,
        client_id="my-api",
        client_secret=client_secret,
    )
)
check_introspection_binding(  # raises unless active and correctly bound
    response,
    access_token,
    TokenPresentation(
        scheme=schemes[scheme.lower()],
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
  and your replay cache. A DPoP-bound token with no `dpop` raises
  `ConfigurationException`.

`py_identity_model.aio.check_introspection_binding` is the async counterpart,
which also accepts an `AsyncDPoPReplayCache`. It is a coroutine and must be
awaited: a call without `await` runs no check and raises nothing, so every
token passes.

```python
from py_identity_model.aio import check_introspection_binding, introspect_token

response = await introspect_token(introspection_request)
await check_introspection_binding(  # raises unless active and correctly bound
    response, access_token, presentation, dpop=dpop
)
```

It fails closed: it returns normally only for an active token whose binding
is satisfied. A response whose `active` is not `true` means the token "is not
active" (RFC 7662 §2.2) and raises `IntrospectedTokenError` with kind
`INACTIVE`. A failed or refused introspection response raises it with kind
`INTROSPECTION_FAILED`, with `introspection_error_kind` set to the response's
`error_kind` for a refused signed response. Both are
`TokenValidationException`s; answer them with `401`
`error="invalid_token"` (RFC 6750 §3.1). `introspect_token` itself still
returns a result and never raises: it is also used by clients that hold no
request presentation.

## Request Model

::: py_identity_model.core.models.TokenIntrospectionRequest

## Response Model

::: py_identity_model.core.models.TokenIntrospectionResponse

::: py_identity_model.core.models.SignedIntrospectionOptions

::: py_identity_model.core.models.IntrospectionErrorKind

## Functions

::: py_identity_model.sync.introspection.introspect_token

::: py_identity_model.core.token_binding.check_introspection_binding

::: py_identity_model.core.token_binding.IntrospectedTokenError

::: py_identity_model.core.token_binding.IntrospectedTokenErrorKind
