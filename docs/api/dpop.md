# DPoP (Demonstrating Proof of Possession)

OAuth 2.0 DPoP (RFC 9449) for binding tokens to a client's private key.

## Key Management

`generate_dpop_key` supports `ES256` (default), `ES384`, `ES512`, `PS256`,
`EdDSA` (Ed25519, RFC 8037) and `RS256`. A FAPI 2.0 client must use `ES256`,
`PS256` or `EdDSA` (FAPI 2.0 Security Profile §5.4.1), and one the server lists
in `dpop_signing_alg_values_supported`.

::: py_identity_model.core.dpop.DPoPKey

::: py_identity_model.core.dpop.generate_dpop_key

## Proof Creation

::: py_identity_model.core.dpop.create_dpop_proof

::: py_identity_model.core.dpop.compute_ath

## HTTP Headers

::: py_identity_model.core.dpop.build_dpop_headers

## Token Requests

Set `dpop_key` on a `PushedAuthorizationRequest`, `AuthorizationCodeTokenRequest`
or `RefreshTokenRequest` to bind the issued tokens to the key. Pass the same key
when refreshing, so the new access token stays bound (RFC 9449 §5, FAPI 2.0
Security Profile §5.3.3.1). Each call attaches a token-endpoint proof and
retries once on a `use_dpop_nonce` challenge (RFC 9449 §8).

```python
from py_identity_model import RefreshTokenRequest, refresh_token

response = refresh_token(
    RefreshTokenRequest(
        address=token_endpoint,
        client_id="my-client",
        refresh_token=tokens["refresh_token"],
        dpop_key=dpop_key,
        require_dpop_token_type=True,
    )
)
```

A server that ignores the proof can still answer with a Bearer token. With
`require_dpop_token_type=True` such a response fails: `is_successful` is
`False` and `error_kind` is `TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH`.
`token_type` is compared case-insensitively (RFC 6749 §7.1). The flag is off by
default; `FAPI2ClientProfile` sets it on every DPoP-bound token request it
builds.

::: py_identity_model.core.models.TokenErrorKind

## Resource Server Verification

A resource server that accepts DPoP-bound access tokens must check, on every
request, that the token arrived with the `DPoP` scheme and a proof signed by the
key in its `cnf.jkt` (RFC 9449 §7.1, §6.1). Pass `validate_token` a
`TokenPresentation` that describes how the token arrived:

```python
from py_identity_model import (
    AuthorizationScheme,
    DPoPValidationError,
    TokenBinding,
    TokenPresentation,
    TokenValidationConfig,
    validate_token,
)

config = TokenValidationConfig(
    perform_disco=True,
    audience="urn:my-api",
    required_binding=TokenBinding.DPOP,  # refuse Bearer and unbound tokens
)

try:
    claims = validate_token(
        access_token,
        config,
        disco_doc_address,
        presentation=TokenPresentation(
            scheme=AuthorizationScheme.DPOP,       # from the Authorization header
            method=request.method,
            url="https://api.example.com/orders",  # the URI the client addressed
            dpop_proof=request.headers.get("DPoP"),  # None → PROOF_REQUIRED
        ),
    )
except DPoPValidationError as exc:
    # 401, WWW-Authenticate: DPoP error="<exc.kind.oauth_error>"
    ...
```

The proof checks run in RFC 9449 §4.3 order: `typ` is `dpop+jwt`; `alg` is in
`DPoPVerificationOptions.algorithms`, `DEFAULT_ALLOWED_ALGORITHMS` by default
(`none` and `HS*` are refused); the `jwk`
header is a public key that fits `alg` and meets the RSA/EC strength floor; the
signature verifies with it; `htm` equals the request method; `htu` equals the
request URI, ignoring query and fragment, with scheme and host case and the
default port normalized (RFC 3986 §6.2.2.1, §6.2.3) and the path compared as sent;
`iat` is inside `[now - max_age - iat_leeway, now + iat_leeway]`; `nonce`
equals `TokenPresentation.expected_nonce` when one is set; `ath` is the hash of
the access token; the key's RFC 7638 thumbprint equals `cnf.jkt`; and last, the
proof has not been seen. A rejected proof, including one whose token fails the
certificate binding, is never recorded.

What `required_binding` does:

| `required_binding` | Token | Presented as | Result |
|---|---|---|---|
| any | `cnf.jkt` | `DPoP` + valid proof by the bound key | accepted |
| any | `cnf.jkt` | `Bearer`, or `DPoP` with no proof | `WRONG_SCHEME` / `PROOF_REQUIRED` |
| any | no `cnf.jkt` | `DPoP` | `NOT_BOUND` |
| `DPOP` | no `cnf.jkt` | anything | `NOT_BOUND` |
| any | `cnf["x5t#S256"]` | the bound client certificate | accepted (RFC 8705 §3) |
| any | `cnf["x5t#S256"]` | no client certificate, another one, or one that is not valid PEM/DER | `CertificateBindingError` |
| `MTLS` | no `cnf["x5t#S256"]` | anything | `CertificateBindingError` |
| `NONE` (default) | no `cnf` | `Bearer` | accepted |
| `NONE` | `cnf.jkt` | no `presentation=` | `PROOF_REQUIRED` (RFC 9449 §7.2) |
| `NONE` | `cnf["x5t#S256"]` | no `presentation=` | `CertificateBindingError` (RFC 8705 §3) |
| `NONE` | no `cnf.jkt` or `cnf["x5t#S256"]` | no `presentation=` | accepted |

The table applies to access tokens (`validate_token`), and to opaque access
tokens checked with `check_introspection_binding`, which reads `cnf` from the
introspection response (RFC 9449 §6.2, see
[Token Introspection](introspection.md#sender-constrained-opaque-tokens)).
`validate_id_token` and
`validate_logout_token` do not check `cnf` and ignore `required_binding`: ID
Tokens and Logout Tokens arrive with no presentation.

`required_binding=DPOP` or `MTLS` without `presentation=` raises
`ConfigurationException`. Every rejection is a `DPoPValidationError` (or
`CertificateBindingError` for mTLS), both `TokenValidationException`s, with a
typed `kind`. `kind.oauth_error` is the `WWW-Authenticate` error code:
`invalid_dpop_proof` for a bad proof and `invalid_token` for a failed binding.

Proof algorithms, the `iat` window and the replay cache are set with
`TokenValidationConfig(dpop=DPoPVerificationOptions(...))`. The replay cache
is yours and required: there is no process-wide default, so build one
`DPoPVerificationOptions` at startup and reuse it. A DPoP-bound token with no
`dpop` options raises `ConfigurationException`.

```python
from py_identity_model import (
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenValidationConfig,
)

dpop = DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())
config = TokenValidationConfig(perform_disco=True, audience="api", dpop=dpop)
```

`InMemoryDPoPReplayCache` holds each proof, keyed by its key thumbprint and
`jti`, for as long as the window would accept it and never evicts a live one:
when it is full, a new proof is refused with `REPLAY_CACHE_FULL`, so size
`InMemoryDPoPReplayCache(max_entries=...)` above the proofs a process accepts
in one window. A deployment with several processes or hosts needs a shared
store so a proof replayed to another worker is refused (RFC 9449 §11.1).

A store implements `DPoPReplayCache`, whose
`check_and_store(jkt, jti, expires_at, now)` returns a `DPoPReplayCheck`:
`RECORDED`, `REPLAYED` or `FULL`. It returns its answer and does not raise for
a replay or a full store; `REPLAYED` and `FULL` refuse the proof, and an
answer that is not a `DPoPReplayCheck` raises `ConfigurationException`.
A store reached over the network can implement `AsyncDPoPReplayCache`
(`async def check_and_store`) instead, with the async validators
(`py_identity_model.aio.validate_token`,
`py_identity_model.aio.check_introspection_binding`,
`py_identity_model.aio.verify_dpop_proof`). The sync validators refuse an
async cache with `ConfigurationException`.

`py_identity_model.aio.verify_dpop_proof` and
`py_identity_model.aio.check_introspection_binding` are coroutines and must be
awaited. A call without `await` runs no check (signature, `htm`/`htu`, `iat`,
`ath`, `jkt` or replay) and raises nothing:

```python
from py_identity_model import DPoPProofRequest
from py_identity_model.aio import verify_dpop_proof

proof = await verify_dpop_proof(  # raises DPoPValidationError on any failure
    request.headers["DPoP"],
    DPoPProofRequest(
        method=request.method,
        url="https://api.example.com/orders",
        access_token=access_token,
    ),
    dpop,
)
```

### FastAPI

`TokenValidationMiddleware` and `build_ws_authenticator` build the
`TokenPresentation` for every request, so a bound token is always checked. They
accept `Authorization: Bearer <token>` and `Authorization: DPoP <token>` (scheme
case-insensitive).

Both take their binding configuration from one frozen `AuthOptions`, passed as
`options=`. Pass the same instance to both entry points so HTTP and WebSocket
routes enforce the same rules:

```python
from fastapi_identity_model import (
    AuthOptions,
    TokenValidationMiddleware,
    build_ws_authenticator,
)
from py_identity_model import (
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
)

options = AuthOptions(
    required_binding=TokenBinding.DPOP,  # refuse Bearer and unbound tokens
    dpop=DPoPVerificationOptions(
        algorithms=FAPI2_ALLOWED_SIGNING_ALGORITHMS,  # ES256, PS256, EdDSA
        replay_cache=InMemoryDPoPReplayCache(),
    ),
    expected_origin="https://api.example.com",
)
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    options=options,
)
ws_auth = build_ws_authenticator(
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    options=options,
)
```

`AuthOptions` fields:

| Field | Default | Meaning |
|---|---|---|
| `required_binding` | `TokenBinding.NONE` | The sender constraint every token must carry. |
| `dpop` | defaults, with an `InMemoryDPoPReplayCache` owned by this `AuthOptions` | `DPoPVerificationOptions` (algorithms, `iat` window, replay cache). Pass the same `AuthOptions` to the middleware and the WebSocket authenticator to share the cache; behind a load balancer, pass a shared one. |
| `client_certificate` | `None` | Callable returning the connection's client certificate (PEM or DER), or `None`. Receives the `Request` or `WebSocket`. |
| `expected_origin` | `None` | `scheme://host[:port]` the proof's `htu` is checked against. `None` takes the origin from the request. |

`AuthOptions(required_binding=TokenBinding.MTLS)` without `client_certificate`
raises `ValueError`, because every token would be refused.

#### From `OIDCSettings`

Pass `settings=` instead of `options=` and both entry points read the binding
from `OIDCSettings`, along with `discovery_url`, `audience` and (middleware)
`excluded_paths`:

```python
from fastapi_identity_model.config_helpers import oidc_settings_from_env

settings = oidc_settings_from_env()
app.add_middleware(TokenValidationMiddleware, settings=settings)
ws_auth = build_ws_authenticator(settings=settings)
```

| Setting | Environment variable | Values |
|---|---|---|
| `required_binding` | `OIDC_REQUIRED_BINDING` | `none`, `dpop`, `mtls` |
| `client_certificate_header` | `OIDC_CLIENT_CERTIFICATE_HEADER` | Header carrying the leaf client certificate PEM only, URL-decoded before use (nginx `$ssl_client_escaped_cert`); a repeated header, a comma or a second PEM block yields no certificate |
| `expected_origin` | `OIDC_EXPECTED_ORIGIN` | `scheme://host[:port]` |

Settings cannot hold callables or a replay cache. Supply those with
`AuthOptions.from_settings(settings, dpop=..., client_certificate=...)` and pass
the result as `options=` together with `settings=`. An `options` that drops a
`required_binding`, `expected_origin` or client certificate header set in
`settings` raises `ValueError`. A request that carries the certificate header
more than once gets no certificate.

Read the client certificate only from a header your TLS terminator sets and
strips from client requests; otherwise a client can present any certificate.

#### Behaviour

- A rejected binding is a `401` with
  `WWW-Authenticate: DPoP error="<kind.oauth_error>", algs="<accepted algorithms>"`
  (RFC 9449 §7.1). The body is the same generic detail as every other `401`.
- With `required_binding=TokenBinding.DPOP`, every `401` challenges with `DPoP`.
  Otherwise non-DPoP failures challenge with `Bearer`.
- More than one `DPoP` header is refused as `invalid_dpop_proof` (§4.3).
- Without `expected_origin`, the proof's `htu` is checked against
  `request.url`, whose scheme and host come from the ASGI scope and the `Host`
  header. A client that controls the `Host` header your app sees can then get a
  proof minted for another origin past the `htu` check. Set `expected_origin`
  to the origin clients address, unless a trusted proxy pins `Host` (or
Starlette's `TrustedHostMiddleware` restricts it). Behind a
  reverse proxy without it, run uvicorn with `--proxy-headers` (or Starlette's
  proxy-headers middleware) so `request.url` is the URI the client addressed.
- With `expected_origin`, `htu` is compared with that origin plus the request
  path and query as sent.
- Certificate-bound tokens need a `client_certificate` source. Without one,
  every certificate-bound token is refused.

On a WebSocket, a DPoP proof for the handshake has `htm` `GET` and `htu` the
handshake URI written with `http`/`https` in place of `ws`/`wss` (or
`expected_origin` plus the path). A token from the query parameter is a bearer
token, so a DPoP-bound token can only be used from a client that can set
headers.

::: py_identity_model.core.token_binding.TokenPresentation

::: py_identity_model.core.token_binding.AuthorizationScheme

::: py_identity_model.core.token_binding.TokenBinding

::: py_identity_model.core.dpop_verify.verify_dpop_proof

::: py_identity_model.core.dpop_verify.DPoPProofRequest

::: py_identity_model.core.dpop_verify.DPoPProof

::: py_identity_model.core.dpop_verify.DPoPVerificationOptions

::: py_identity_model.core.dpop_verify.DPoPErrorKind

::: py_identity_model.core.dpop_verify.DPoPValidationError

::: py_identity_model.core.dpop_verify.DPoPReplayCache

::: py_identity_model.core.dpop_verify.AsyncDPoPReplayCache

::: py_identity_model.core.dpop_verify.DPoPReplayCheck

::: py_identity_model.core.dpop_verify.InMemoryDPoPReplayCache

::: py_identity_model.aio.token_binding.verify_dpop_proof

::: py_identity_model.aio.token_binding.check_token_binding

::: py_identity_model.aio.token_binding.check_introspection_binding

::: py_identity_model.core.dpop.compute_jwk_thumbprint
