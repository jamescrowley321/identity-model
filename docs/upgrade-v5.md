# Upgrading from 4.x to 5.0

py-identity-model 5.0 changes how the library is configured and enforces
several OpenID Connect rules that 4.x left to the caller. This page lists every
breaking change, with what to change in your code. fastapi-identity-model
releases a matching version that requires py-identity-model 5.

Most applications need three edits:

1. Build an `HTTPConfig` and pass it on an `HTTPClient` / `AsyncHTTPClient`
   (and a `CacheConfig` on a `ValidationCache`) instead of setting
   `HTTP_TIMEOUT` and the other environment variables.
2. If you use the FastAPI package, replace `OIDCSettings.from_env()` with
   `oidc_settings_from_env()`.
3. Pass `trusted_audiences=` to `validate_id_token` (or set
   `OIDCSettings.trusted_audiences` for the FastAPI login router) if your
   provider issues ID Tokens with more than one audience.

The other changes reject provider responses and tokens that the OpenID
Connect specifications already forbid. A conforming provider is unaffected.

## Configuration

### Settings are two plain typed values, `HTTPConfig` and `CacheConfig` ([#892](https://github.com/jamescrowley321/identity-model/pull/892), [#1060](https://github.com/jamescrowley321/identity-model/issues/1060))

`Config.from_env`, `Config.build`, `ConfigSource`, `EnvSource`,
`MappingSource` and `Secret` are removed, and so is `Config` itself. The
settings are on two frozen values, each taken only by the object that reads
it:

- `HTTPConfig` (`http_timeout`, `http_retry_max_attempts`,
  `http_retry_base_delay`, `ca_bundle`, `jwks_max_size`, `jwks_max_keys`), for
  `HTTPClient` / `AsyncHTTPClient`.
- `CacheConfig` (`jwks_cache_ttl`, `jwks_kid_miss_cooldown`,
  `discovery_cache_ttl`, `cache_max_entries`), for `ValidationCache` /
  `AsyncValidationCache`.

Build them with keyword arguments; each setting has a default, so
`HTTPConfig()` and `CacheConfig()` are complete. An invalid value raises one
`ConfigError` (a `ValueError`) listing every bad setting. A setting of the
other config (`HTTPConfig(cache_max_entries=8)`), or the other config passed
to a client or cache (`HTTPClient(config=CacheConfig())`), raises `TypeError`.
A single `Config` used to be accepted by both and each silently ignored the
other's settings.

Before:

```python
from py_identity_model import Config

config = Config.build(overrides={"http.timeout": "10"})
```

After:

```python
from py_identity_model import CacheConfig, HTTPConfig

http_config = HTTPConfig(http_timeout=10.0)
cache_config = CacheConfig(cache_max_entries=128)
```

Also changed:

- `jwks_cache_max_entries` and `discovery_cache_max_entries` are replaced by
  one `cache_max_entries` (at least 1), applied to each cache.
- The client settings (`client_id`, `client_secret`, discovery URL, scope,
  audience, redirect URIs, excluded paths) are on neither config. For the
  FastAPI package they live on `OIDCSettings`.
- `ConfigIssue` carries `setting` and `message` instead of `code` and `keys`.

See [Configuration](api/config.md) for every setting and its range.

### The library reads no environment variables ([#895](https://github.com/jamescrowley321/identity-model/pull/895), [#893](https://github.com/jamescrowley321/identity-model/pull/893))

These variables are now ignored: `HTTP_TIMEOUT`, `HTTP_RETRY_MAX_ATTEMPTS`,
`HTTP_RETRY_COUNT`, `HTTP_RETRY_BASE_DELAY`, `MAX_JWKS_SIZE`,
`MAX_JWKS_KEYS`, `JWKS_CACHE_TTL`, `DISCO_CACHE_TTL`,
`KID_MISS_REFRESH_COOLDOWN`, `JWKS_CACHE_MAX_ENTRIES`, `SSL_CERT_FILE`,
`CURL_CA_BUNDLE` and `REQUESTS_CA_BUNDLE`. An `HTTPConfig` takes effect only on
a client you pass as `http_client=`, and a `CacheConfig` only on a
`ValidationCache` you pass as `cache=` (see
[Caches live on a `ValidationCache`](#caches-live-on-a-validationcache-not-on-the-http-client-953)).
Without one, an entry point uses the library default client or cache, built
from `HTTPConfig()` or `CacheConfig()`.

Before:

```python
# HTTP_TIMEOUT=10 and MAX_JWKS_KEYS=20 set in the environment
from py_identity_model import validate_token

claims = validate_token(token, validation_config, DISCO_URL)
```

After, building the `HTTPConfig` in code:

```python
from py_identity_model import HTTPClient, HTTPConfig, validate_token

with HTTPClient(config=HTTPConfig(http_timeout=10.0, jwks_max_keys=20)) as client:
    claims = validate_token(token, validation_config, DISCO_URL, http_client=client)
```

After, keeping the same variables with the optional helper:

```python
from py_identity_model import HTTPClient, ValidationCache
from py_identity_model.config_helpers import (
    cache_config_from_env,
    http_config_from_env,
)

client = HTTPClient(config=http_config_from_env())
cache = ValidationCache(config=cache_config_from_env())
```

`http_config_from_env()` and `cache_config_from_env()` read the variable names
listed above, each for its own settings (`JWKS_CACHE_MAX_ENTRIES` sets
`CacheConfig.cache_max_entries`). `prefix="APP_"` reads `APP_HTTP_TIMEOUT` and
so on, and `http_config_from_mapping()` / `cache_config_from_mapping()` take
any mapping, such as python-dotenv's `dotenv_values()`.

The async client works the same way:

```python
from py_identity_model import HTTPConfig
from py_identity_model.aio import AsyncHTTPClient, validate_token

async with AsyncHTTPClient(config=HTTPConfig(http_timeout=10.0)) as client:
    claims = await validate_token(token, validation_config, DISCO_URL, http_client=client)
```

Also changed:

- `HTTPClient` / `AsyncHTTPClient` no longer take `timeout=` or `verify=`.
  For `verify=False` (in a test) or a proxy, wrap your own httpx client:
  `HTTPClient(httpx.Client(verify=False), config=config)`. The wrapped client
  keeps its own timeout and TLS settings; the `HTTPConfig` still sets
  retries and JWKS limits.
- `get_retry_config`, `get_timeout`, `get_max_jwks_size` and
  `get_max_jwks_keys` in `py_identity_model.core.http_utils` are removed.
  `py_identity_model.ssl_config.get_ssl_verify(config)` takes an
  `HTTPConfig`.
- `get_max_cache_entries` and `get_kid_miss_cooldown` in
  `py_identity_model.core.jwks_cache` are removed; read
  `CacheConfig.cache_max_entries` and `CacheConfig.jwks_kid_miss_cooldown`
  instead.
  `resolve_ttl(cache_control, default_ttl)` and
  `resolve_disco_ttl(cache_control, default_ttl)` take the fallback TTL as a
  required argument.
- `build_mtls_client(mtls, config)` (sync and async) and
  `build_mtls_ssl_context(mtls, config)` take a required `HTTPConfig`.
- `get_default_http_client()` and `get_default_async_http_client()` return the
  client that every call without `http_client=` uses, built from
  `HTTPConfig()`.

httpx still honours `SSL_CERT_FILE`, `SSL_CERT_DIR` and the proxy variables
when it builds a client with its default `trust_env=True`. To turn that off,
wrap an `httpx.Client(trust_env=False)`.

### mTLS requests never go through a caller-owned client ([#895](https://github.com/jamescrowley321/identity-model/pull/895))

In 4.x a request with `mtls=` and an `http_client=` raised `ValueError`. In
5.0 the pair is accepted when `http_client` is built from an `HTTPConfig`: the request goes through a short-lived client that
presents the certificate, built from your `http_client`'s `HTTPConfig`
(`ca_bundle`, `http_timeout`, retries). The request never uses your client's
own httpx connection pool, transport or TLS settings, because a pooled client
cannot be guaranteed to present the certificate (RFC 8705 §2). A closed
`http_client` raises `RuntimeError`.

Before:

```python
# The mTLS request always used the default settings.
response = request_client_credentials_token(request)  # request.mtls is set
```

After:

```python
from py_identity_model import HTTPClient, HTTPConfig

with HTTPClient(config=HTTPConfig(ca_bundle="/etc/ssl/private-ca.pem")) as http_client:
    response = request_client_credentials_token(request, http_client=http_client)
```

This works only with an `HTTPClient` built from an `HTTPConfig`. An `HTTPClient`
that wraps your own `httpx.Client` still raises `ValueError` when combined
with `mtls=`, because that client's TLS settings (a pinned CA, a proxy, a
custom transport) cannot be carried over to the certificate client. Set
`ca_bundle` on the `HTTPConfig` instead. See [Mutual TLS](api/mtls.md).

### Caches live on a `ValidationCache`, not on the HTTP client ([#953](https://github.com/jamescrowley321/identity-model/issues/953))

In 4.x the discovery and JWKS caches were module-level, and passing
`http_client=` to `validate_token` bypassed them (and the kid-miss cooldown)
with a warning. In 5.0 they live on a `ValidationCache` (async:
`AsyncValidationCache`), which the token validators take as `cache=`. HTTP
clients only send requests and hold no cache.

- Without `cache=`, `validate_token`, `validate_id_token` and
  `validate_logout_token` use the process-wide default cache, whichever
  `http_client` you pass. An injected client is therefore cached and
  rate-limited like the default one, and a client built per request still
  shares the kid-miss cooldown.
- Cached documents are kept per transport trust scope: clients built from a
  `HTTPConfig` share them per `HTTPConfig.ca_bundle`, and a client wrapping your own
  httpx client shares them only with other wrappers of that httpx client. A
  JWKS fetched through a `verify=False` or proxied client is never used by a
  client that verifies TLS. The kid-miss cooldown is shared by all of them.
  Wrap your httpx client once, not per request, or every request fetches the
  documents again (see
  [Trust scopes](api/http-client.md#trust-scopes)). The scope is the
  `ca_bundle` path, not its contents: after changing a CA bundle in place,
  call `clear_discovery_cache()` and `clear_jwks_cache()`, or build a fresh
  `ValidationCache`.
- The cache settings (`jwks_cache_ttl`, `discovery_cache_ttl`,
  `cache_max_entries`, `jwks_kid_miss_cooldown`) are on the cache's
  `CacheConfig`. An `HTTPConfig` has no cache settings.
- A `ValidationCache`'s state is private
  ([#1060](https://github.com/jamescrowley321/identity-model/issues/1060)):
  `disco`, `jwks`, `disco_write_lock`, `jwks_write_lock`,
  `kid_miss_last_attempt` and the fetch-lock methods are no longer public
  attributes. Its only public member is `config`; clear it with
  `clear_discovery_cache(cache=...)` / `clear_jwks_cache(cache=...)`.
- `clear_discovery_cache()` and `clear_jwks_cache()` take an optional `cache`
  and clear the default cache when it is omitted.
- The default cache and the library default HTTP clients are rebuilt in a
  forked child (gunicorn, uWSGI, `multiprocessing`), so workers never share
  the parent's cache or connections. Build your own caches and clients after
  the fork.
- `close_async_http_client()` can be called from any event loop
  ([#944](https://github.com/jamescrowley321/identity-model/issues/944)).

Before:

```python
# JWKS_CACHE_TTL=900 set in the environment
claims = validate_token(token, validation_config, DISCO_URL)
```

After:

```python
from py_identity_model import CacheConfig, validate_token, ValidationCache

cache = ValidationCache(config=CacheConfig(jwks_cache_ttl=900.0))  # once, at startup

claims = validate_token(token, validation_config, DISCO_URL, cache=cache)
```

The async validators take an `AsyncValidationCache`
(`from py_identity_model.aio import AsyncValidationCache`). Build a cache once
and keep it: a cache built per request starts empty and has no cooldown
history. In the FastAPI package, pass it as `cache=` to
`TokenValidationMiddleware` or `build_ws_authenticator`.

### The JWKS cache keeps keys for 1 hour, not 24 ([#953](https://github.com/jamescrowley321/identity-model/issues/953))

When the JWKS response has no `Cache-Control: max-age`, the key set is now
kept for 1 hour (`CacheConfig.jwks_cache_ttl` defaults to `3600`, was `86400`). A
key the provider pulls stops validating within the hour. A provider's
`max-age` still wins, clamped to 60 – 86400 seconds as before. A provider
without `max-age` sees up to one JWKS fetch per hour per process instead of
one per day.

To keep the 4.x lifetime:

```python
from py_identity_model import CacheConfig, ValidationCache

cache = ValidationCache(config=CacheConfig(jwks_cache_ttl=86400.0))
```

### One `ClientAuthMethod` enum, chosen per request ([#934](https://github.com/jamescrowley321/identity-model/issues/934), [#1056](https://github.com/jamescrowley321/identity-model/issues/1056))

`ClientAuthMethod` now lists every client authentication method the library
implements: `NONE`, `CLIENT_SECRET_BASIC`, `CLIENT_SECRET_POST`,
`PRIVATE_KEY_JWT`, `TLS_CLIENT_AUTH` and `SELF_SIGNED_TLS_CLIENT_AUTH`.

- `ClientAuthMethod.requires_secret` is removed. Use `uses_client_secret`,
  which is true only for the two `client_secret_*` methods. A method that
  isn't `NONE` doesn't necessarily use a secret: `private_key_jwt` and mTLS
  don't.
- `oidc_constants.EndpointAuthenticationMethods` is removed. Use
  `ClientAuthMethod`; the string values are the same.
- `MtlsClientAuth.auth_method` takes a `ClientAuthMethod`, not a string. Any
  method other than the two `TLS_*` ones raises `ClientAuthMethodError`.

Before:

```python
from py_identity_model.oidc_constants import EndpointAuthenticationMethods

if method.requires_secret:
    ...
MtlsClientAuth(certificate=cert, private_key=key,
               auth_method="self_signed_tls_client_auth")
```

After:

```python
from py_identity_model import ClientAuthMethod

if method.uses_client_secret:
    ...
MtlsClientAuth(certificate=cert, private_key=key,
               auth_method=ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
```

Every request that authenticates a client also accepts an optional
`client_auth_method`. Leaving it unset keeps the existing behaviour: the
method is picked from what you set (`private_key_jwt`, then `mtls`, then
`client_secret` as HTTP Basic, else a public client). Setting it sends only
that method. If its credential is missing, nothing is sent: the request
function returns an unsuccessful response whose `error` names the missing
credential. This is how you send `client_secret_post`:

```python
request_client_credentials_token(
    ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id="my-client",
        client_secret="...",
        client_auth_method=ClientAuthMethod.CLIENT_SECRET_POST,
    )
)
```

### `private_key_jwt` assertions are addressed to the issuer ([#950](https://github.com/jamescrowley321/identity-model/issues/950))

`PrivateKeyJwt` has a new `issuer` field. Set it to the authorization
server's issuer identifier (the discovery document's `issuer`), and every
client assertion the library builds (PAR, token, introspection, revocation,
device authorization and token exchange) carries it as `aud`, as
[FAPI 2.0 Security Profile §5.3.3.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.3.1)
requires. An explicit `audience` still wins. With neither set, `aud` is still
the request `address` (the endpoint URL), as in 4.x.

```python
from py_identity_model import PrivateKeyJwt

private_key_jwt = PrivateKeyJwt(
    private_key=pem,
    algorithm="ES256",
    issuer=discovery.issuer,
)
```

`aud` is always a single string. An `audience` or `issuer` that is not a
`str` (for example a list) raises `ValueError` when the request is built;
4.x signed a list into the assertion as a JSON array.

### FastAPI: `OIDCSettings.from_env` is a separate helper ([#899](https://github.com/jamescrowley321/identity-model/pull/899))

The FastAPI package reads no environment variables either. Use the helper,
which reads the same variables with the same `prefix` argument, or construct
`OIDCSettings` yourself.

Before:

```python
from fastapi_identity_model import OIDCSettings

settings = OIDCSettings.from_env()
```

After:

```python
from fastapi_identity_model.config_helpers import oidc_settings_from_env

settings = oidc_settings_from_env()        # OIDC_DISCOVERY_URL, OIDC_CLIENT_ID, ...
settings = oidc_settings_from_env("APP_")  # APP_DISCOVERY_URL, APP_CLIENT_ID, ...
```

HTTP settings for the FastAPI package come from a py-identity-model
`HTTPConfig` on an `AsyncHTTPClient`, passed as `http_client=` to
`TokenValidationMiddleware`, `build_oidc_router`, `build_ws_authenticator`
and `TokenManager`:

```python
from py_identity_model import HTTPConfig
from py_identity_model.aio import AsyncHTTPClient

http_client = AsyncHTTPClient(config=HTTPConfig(http_timeout=10.0))
app.include_router(build_oidc_router(settings, http_client=http_client), prefix="/auth")
```

fastapi-identity-model now requires `py-identity-model>=5.0.0,<6`.

### FastAPI: bound tokens are checked on every request ([#1021](https://github.com/jamescrowley321/identity-model/issues/1021))

`TokenValidationMiddleware` and `build_ws_authenticator` now check a token's
sender constraint (RFC 9449 §7.1, RFC 8705 §3). Unbound bearer tokens behave as
before.

- A DPoP-bound token (`cnf.jkt`) sent as `Bearer` is refused. Send it as
  `Authorization: DPoP <token>` with a `DPoP` proof for the request.
- A certificate-bound token (`cnf["x5t#S256"]`) is refused unless the
  middleware has a client certificate source: `OIDCSettings.client_certificate_header`
  (`OIDC_CLIENT_CERTIFICATE_HEADER`), or a `client_certificate` callable on
  `AuthOptions`. See the next section.

See [DPoP: FastAPI](api/dpop.md#fastapi) for `required_binding` and the
`DPoP` challenge.

### FastAPI: binding options are one `AuthOptions`, read from `OIDCSettings` ([#1064](https://github.com/jamescrowley321/identity-model/issues/1064))

`TokenValidationMiddleware` and `build_ws_authenticator` no longer take
`required_binding=`, `dpop=` or `client_certificate=`. Pass one frozen
`AuthOptions` as `options=` to both, so HTTP and WebSocket routes enforce the
same binding. New validation options are added to `AuthOptions`, not as
keyword arguments on either entry point.

Both entry points also take `settings=`. With `settings` and no `options`,
they use `AuthOptions.from_settings(settings)`, so `OIDCSettings.required_binding`
and `OIDC_REQUIRED_BINDING` take effect; in 4.x and earlier 5.0 builds the
setting was never read. `settings` also supplies `discovery_url`, `audience`
and (middleware only) `excluded_paths` when they are not passed.

Before:

```python
app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    required_binding=settings.required_binding,
    dpop=DPoPVerificationOptions(replay_cache=replay_cache),
    client_certificate=client_certificate,
)
ws_auth = build_ws_authenticator(
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    required_binding=settings.required_binding,
)
```

After:

```python
from fastapi_identity_model import AuthOptions

options = AuthOptions.from_settings(
    settings,
    dpop=DPoPVerificationOptions(replay_cache=replay_cache),
    client_certificate=client_certificate,  # or OIDC_CLIENT_CERTIFICATE_HEADER
)
app.add_middleware(TokenValidationMiddleware, settings=settings, options=options)
ws_auth = build_ws_authenticator(settings=settings, options=options)
```

- `discovery_url` is now optional on both entry points; one of
  `discovery_url` or `settings` is required.
- Explicit `options` win over `settings`, but an `options` whose
  `required_binding` or `expected_origin` differs from a value `settings` sets
  raises `ValueError`. Build it with `AuthOptions.from_settings(settings, ...)`.
- `AuthOptions(required_binding=TokenBinding.MTLS)` without a
  `client_certificate` raises `ValueError`; before, every token was refused at
  request time.
- An `options` without `client_certificate` while
  `settings.client_certificate_header` is set also raises `ValueError`.
- The middleware attributes `required_binding`, `dpop` and
  `client_certificate` are removed; read `middleware.options` instead.
- `OIDCSettings` now validates at construction: `required_binding` is coerced
  with `TokenBinding(...)` (so `"dpop"` works and `"bearer"` raises), an
  invalid `expected_origin` raises `ValueError` (a default port such as `:443`
  is dropped; an internationalized host must be given in punycode), and so does a `client_certificate_header` that is not a valid
  HTTP header name (RFC 9110 token characters only).
- `client_certificate` receives the `Request` or the `WebSocket`
  (`starlette.requests.HTTPConnection`).
- New settings: `client_certificate_header` (`OIDC_CLIENT_CERTIFICATE_HEADER`)
  names a header holding the client certificate PEM, URL-decoded before use
  (nginx `$ssl_client_escaped_cert`). It must carry the leaf certificate
  only: a request carrying the header more than once, or a value with a comma
  or more than one PEM block (a folded header or a full chain, as some
  terminators send), gets no certificate. Use only a header your TLS
  terminator sets on every request and strips from client requests, and keep
  the app port unreachable except through it. `expected_origin`
  (`OIDC_EXPECTED_ORIGIN`) is described below.
- New, opt-in: `AuthOptions.expected_origin` (`scheme://host[:port]`). When
  set, a DPoP proof's `htu` is checked against that origin plus the request
  path and query, not the `Host` header. Unset, the origin still comes from
  the request, so a client that controls the `Host` header your app sees can
  get a proof minted for another origin past the `htu` check. Set it unless a
  trusted proxy pins `Host`.

### DPoP: the replay cache is yours ([#1060](https://github.com/jamescrowley321/identity-model/issues/1060))

`DPoPVerificationOptions` now requires `replay_cache=`, and the process-wide
default replay cache is gone (`get_default_dpop_replay_cache` is removed). A
proof is recorded by the replay cache you pass, which the whole resource
server (or every process behind a load balancer) must share. Build it once:

```python
from py_identity_model import (
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenValidationConfig,
)

dpop = DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())  # at startup
config = TokenValidationConfig(perform_disco=True, audience="api", dpop=dpop)
```

A common mistake: building the options (and so the cache) inside the request
handler. Each request then gets an empty cache, so every replay within the
proof window is accepted, with no error. Build them once at startup.

- A DPoP-bound access token with a proof and no `dpop` options
  (`TokenValidationConfig.dpop=None`, or `check_introspection_binding` without
  `dpop=`) now raises `ConfigurationException`. It used to be checked against
  the hidden process-wide cache. `TokenValidationConfig` with
  `required_binding=TokenBinding.DPOP` and no `dpop` raises it when built.
- A replay cache whose `check_and_store` does not take the four arguments
  below (a 4.x three-argument cache) is refused by `DPoPVerificationOptions`
  with `TypeError`.
- `verify_dpop_proof(proof, request, options)` takes `options` as a required
  argument, and `DPoPVerificationOptions` is keyword-only.
- `DPoPReplayCache.check_and_store(jkt, jti, expires_at, now)` takes the proof
  key's thumbprint, so one client's `jti` can never block another's, and
  returns a `DPoPReplayCheck` (`RECORDED`, `REPLAYED` or `FULL`). It no longer
  returns `bool` or raises `REPLAY_CACHE_FULL`; the verifier raises
  `DPoPValidationError` with `REPLAYED_JTI` or `REPLAY_CACHE_FULL` from the
  answer. A custom cache must be updated.
- For a store reached over the network, implement `AsyncDPoPReplayCache`
  (an `async def check_and_store`) and use the async validators
  (`py_identity_model.aio.validate_token`,
  `py_identity_model.aio.check_introspection_binding`,
  `py_identity_model.aio.verify_dpop_proof`). The sync validators refuse an
  async cache, or any cache that returns an awaitable, with
  `DPoPReplayCacheError` (a `ConfigurationException`).
- A cache answer that is not a `DPoPReplayCheck` raises `DPoPReplayCacheError`.
  The FastAPI middleware answers it with `500` (WebSocket close `1011`).
- `py_identity_model.aio.check_introspection_binding` and
  `py_identity_model.aio.verify_dpop_proof` are coroutines, like every `aio`
  function, and must be awaited. A call without `await` runs no check and
  raises nothing, so an inactive, unbound or replayed token is accepted:

  ```python
  from py_identity_model.aio import check_introspection_binding, verify_dpop_proof

  await check_introspection_binding(response, access_token, presentation, dpop=dpop)
  proof = await verify_dpop_proof(dpop_header, proof_request, dpop)

  # Wrong: returns an unawaited coroutine; nothing is checked.
  check_introspection_binding(response, access_token, presentation, dpop=dpop)
  ```

  Python only logs `RuntimeWarning: coroutine ... was never awaited`. A type
  checker catches a missing `await`: pyright's `reportUnusedCoroutine` and
  pyrefly's `unused-coroutine` are on by default; keep them on.
- The proof is recorded last, after the certificate binding check too, so a
  token refused for its certificate does not use up its proof.
- The FastAPI package keeps one default replay cache per process:
  `AuthOptions.dpop` (and `AuthOptions(dpop=None)`) defaults to options with
  an `InMemoryDPoPReplayCache` shared by every middleware and WebSocket
  authenticator built without explicit `dpop` options. Explicit
  `AuthOptions(dpop=...)` options use the cache you pass.
- `InMemoryDPoPReplayCache` copies (`copy.deepcopy`, `dataclasses.asdict`)
  are the same cache; pickling one raises `TypeError`.

## Discovery

### Every Discovery §3 REQUIRED field must be present ([#891](https://github.com/jamescrowley321/identity-model/pull/891))

A discovery document missing any of `issuer`, `authorization_endpoint`,
`token_endpoint`, `jwks_uri`, `response_types_supported`,
`subject_types_supported` or `id_token_signing_alg_values_supported` fails
with `DiscoveryErrorKind.MISSING_FIELDS`, and `missing_fields` lists every
missing name in spec order. A field counts as missing when it is absent or
falsy: `null`, `""`, `[]`, `false`, `0` or `{}`. A body that is valid JSON but
not an object (for example a top-level array) fails with
`DiscoveryErrorKind.INVALID_JSON`.

`DiscoveryPolicy.require_key_set` is removed; `jwks_uri` is always required.

Before:

```python
from py_identity_model import DiscoveryPolicy

policy = DiscoveryPolicy(require_key_set=False)
```

After:

```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryErrorKind,
    DiscoveryPolicy,
    get_discovery_document,
)

disco = get_discovery_document(
    DiscoveryDocumentRequest(address=AUTHORITY, policy=DiscoveryPolicy())
)
if not disco.is_successful and disco.error_kind is DiscoveryErrorKind.MISSING_FIELDS:
    print(disco.missing_fields)  # e.g. ("jwks_uri",)
```

A missing `jwks_uri` now reports `Missing required parameters: jwks_uri`.

`DiscoveryPolicy`'s fields after `validate_endpoints`
(`additional_endpoint_base_addresses`, `authority`,
`allow_loopback_endpoints`) are keyword-only. A call that passed
`require_key_set` as the fifth positional argument raises `TypeError`: drop it
and pass the later fields by name.

```python
# Before
DiscoveryPolicy(True, True, True, True, True, ["https://login.example.com"])

# After
DiscoveryPolicy(additional_endpoint_base_addresses=["https://login.example.com"])
```

### FAPI 2.0: `response_types_supported` is required ([#877](https://github.com/jamescrowley321/identity-model/pull/877))

`validate_fapi_discovery` reports a violation when the document has no
`response_types_supported`. In 4.x it assumed `["code"]`. A missing
`id_token_signing_alg_values_supported` is still a violation, and the
message no longer mentions an `RS256` default. Both fields are REQUIRED
provider metadata (Discovery §3), so a document missing them also fails
`get_discovery_document` with `DiscoveryErrorKind.MISSING_FIELDS`.

### FAPI 2.0: absent capability metadata is a violation ([#949](https://github.com/jamescrowley321/identity-model/issues/949))

In 4.x, `validate_fapi_discovery` passed a document that did not mention a
capability FAPI 2.0 requires. In 5.0 each of these is a violation:

| Metadata | Violation when | Requirement |
|---|---|---|
| `code_challenge_methods_supported` | absent (RFC 8414 §2: no PKCE) or without `S256` | [FAPI 2.0 Security Profile §5.3.2.2](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2) |
| `pushed_authorization_request_endpoint` | absent, empty, or not a string (`true` used to pass, [#1068](https://github.com/jamescrowley321/identity-model/issues/1068)) | §5.3.2.2, RFC 9126 |
| `authorization_response_iss_parameter_supported` | absent or `false` | §5.3.2.2, RFC 9207 §3 |
| `dpop_signing_alg_values_supported`, `tls_client_certificate_bound_access_tokens` | neither a DPoP list with a FAPI algorithm (§5.4.1) nor `true` for MTLS | [§5.3.2.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1) |
| `token_endpoint_auth_signing_alg_values_supported` | `private_key_jwt` is offered and the list is absent or has no FAPI algorithm | [§5.4.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1) |

`FAPI2_ALLOWED_SIGNING_ALGORITHMS` now includes `EdDSA` (§5.4.1), for both
`validate_fapi_discovery` and `validate_fapi_authorization_request`.
`DiscoveryDocumentResponse` gains `dpop_signing_alg_values_supported`
(RFC 9449 §5.1). Only `grant_types_supported` and
`token_endpoint_auth_methods_supported` still take their RFC 8414 §2 default
when absent. A server that passed in 4.x without advertising these fields now
reports violations until its metadata advertises them. A metadata value
that is not an array of strings counts as advertising nothing.

### FAPI 2.0: a fail-closed client profile; validators take request objects ([#951](https://github.com/jamescrowley321/identity-model/issues/951))

`FAPI2ClientProfile` builds an immutable FAPI 2.0 client from
the authorization server's discovery document. It raises `FAPIProfileError`
(a `ValueError` with a `violations` list) when the document fails
`validate_fapi_discovery`, when the client does not authenticate with
`private_key_jwt` or mTLS, or when the redirect URI is not `https` (an `http`
loopback URI is allowed with `native_app=True`). It fills
`PrivateKeyJwt.issuer` from the discovery issuer and refuses an `audience` or
`issuer` that names anything else, so the assertion `aud` is never the
endpoint URL. Its request builders fix PAR, `response_type=code` and PKCE
`S256`, require a DPoP key for a `private_key_jwt` client whose algorithm the
server lists in `dpop_signing_alg_values_supported`, cap `nonce` at 64
characters, and raise on anything that would weaken the flow. The issuer and
every endpoint must be an `https` URL with a host.
`validate_callback_issuer` requires the RFC 9207 `iss` parameter, and
`signing_algorithms` is the list to pass when validating ID Tokens and JARM
responses.

```python
profile = FAPI2ClientProfile(
    discovery,
    client_id="fapi-client",
    redirect_uri="https://client.example.com/callback",
    client_auth=PrivateKeyJwt(private_key=pem, algorithm="ES256"),
)
dpop_key = generate_dpop_key("ES256")
par = push_authorization_request(
    profile.pushed_authorization_request(
        state=state, nonce=nonce, code_challenge=challenge, dpop_key=dpop_key
    )
)
redirect_to(profile.authorization_url(par.request_uri))
```

`validate_fapi_authorization_request` and `validate_fapi_client_config` now
check real objects instead of booleans:

```python
# Before
validate_fapi_authorization_request(
    response_type="code", code_challenge=challenge,
    code_challenge_method="S256", redirect_uri=uri, use_par=True,
    algorithm="ES256",
)
validate_fapi_client_config(auth_method="private_key_jwt", use_dpop=True)

# After
validate_fapi_authorization_request(par_request)  # a PushedAuthorizationRequest
validate_fapi_client_config(
    issuer=discovery.issuer,
    private_key_jwt=private_key_jwt,
    dpop_key=dpop_key,
)
```

The request validator now also checks the request's client authentication,
its DPoP key algorithm and its `nonce` length. The client validator reports
a `private_key_jwt` whose assertion `aud` would not be the issuer.

### FAPI 2.0: violations are typed ([#1059](https://github.com/jamescrowley321/identity-model/issues/1059))

`FAPIValidationResult.violations` and `FAPIProfileError.violations` were
`list[str]`. They are now `list[FAPIViolation]`: each has a `code` (a
`FAPIViolationCode`) and a `message`. Match on the code; the message is for
people and may change. Both also have `codes`, the codes in order.
`str(violation)` is the message, and `str(FAPIProfileError)` is unchanged.

```python
# Before
except FAPIProfileError as exc:
    if any(v.startswith("PKCE") for v in exc.violations):
        ...

# After
except FAPIProfileError as exc:
    if FAPIViolationCode.PKCE_METHOD_NOT_S256 in exc.codes:
        ...
```

### FAPI 2.0: frozen client-auth types and a separate signed PAR type ([#1061](https://github.com/jamescrowley321/identity-model/issues/1061))

`PrivateKeyJwt`, `MtlsClientAuth` and `RequestObjectKey` are frozen
dataclasses. Assigning a field raises `dataclasses.FrozenInstanceError`; use
`dataclasses.replace` to derive a changed copy. `FAPI2ClientProfile` now keeps
the objects you pass instead of copying them, and checks client
authentication and the request object key once, at construction.

A pushed authorization request sent as a signed request object is now a
`SignedPushedAuthorizationRequest`. `PushedAuthorizationRequest` no longer has
a `request` field, and the signed type has no fields for the authorization
parameters, because RFC 9126 §3 puts them inside the request object. A blank
`request` raises `ConfigurationException` instead of falling back to a plain
request. `push_authorization_request` takes either type, and
`FAPI2ClientProfile.pushed_authorization_request` returns the signed type when
the profile has a `request_object_key`.

```python
# Before
PushedAuthorizationRequest(
    address=par_endpoint, client_id=client_id, request=request_object,
    private_key_jwt=private_key_jwt,
)

# After
SignedPushedAuthorizationRequest(
    address=par_endpoint, client_id=client_id, request=request_object,
    private_key_jwt=private_key_jwt,
)
```

`validate_fapi_authorization_request` accepts a
`SignedPushedAuthorizationRequest` and checks the request object's claims
(`response_type`, PKCE, `nonce`, `redirect_uri`), its header `alg` (FAPI 2.0
Security Profile §5.4.1), that `exp - nbf` is at most 3600 seconds (FAPI
2.0 Message Signing §5.3.2), and that its `client_id` and `iss` match the
request's `client_id` (RFC 9101). An encrypted request object is reported as
a violation, because its claims cannot be read. These carry the codes
`REQUEST_OBJECT_INVALID`, `REQUEST_OBJECT_ENCRYPTED`,
`REQUEST_OBJECT_CLIENT_ID_MISMATCH`, `REQUEST_OBJECT_ISSUER_MISMATCH`,
`REQUEST_OBJECT_LIFETIME_INVALID` and `NONCE_INVALID`. Before, it read only the plain fields and
reported violations for compliant signed requests
([#1016](https://github.com/jamescrowley321/identity-model/issues/1016)). It
does not verify the request object's signature or `aud`.

### The issuer must match the requested issuer ([#842](https://github.com/jamescrowley321/identity-model/pull/842))

The document's `issuer` must equal the address you requested it from (OIDC
Discovery 1.0 §4.3, RFC 8414 §3.3). Otherwise discovery fails with
`DiscoveryErrorKind.ISSUER_MISMATCH`. The comparison is an exact string match
against `DiscoveryDocumentRequest.address` as you passed it, with
`/.well-known/openid-configuration` removed. A trailing slash on either side
is the only difference allowed: host case, an explicit port and the path all
count. No `DiscoveryPolicy` setting turns this off.

Before (accepted in 4.x):

```python
# The provider's document says "issuer": "https://login.example.com"
disco = get_discovery_document(
    DiscoveryDocumentRequest(address="https://LOGIN.example.com:443")
)
```

After:

```python
disco = get_discovery_document(
    DiscoveryDocumentRequest(address="https://login.example.com")
)
# Also accepted:
#   "https://login.example.com/"
#   "https://login.example.com/.well-known/openid-configuration"
```

Use the issuer exactly as your provider publishes it. If you call
`process_discovery_response` (`py_identity_model.core.discovery_logic`) or
`validate_and_parse_discovery_response`
(`py_identity_model.core.response_processors`) directly, both now take a
required keyword-only `requested_address`:

```python
from py_identity_model.core.discovery_logic import process_discovery_response

disco = process_discovery_response(
    response, policy, requested_address="https://login.example.com"
)
```

## DPoP client

### A refused Bearer answer keeps its tokens; the opt-in needs a key ([#1063](https://github.com/jamescrowley321/identity-model/issues/1063))

`require_dpop_token_type` stays opt-in and off by default. RFC 9449 §5 leaves
the choice to the application: when the response carries a `token_type` other
than `DPoP`, the client "MUST discard the response in this case if this
protection is deemed important for the security of the application;
otherwise, the client may continue as in a regular OAuth interaction."
`FAPI2ClientProfile` sets it on every DPoP-bound token request, because FAPI
2.0 requires sender-constrained access tokens (Security Profile §5.3.2.1).

Two things change:

- A response refused with `TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH` keeps the
  tokens the server issued on the new `rejected_token` field, so a rotated
  refresh token is not lost and the Bearer tokens can still be revoked.
  `token` stays guarded on a failed response, and `repr` redacts
  `rejected_token`.
- `require_dpop_token_type=True` without a `dpop_key` raises `ValueError`
  when the request is built. In 4.x it failed every response.

```python
response = refresh_token(
    RefreshTokenRequest(..., dpop_key=key, require_dpop_token_type=True)
)
if response.error_kind is TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH:
    revoke_or_store(response.rejected_token)
```

### Load a stored DPoP key; algorithms are a `DPoPAlgorithm` ([#1063](https://github.com/jamescrowley321/identity-model/issues/1063))

`DPoPKey.from_pem(pem, algorithm)` and `DPoPKey.from_jwk(jwk, algorithm=None)`
load an existing private key, so tokens bound to it stay usable across
restarts. Both refuse a key the algorithm cannot sign with.

`DPoPKey.algorithm` now returns a `DPoPAlgorithm`. It is a `StrEnum`, so it
still compares equal to `"ES256"` and the other strings, and
`generate_dpop_key("ES256")` keeps working.

### Each retry attempt mints a fresh DPoP proof ([#1019](https://github.com/jamescrowley321/identity-model/issues/1019))

The authorization code, refresh, client credentials and PAR calls now build
the request, including the DPoP proof and any `private_key_jwt` assertion,
on every `429`/`5xx` backoff attempt. A server that remembers `jti` values
(RFC 9449 §11.1) no longer rejects the retry as a replay. No API change.

## Access token validation

### A bound access token without a presentation is rejected ([#1062](https://github.com/jamescrowley321/identity-model/issues/1062))

In 4.x, `validate_token` without `presentation=` skipped the sender-constraint
check, so a DPoP-bound or certificate-bound access token was accepted as a
plain bearer token. 5.0 rejects it, whatever `required_binding` is: a resource server "MUST
reject a DPoP-bound access token received as a bearer token" (RFC 9449 §7.2),
and a certificate-bound token is valid only with the certificate it is bound
to (RFC 8705 §3).

- A token with `cnf.jkt` raises `DPoPValidationError` with kind
  `PROOF_REQUIRED`.
- A token with `cnf["x5t#S256"]` raises `CertificateBindingError`.
- An unbound token is accepted as before, unless `required_binding` is `DPOP`
  or `MTLS` (still a `ConfigurationException` without `presentation=`).

To accept a bound token, pass how it arrived, with the scheme from the
request's `Authorization` header:

```python
scheme, _, access_token = request.headers["Authorization"].partition(" ")
claims = validate_token(
    access_token,
    config,
    disco_doc_address,
    presentation=TokenPresentation(
        scheme=(
            AuthorizationScheme.DPOP
            if scheme.lower() == "dpop"
            else AuthorizationScheme.BEARER
        ),
        method=request.method,
        url="https://api.example.com/orders",
        dpop_proof=request.headers.get("DPoP"),  # for cnf.jkt
        client_certificate=client_certificate,  # for cnf["x5t#S256"], from mTLS
    ),
)
```

The check applies to access tokens only: `validate_token`, and the FastAPI
middleware and WebSocket authenticator, which already pass a presentation (see
[DPoP](api/dpop.md)). `validate_id_token` and `validate_logout_token` do not run
it, so an ID Token or Logout Token carrying `cnf` still validates: neither
arrives with a presentation (OIDC Core §3.1.3.7, Back-Channel Logout §2.6).
Validate those tokens with their own functions, not `validate_token`.

The FastAPI `build_oidc_router` callback now validates the ID Token with
`validate_id_token` instead of `validate_token`, so it also applies the ID
Token profile (required `sub`, no untrusted additional audience, OIDC Core
§3.1.3.7). An ID Token whose `aud` lists anything besides `client_id` now
fails the login with a 401. If your provider issues multi-audience ID Tokens,
list the extra audiences in `OIDCSettings.trusted_audiences`
(`OIDC_TRUSTED_AUDIENCES`, comma-separated)
([#1099](https://github.com/jamescrowley321/identity-model/issues/1099)).
Whenever you set `OIDC_TRUSTED_AUDIENCES`, also set `OIDC_VALIDATE_AZP=true`
(`validate_azp=True`), so the token must name your client in `azp`; without
it, an ID Token issued to another client that also lists yours in `aud` logs
in. The `azp` check stays off by default because §3.1.3.7 makes it a SHOULD:

```python
settings = OIDCSettings(
    discovery_url=DISCOVERY_URL,
    client_id="my-client",
    redirect_uri=REDIRECT_URI,
    trusted_audiences=["https://api.example.com"],
    validate_azp=True,
)
```

### Check the introspected `cnf` of an opaque token ([#1094](https://github.com/jamescrowley321/identity-model/issues/1094))

A resource server that authorizes opaque tokens through `introspect_token`
learns the token's binding from the response's `cnf` (RFC 9449 §6.2, RFC 8705
§3.2). 4.x never checked it, so a DPoP-bound or certificate-bound opaque token
was accepted as a bearer token. Call `check_introspection_binding` after
introspecting. It has the rules and errors of `validate_token`: a token with
`cnf.jkt` and no presentation raises `DPoPValidationError` (`PROOF_REQUIRED`), a
token with `cnf["x5t#S256"]` raises `CertificateBindingError` unless the bound
certificate is presented, and an unbound token passes. It fails closed: a
failed introspection, or a token that "is not active" (RFC 7662 §2.2), raises
`IntrospectedTokenError` (kind `INTROSPECTION_FAILED` / `INACTIVE`), so a
normal return means the token is active and correctly bound.

```python
response = introspect_token(request)
check_introspection_binding(  # raises unless active and correctly bound
    response,
    access_token,
    presentation,  # a TokenPresentation, see Token Introspection
)
```

`introspect_token` does not run the check; see
[Token Introspection](api/introspection.md#sender-constrained-opaque-tokens).

### Certificate binding errors have a kind; a bad presentation is a `ConfigurationException` ([#1059](https://github.com/jamescrowley321/identity-model/issues/1059))

`CertificateBindingError` now takes a `CertificateBindingErrorKind` and has a
`kind`: `NOT_BOUND`, `INVALID_THUMBPRINT`, `MISMATCH`, `CERTIFICATE_REQUIRED`
or `INVALID_CERTIFICATE`. The message is fixed per kind, so match on `kind`,
not on the text. `CertificateBindingError(message)` no longer works; raise it
with a kind.

`check_token_binding`, `check_introspection_binding` and `validate_token`
raised a bare `ValueError` when a DPoP proof had to be checked but
`presentation.method` or `presentation.url` was missing, or the URL was not an
absolute http(s) URI. They now raise `ConfigurationException`, as they already
did for `required_binding` without a presentation. Treat it as a server fault
in your own handler, not as a bad token: it is a `PyIdentityModelException`, so
a broad `except PyIdentityModelException` that answers 401 would hide it. The
FastAPI middleware and WebSocket authenticator build the presentation from the
request's absolute URL and method, so they never hit this.

### Signed introspection gets its keys from discovery ([#1067](https://github.com/jamescrowley321/identity-model/issues/1067))

Signed introspection responses (RFC 9701) are new in 5.0.
`SignedIntrospectionOptions` takes either `discovery_address` or both `issuer`
and `jwks`; passing both, or neither, raises `ValueError`.

- **Discovery mode** (`discovery_address=`, recommended): the issuer, keys and
  algorithms come from the discovery document. The keys go through the
  validation cache, and an unknown `kid` refreshes them once, so the
  authorization server can rotate keys. `introspect_token` takes
  `cache=` (keyword-only) for an injected `ValidationCache` /
  `AsyncValidationCache`. A discovery document or JWK Set that can't be
  fetched fails the call with `error_kind=None`.
- **Manual mode** (`issuer=`, `jwks=`): the keys are fixed and never
  refreshed.
- **Algorithms.** With `algorithms=None`, discovery mode allows the
  `introspection_signing_alg_values_supported` algorithms that are in
  `DEFAULT_ALLOWED_ALGORITHMS` (all of them if nothing is advertised; none if
  the value is not a list). An explicit `algorithms` replaces that.
- **`leeway=`** (seconds, keyword-only) tolerates clock skew in `iat`. The
  default is none.
- **`TokenIntrospectionResponse.jwt_claims`** holds the verified claims of the
  response JWT (`iss`, `aud`, `iat`, ...) without `token_introspection`. It is
  `None` for a plain JSON response.

```python
from py_identity_model import SignedIntrospectionOptions

signed = SignedIntrospectionOptions(discovery_address=disco_address)
```

## ID Token validation

### Untrusted additional audiences are rejected ([#881](https://github.com/jamescrowley321/identity-model/pull/881))

`validate_id_token` and `validate_id_token_claims` reject an ID Token whose
`aud` contains any value other than your `client_id`, unless you list it in
the new `trusted_audiences=` argument (OIDC Core §3.1.3.7 step 3). The error is
`UntrustedAudienceException`, a subclass of `IdTokenValidationException`,
with the rejected values in `details["untrusted_audiences"]`. The list only
adds trusted audiences; it cannot turn the check off. Without a `client_id`
and without the list, every audience is untrusted.

Before:

```python
claims = validate_id_token(
    id_token,
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
)
```

After, for a token with `"aud": [CLIENT_ID, "https://api.example.com"]`:

```python
claims = validate_id_token(
    id_token,
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
    trusted_audiences=["https://api.example.com"],
)
```

`trusted_audiences` must be an iterable of strings. A bare string raises
`ConfigurationException` instead of being read as a set of characters:

```python
validate_id_token(..., trusted_audiences="https://api.example.com")    # ConfigurationException
validate_id_token(..., trusted_audiences=["https://api.example.com"])  # OK
```

### An ID Token without `aud` is rejected ([#881](https://github.com/jamescrowley321/identity-model/pull/881))

`aud` is REQUIRED in an ID Token (OIDC Core §2). A token whose `aud` is
absent, `null`, an empty array or only empty strings now raises
`IdTokenValidationException` ("ID token missing required 'aud' claim"),
whether or not a `client_id` is set. In 4.x, `validate_id_token_claims`
called without a `client_id` accepted such a token.

```python
from py_identity_model import IdTokenValidationException
from py_identity_model.core.id_token_logic import validate_id_token_claims

claims = {"iss": ISSUER, "sub": "248289761001", "iat": 1699999900, "exp": 1700003600}

try:
    validate_id_token_claims(claims, "RS256", nonce=None)  # accepted in 4.x
except IdTokenValidationException:
    ...  # 5.0: no aud
```

### `azp` rules are opt-in ([#885](https://github.com/jamescrowley321/identity-model/pull/885))

`validate_id_token` and `validate_id_token_claims` no longer check `azp` by
default. OIDC Core 1.0 errata set 2 makes neither rule a MUST, and §2 tells
relying parties that use no extensions to ignore `azp`. Pass
`validate_azp=True` to keep rejecting multi-audience tokens without `azp` and
tokens whose `azp` is not your `client_id`.

Before:

```python
claims = validate_id_token(
    id_token, validation_config, disco_doc_address=DISCOVERY_URL, nonce=expected_nonce
)
```

After, keeping the 4.x behaviour:

```python
claims = validate_id_token(
    id_token,
    validation_config,
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
    validate_azp=True,
)
```

### `validate_azp=True` requires a `client_id` ([#930](https://github.com/jamescrowley321/identity-model/issues/930))

`validate_azp=True` without a `client_id` used to compare `azp` against
nothing: a multi-audience token still needed an `azp`, but any `azp` value was
accepted. It now raises `AzpRequiresClientIdError`, a `ConfigurationException`,
before any discovery or JWKS request and whatever the token carries. Set
`token_validation_config.audience` to your `client_id` (or pass `client_id=`
to `validate_id_token_claims`).

Before:

```python
config = TokenValidationConfig(perform_disco=True, issuer=ISSUER)
claims = validate_id_token(
    id_token,
    config,
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
    validate_azp=True,
)
```

After:

```python
config = TokenValidationConfig(perform_disco=True, issuer=ISSUER, audience=CLIENT_ID)
claims = validate_id_token(
    id_token,
    config,
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
    validate_azp=True,
)
```

### An empty `client_id` means no `client_id` ([#1065](https://github.com/jamescrowley321/identity-model/issues/1065))

`client_id=""` (or `TokenValidationConfig(audience="")` with
`validate_id_token`) is now the same as passing no `client_id`, as in the Go
library. In 4.x it counted as configured:

- `validate_azp=True` with `client_id=""` now raises
  `AzpRequiresClientIdError`.
- `""` is no longer a configured audience, so `validate_id_token` rejects any
  token with an `aud` claim with `InvalidAudienceException`, exactly as with
  no `client_id`. In 4.x a token whose `aud` listed `""` was accepted.
- In `validate_id_token_claims`, `client_id=""` no longer makes `""` a trusted
  audience: a token whose `aud` lists `""` is rejected with
  `UntrustedAudienceException` unless `""` is listed in `trusted_audiences`.

This applies to `validate_id_token` only. `validate_token` still treats
`audience=""` as a configured audience, so a token with no `aud` is rejected;
unsetting it there would turn the `aud` check off.

Pass your real `client_id`.

### `nonce` is a required argument ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

`validate_id_token` (sync and async) and `validate_id_token_claims` take a
required keyword `nonce: str | None`. Pass the `nonce` you sent on the
authorization request, or `None` when you sent none. In 4.x leaving it out
skipped the check, so a token carrying a `nonce` was accepted unchecked.

- A string: the token's `nonce` MUST be present and equal it (OIDC Core
  §3.1.3.7 step 11, §3.2.2.11 step 2). For an ID Token from a refresh, pass
  the original nonce (§12.2).
- `None`: a token that carries a `nonce` raises `IdTokenValidationException`,
  because §2 requires a present `nonce` to equal the value sent, and none was.

Before:

```python
claims = validate_id_token(id_token, validation_config, disco_doc_address=DISCOVERY_URL)
```

After:

```python
claims = validate_id_token(
    id_token, validation_config, disco_doc_address=DISCOVERY_URL, nonce=expected_nonce
)
```

### ID Tokens require `exp` and `iat` ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

`exp` and `iat` are REQUIRED in an ID Token (OIDC Core §2). `validate_id_token`
and `validate_id_token_claims` raise the new `IdTokenMissingClaimError` (an
`IdTokenValidationException`) when either is absent. Its `claim` is an
`IdTokenRequiredClaim` (`EXP` or `IAT`). In 4.x the values were checked only
when present, so a validly signed ID Token without them was accepted.

```python
from py_identity_model import IdTokenMissingClaimError, IdTokenRequiredClaim

try:
    claims = validate_id_token(id_token, validation_config, DISCOVERY_URL, nonce=nonce)
except IdTokenMissingClaimError as exc:
    assert exc.claim in (IdTokenRequiredClaim.EXP, IdTokenRequiredClaim.IAT)
```

`validate_token` is unchanged: for a generic JWT, RFC 7519 §4.1.4 and §4.1.6
make `exp` and `iat` OPTIONAL. Its `exp` and `iat` values are checked when
present.

### Without discovery, an issuer is required ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

With `perform_disco=False`, `validate_id_token` and `validate_logout_token`
(sync and async) raise `ConfigurationException` when
`TokenValidationConfig.issuer` is `None`, `""` or empty. The OP issuer MUST
match the token's `iss` (OIDC Core §3.1.3.7 step 2; Back-Channel Logout 1.0
§2.6 step 4), and in 4.x such a config skipped the `iss` check. Discovery mode
is unchanged: it always checks the discovered issuer.

```python
config = TokenValidationConfig(
    perform_disco=False, key=op_public_jwk, audience=CLIENT_ID, issuer=ISSUER
)
claims = validate_id_token(id_token, config, nonce=expected_nonce)
```

### A missing `at_hash` / `c_hash` is reported as missing ([#887](https://github.com/jamescrowley321/identity-model/pull/887))

When you pass `access_token=` or `code=`, the matching hash claim is still
required by default, but an absent claim now raises
`IdTokenValidationException` with "ID token missing required 'at_hash'
claim ..." instead of a hash-mismatch message.

An ID Token from the token endpoint may omit `at_hash` (OIDC Core §3.1.3.6).
Pass `access_token_issued_with_id_token=False` (or
`code_issued_with_id_token=False`) when the value did not come back with the
ID Token: an absent claim is then accepted, and a present one must still
match.

```python
claims = validate_id_token(
    id_token,
    validation_config,
    disco_doc_address=DISCOVERY_URL,
    nonce=expected_nonce,
    access_token=token_response.access_token,
    access_token_issued_with_id_token=False,  # code flow: from the token endpoint
)
```

See [ID Token validation](api/id-token.md).

## Signing key selection

### Typed exceptions for key-selection failures ([#889](https://github.com/jamescrowley321/identity-model/pull/889))

Two failures that raised a plain `TokenValidationException` in 4.x now raise
subclasses of it, with the same message and `details`:

- `AmbiguousKeyException`: a token with no `kid` matches more than one key in
  the JWK Set. `details["available_kids"]` and `details["key_count"]`
  describe the candidates.
- `KeyAlgorithmMismatchException`: the selected key declares an `alg` that
  differs from the token's header `alg` (RFC 7517 §4.4).

An existing `except TokenValidationException` still catches both. Catch the
subclass to handle the case on its own:

```python
from py_identity_model import AmbiguousKeyException, validate_token

try:
    claims = validate_token(token, validation_config, DISCOVERY_URL)
except AmbiguousKeyException as exc:
    print(exc.details["available_kids"])
```

### `use: "enc"` keys never verify signatures ([#888](https://github.com/jamescrowley321/identity-model/issues/888))

A JWK marked `use: "enc"` is for encryption only
([RFC 7517 §4.2](https://www.rfc-editor.org/rfc/rfc7517#section-4.2)), so 5.0
never uses one to verify a signature. Only keys whose `use` is `sig` or absent
are considered. In 4.x a `kid` naming an `enc` key selected it, and a token
with no `kid` fell back to the `enc` keys when the set held no signing key.

- A `kid` that names only an `enc` key is treated like an unknown `kid`: one
  JWK Set refresh, then `KeyNotFoundException`.
- A token with no `kid` against a set with no signing key raises
  `KeyNotFoundException`, not `AmbiguousKeyException`.

`KeyNotFoundException` is new. It subclasses `TokenValidationException`, and
an unknown `kid` raises it too, with the same message as in 4.x. A provider
that labels its signing keys `use: "enc"` must fix the label. Its tokens fail
validation until it does.

```python
from py_identity_model import KeyNotFoundException, validate_token

try:
    claims = validate_token(token, validation_config, DISCOVERY_URL)
except KeyNotFoundException as exc:
    print(exc.details["kid"], exc.details["available_kids"])
```

### An empty `kid` or `use` means absent; `key_ops` is accepted ([#1065](https://github.com/jamescrowley321/identity-model/issues/1065))

5.0 reads JWKs the way the Go and Rust libraries do:

- `"kid": ""` in a token header means the token has no `kid`: the key is
  chosen as for a token without one (the single signing key, or
  `AmbiguousKeyException`). In 4.x it was looked up as the key ID `""`. A JWK
  with `"kid": ""` is parsed with `kid=None`.
- `"use": ""` on a JWK means `use` is absent, so the key is a signing key. In
  4.x the key was dropped.
- A JWK with both `use` and `key_ops`, with `key_ops` values outside the RFC
  7517 §4.3 registry, or with a `use` other than `sig`, `enc` or an `https://`
  URI is now accepted. In 4.x it was dropped. A key whose `use` is anything
  other than `sig` or absent still never verifies a signature.

`key_ops` does not affect whether a key verifies. When a JWK Set is parsed, a
`key_ops` that is not a list of strings, or a `use` that is not a string,
still makes the key unusable.

### `algorithms=None` allows only asymmetric algorithms ([#952](https://github.com/jamescrowley321/identity-model/issues/952))

In 4.x, a discovery-mode `TokenValidationConfig` with `algorithms=None` (the
default) accepted any algorithm that matched the resolved key, including
`HS256` with an `oct` key from the JWK Set. In 5.0, `None` means
`DEFAULT_ALLOWED_ALGORITHMS`: RS256/384/512, PS256/384/512, ES256/384/512 and
EdDSA. Go has the same default; Rust's omits ES512
([#1011](https://github.com/jamescrowley321/identity-model/issues/1011)). A token signed with any
other algorithm raises `TokenValidationException`
(`"Algorithm 'HS256' is not in the allowed algorithms"`).

An explicit `algorithms` list works as before. Manual mode is covered in the
next section. To keep accepting an HMAC-signed token, list its algorithm:

```python
config = TokenValidationConfig(
    perform_disco=True,
    audience="my-api",
    algorithms=["HS256"],
)
```

### One algorithm allowlist per purpose ([#1058](https://github.com/jamescrowley321/identity-model/issues/1058))

5.0 has one allowlist per purpose, and `algorithms=None` means the verify set
everywhere (see
[Algorithm allowlists](api/token-validation.md#algorithm-allowlists)):

| Purpose | Set | Contents |
|---|---|---|
| Verify (every inbound JWS) | `DEFAULT_ALLOWED_ALGORITHMS` | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA |
| Sign (client assertions, request objects) | `SUPPORTED_SIGNING_ALGORITHMS` | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA |
| FAPI 2.0 (only when passed) | `FAPI2_ALLOWED_SIGNING_ALGORITHMS` | PS256, ES256, EdDSA |

`DEFAULT_ALLOWED_ALGORITHMS` is no longer the same object as
`SUPPORTED_SIGNING_ALGORITHMS`, so a future signing algorithm will not widen
verification. The defaults are:

- **Manual mode.** `TokenValidationConfig(perform_disco=False, key=...)` with
  `algorithms=None` no longer raises `ConfigurationException`. The token's
  header `alg` must be in `DEFAULT_ALLOWED_ALGORITHMS`, as in discovery mode;
  an HMAC token is refused (`"Algorithm 'HS256' is not in the allowed
  algorithms"`). The error for a missing key is now
  `"TokenValidationConfig.key is required if perform_disco is False"`.
  `algorithms=[]` raises `ConfigurationException`. A key that declares `alg`
  verifies only tokens with that header `alg`; any other raises
  `KeyAlgorithmMismatchException`, as in discovery mode.
- **Key errors are typed.** A key that is malformed or does not fit the
  token's algorithm raises `TokenValidationException("Key cannot verify the
  token", token_part="header")`, with PyJWT's `InvalidKeyError` or
  `PyJWKError` chained as `__cause__`. In 4.x the raw PyJWT exception
  escaped, so an `except jwt.InvalidKeyError` handler no longer matches.
- **DPoP proofs and signed introspection (new in 5.0).**
  `DPoPVerificationOptions(algorithms=None)` and
  `SignedIntrospectionOptions(algorithms=None)` accept the verify set (for
  signed introspection in discovery mode, the part of it the server
  advertises; see [#1067](#signed-introspection-gets-its-keys-from-discovery-1067)),
  so a plain RS256 authorization server works for signed introspection, and
  `DPoPVerificationOptions(replay_cache=...).accepted_algorithms` (the `algs` of a
  `WWW-Authenticate: DPoP` challenge) lists all ten. Neither defaults to the
  FAPI 2.0 set: a FAPI 2.0 deployment passes
  `algorithms=FAPI2_ALLOWED_SIGNING_ALGORITHMS`.
- **JARM.** With no `algorithms`, a response must use an algorithm the
  authorization server advertises in `authorization_signing_alg_values_supported`
  that is also in `DEFAULT_ALLOWED_ALGORITHMS`. If the server advertises none,
  `DEFAULT_ALLOWED_ALGORITHMS` applies instead of raising
  `JarmValidationException`.

```python
from py_identity_model import (
    DPoPVerificationOptions,
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    InMemoryDPoPReplayCache,
    SignedIntrospectionOptions,
)

dpop = DPoPVerificationOptions(
    algorithms=FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    replay_cache=InMemoryDPoPReplayCache(),
)
signed = SignedIntrospectionOptions(
    issuer=issuer, jwks=jwks, algorithms=FAPI2_ALLOWED_SIGNING_ALGORITHMS
)
```

### Weak RSA and EC verification keys are rejected ([#952](https://github.com/jamescrowley321/identity-model/issues/952))

5.0 refuses to verify a token with an RSA key under 2048 bits
([RFC 7518 §3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3)) or an EC
key under 224 bits
([FAPI 2.0 Security Profile §5.4.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1)).
This applies in discovery and manual mode and to JARM responses, whatever the
`algorithms` setting. The new `WeakKeyException` (a `TokenValidationException`)
is raised when the key chosen for the token is too weak. Other keys in the
JWK Set are unaffected, and the JWK Set is not refreshed. OKP (Ed25519) keys
have no floor. A provider still signing with a 1024-bit RSA key must rotate
it. Its tokens fail validation until it does.

```python
from py_identity_model import validate_token, WeakKeyException

try:
    claims = validate_token(token, validation_config, DISCOVERY_URL)
except WeakKeyException as exc:
    print(exc.details["kid"], exc.details["bits"], exc.details["min_bits"])
```

### `options` cannot disable a configured audience or issuer check ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

`TokenValidationConfig.options` is passed to PyJWT. In 4.x,
`options={"verify_aud": False}` or `{"verify_iss": False}` silently turned off
the check for a configured `audience` or `issuer`. Now `verify_aud=False`
raises `ConfigurationException` when an `audience` is set, and
`verify_iss=False` raises it when an issuer is set or comes from discovery.
`require` must be a list of claim names. With no audience configured,
`verify_aud=False` is still accepted.

Before:

```python
TokenValidationConfig(perform_disco=True, audience="api", options={"verify_aud": False})
```

After, either check the audience:

```python
TokenValidationConfig(perform_disco=True, audience="api")
```

or configure none:

```python
TokenValidationConfig(perform_disco=True, options={"verify_aud": False})
```

### Every algorithm in an explicit list is usable ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

RFC 8725 §3.1 lets the caller specify a set of algorithms. In 4.x a manual key
without `alg` was bound to the first entry of `algorithms`, so with
`algorithms=["RS256", "PS256"]` a valid PS256 token was rejected. The key is
now bound to the token's header `alg` when that is in the list, and the key
type must fit it.

A key that declares `alg` is used only with that algorithm (RFC 7517 §4.4,
RFC 8725 §3.1). In 4.x an explicit `algorithms` list overrode it; now a token
signed with another listed algorithm raises `KeyAlgorithmMismatchException`.

### Short HMAC keys are rejected ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

RFC 7518 §3.2 requires an HMAC key at least as long as the hash output. When
you allow an HS* algorithm, a verification key (`kty: "oct"`) under 256, 384
or 512 bits for HS256, HS384 or HS512 raises `WeakKeyException`. In 4.x PyJWT
only warned. Use a longer secret.

## UserInfo

### A UserInfo response without `sub` is an error ([#884](https://github.com/jamescrowley321/identity-model/pull/884))

Every UserInfo response must carry `sub` (OIDC Core §5.3.2). `get_userinfo`
returns an unsuccessful `UserInfoResponse` when the JSON body has no
non-empty string `sub`, whether or not you pass `expected_sub`. In 4.x this
was checked only when `expected_sub` was set.

```python
from py_identity_model import get_userinfo, UserInfoRequest

response = get_userinfo(UserInfoRequest(address=USERINFO_URL, token=access_token))
if not response.is_successful:
    print(response.error)  # 5.0: also when the body has no sub
```

The failed response's `error_kind` is `UserInfoErrorKind.MISSING_SUB`, so you
can tell a missing `sub` from a failed request:

```python
from py_identity_model import UserInfoErrorKind

if response.error_kind is UserInfoErrorKind.MISSING_SUB:
    ...  # the provider answered, but without sub
```

The FastAPI relying-party router fails the login with `401` ("UserInfo
response has no subject") when the UserInfo response has no `sub`. Other
UserInfo failures are still logged and the login continues on the ID Token.

### `expected_sub` is enforced on signed UserInfo ([#882](https://github.com/jamescrowley321/identity-model/pull/882))

With `expected_sub` set, a signed or encrypted (`application/jwt`) UserInfo
response is now an error. The UserInfo call has no keys to verify the JWT,
and comparing the `sub` of an unverified JWT would prove nothing (OIDC Core
§5.3.4). In 4.x it was returned as successful without checking `sub`.

Before:

```python
response = get_userinfo(
    UserInfoRequest(address=USERINFO_URL, token=access_token, expected_sub=id_token_sub)
)
jwt = response.raw  # sub was never compared
```

`expected_sub` still checks a JSON UserInfo response. For a provider that
returns signed UserInfo, omit `expected_sub`, verify the JWT yourself, and
compare `sub` for both response formats:

```python
response = get_userinfo(UserInfoRequest(address=USERINFO_URL, token=access_token))
if not response.is_successful:
    raise ValueError(response.error)
if response.raw is not None:  # application/jwt: verify before reading claims
    claims = validate_token(response.raw, validation_config, DISCOVERY_URL)
else:  # JSON
    claims = response.claims
if claims.get("sub") != id_token_sub:
    raise ValueError("UserInfo sub does not match the ID Token")
```

## Back-Channel Logout

### Logout Tokens require `exp` ([#875](https://github.com/jamescrowley321/identity-model/pull/875))

Back-Channel Logout 1.0 (errata set 1, §2.4) makes `exp` REQUIRED.
`validate_logout_token` (sync and async) raises
`LogoutTokenValidationException` for a Logout Token without `exp`. In 4.x a
validly signed token without `exp` was accepted. No code change is needed
unless your provider omits `exp`.

```python
from py_identity_model import LogoutTokenValidationException, validate_logout_token

try:
    claims = validate_logout_token(logout_token, validation_config, DISCOVERY_URL)
except LogoutTokenValidationException:
    ...  # 5.0: also raised when exp is missing
```

### Logout Tokens with an untrusted audience are rejected ([#PRNUM](https://github.com/jamescrowley321/identity-model/pull/PRNUM))

Back-Channel Logout 1.0 §2.6 step 4 validates `aud` as for ID Tokens, so
`validate_logout_token` (sync and async) now rejects a Logout Token whose
`aud` holds any value other than your `client_id` (OIDC Core §3.1.3.7 step 3).
The error is `LogoutTokenValidationException` with the rejected values in
`details["untrusted_audiences"]`. List other audiences you trust in the new
`trusted_audiences=` argument. `validate_logout_token_claims` takes a required
keyword `client_id` and an optional `trusted_audiences`.

```python
claims = validate_logout_token(
    logout_token,
    validation_config,
    DISCOVERY_URL,
    trusted_audiences=["https://partner.example.com"],
)
```

With `perform_disco=False`, `validate_logout_token` also requires an issuer;
see [Without discovery, an issuer is required](#without-discovery-an-issuer-is-required).

## Go and Rust

The Go module and the Rust crate are versioned separately and get the same ID
Token rules in their own major releases:

| Change | Go (`idtoken`) | Rust (`IdTokenValidationOptions::builder()`) |
|---|---|---|
| Trust additional audiences | `WithTrustedAudiences("https://api.example.com")` | `.trusted_audiences(["https://api.example.com"])` |
| Keep the `azp` rules | `WithAZPValidation()` | `.validate_azp(true)` |
| Token without `aud` | rejected (`missing_aud`) | rejected (`IdentityError::IdTokenValidation`) |
| `azp` rules without a client id | `ErrAZPRequiresClientID` | `IdentityError::IdTokenAzpRequiresClientId` |

```go
claims, err := idtoken.ValidateIDToken(ctx, rawToken, keySet,
    idtoken.WithClientID(clientID),
    idtoken.WithTrustedAudiences("https://api.example.com"),
    idtoken.WithAZPValidation(),
)
```

```rust
let options = IdTokenValidationOptions::builder()
    .client_id(client_id)
    .trusted_audiences(["https://api.example.com"])
    .validate_azp(true)
    .build();
```

Signature key resolution also skips `use: "enc"` keys
([#888](https://github.com/jamescrowley321/identity-model/issues/888)), as in
Python. In Go, `jwks.JSONWebKeySet.ResolveSigningKey` (used by `jwt` and
`idtoken`) treats a `kid` that names only an `enc` key as a miss: one refresh,
then `*jwks.KeyNotFoundError`. A token with no `kid` against a set with no
signing key returns `*jwks.KeyNotFoundError` with an empty `Kid`.
`ResolveKey` and `ResolveKeyWithRefresh` are unchanged and still return any
key by `kid`.
In Rust, `JsonWebKeySet::resolve_signing_key` and
`JwksClient::resolve_signing_key` (used by `validate_token_with_jwks`) behave
the same and return `IdentityError::KeyNotFound`, with an empty `kid` for a
kid-less token. `find`, `resolve_key` and `JwksClient::resolve_key` are
unchanged.

Both also refuse weak verification keys
([#952](https://github.com/jamescrowley321/identity-model/issues/952)), as in
Python: an RSA key under 2048 bits or an EC key under 224 bits fails
validation without a JWK Set refresh. Go returns `*jwt.WeakKeyError`
(`errors.Is(err, jwt.ErrWeakKey)`), with the floors in `jwt.MinRSAKeyBits` and
`jwt.MinECKeyBits`. Rust returns `IdentityError::WeakKey { kid, kty, bits,
min_bits }`, with the floors in `MIN_RSA_KEY_BITS` and `MIN_EC_KEY_BITS`.
Their default algorithm allowlists now include `EdDSA`, and Ed25519 (`OKP`)
keys verify: in Go with `jwt.Validate` and `idtoken`, in Rust with
`validate_token` and `validate_token_with_jwks`. A caller that passes its own
allowlist is unaffected.
