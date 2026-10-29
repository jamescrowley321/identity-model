# Upgrading from 4.x to 5.0

py-identity-model 5.0 changes how the library is configured and enforces
several OpenID Connect rules that 4.x left to the caller. This page lists every
breaking change, with what to change in your code. fastapi-identity-model
releases a matching version that requires py-identity-model 5.

Most applications need three edits:

1. Build a `Config` and pass it on an `HTTPClient` / `AsyncHTTPClient`
   instead of setting `HTTP_TIMEOUT` and the other environment variables.
2. If you use the FastAPI package, replace `OIDCSettings.from_env()` with
   `oidc_settings_from_env()`.
3. Pass `trusted_audiences=` to `validate_id_token` if your provider issues
   ID Tokens with more than one audience.

The other changes reject provider responses and tokens that the OpenID
Connect specifications already forbid. A conforming provider is unaffected.

## Configuration

### `Config` is a plain typed value ([#892](https://github.com/jamescrowley321/identity-model/pull/892))

`Config.from_env`, `Config.build`, `ConfigSource`, `EnvSource`,
`MappingSource` and `Secret` are removed. Build a `Config` with keyword
arguments; each setting has a default, so `Config()` is complete. An invalid
value raises one `ConfigError` (a `ValueError`) listing every bad setting.

Before:

```python
from py_identity_model import Config

config = Config.build(overrides={"http.timeout": "10"})
```

After:

```python
from py_identity_model import Config

config = Config(http_timeout=10.0)
```

Also changed:

- `jwks_cache_max_entries` and `discovery_cache_max_entries` are replaced by
  one `cache_max_entries` (at least 1), applied to each cache.
- The client settings (`client_id`, `client_secret`, discovery URL, scope,
  audience, redirect URIs, excluded paths) are no longer on `Config`. For the
  FastAPI package they live on `OIDCSettings`.
- `ConfigIssue` carries `setting` and `message` instead of `code` and `keys`.

See [Configuration](api/config.md) for every setting and its range.

### The library reads no environment variables ([#895](https://github.com/jamescrowley321/identity-model/pull/895), [#893](https://github.com/jamescrowley321/identity-model/pull/893))

These variables are now ignored: `HTTP_TIMEOUT`, `HTTP_RETRY_MAX_ATTEMPTS`,
`HTTP_RETRY_COUNT`, `HTTP_RETRY_BASE_DELAY`, `MAX_JWKS_SIZE`,
`MAX_JWKS_KEYS`, `JWKS_CACHE_TTL`, `DISCO_CACHE_TTL`,
`KID_MISS_REFRESH_COOLDOWN`, `JWKS_CACHE_MAX_ENTRIES`, `SSL_CERT_FILE`,
`CURL_CA_BUNDLE` and `REQUESTS_CA_BUNDLE`. A `Config` takes effect only on a
client you pass as `http_client=`, or, for the cache settings, on a
`ValidationCache` you pass as `cache=` (see
[Caches live on a `ValidationCache`](#caches-live-on-a-validationcache-not-on-the-http-client-953)).
Without one, an entry point uses the library default client or cache, built
from `Config()`.

Before:

```python
# HTTP_TIMEOUT=10 and MAX_JWKS_KEYS=20 set in the environment
from py_identity_model import validate_token

claims = validate_token(token, validation_config, DISCO_URL)
```

After, building the `Config` in code:

```python
from py_identity_model import Config, HTTPClient, validate_token

with HTTPClient(config=Config(http_timeout=10.0, jwks_max_keys=20)) as client:
    claims = validate_token(token, validation_config, DISCO_URL, http_client=client)
```

After, keeping the same variables with the optional helper:

```python
from py_identity_model import HTTPClient
from py_identity_model.config_helpers import config_from_env

client = HTTPClient(config=config_from_env())
```

`config_from_env()` reads the variable names listed above (`JWKS_CACHE_MAX_ENTRIES`
sets `cache_max_entries`). `config_from_env(prefix="APP_")` reads
`APP_HTTP_TIMEOUT` and so on, and `config_from_mapping()` takes any mapping,
such as python-dotenv's `dotenv_values()`.

The async client works the same way:

```python
from py_identity_model import Config
from py_identity_model.aio import AsyncHTTPClient, validate_token

async with AsyncHTTPClient(config=Config(http_timeout=10.0)) as client:
    claims = await validate_token(token, validation_config, DISCO_URL, http_client=client)
```

Also changed:

- `HTTPClient` / `AsyncHTTPClient` no longer take `timeout=` or `verify=`.
  For `verify=False` (in a test) or a proxy, wrap your own httpx client:
  `HTTPClient(httpx.Client(verify=False), config=config)`. The wrapped client
  keeps its own timeout and TLS settings; the `Config` still sets retries
  and JWKS limits.
- `get_retry_config`, `get_timeout`, `get_max_jwks_size` and
  `get_max_jwks_keys` in `py_identity_model.core.http_utils` are removed.
  `py_identity_model.ssl_config.get_ssl_verify(config)` takes a `Config`.
- `get_max_cache_entries` and `get_kid_miss_cooldown` in
  `py_identity_model.core.jwks_cache` are removed; read
  `config.cache_max_entries` and `config.jwks_kid_miss_cooldown` instead.
  `resolve_ttl(cache_control, default_ttl)` and
  `resolve_disco_ttl(cache_control, default_ttl)` take the fallback TTL as a
  required argument.
- `build_mtls_client(mtls, config)` (sync and async) and
  `build_mtls_ssl_context(mtls, config)` take a required `Config`.
- `get_default_http_client()` and `get_default_async_http_client()` return the
  client that every call without `http_client=` uses, built from `Config()`.

httpx still honours `SSL_CERT_FILE`, `SSL_CERT_DIR` and the proxy variables
when it builds a client with its default `trust_env=True`. To turn that off,
wrap an `httpx.Client(trust_env=False)`.

### mTLS requests never go through a caller-owned client ([#895](https://github.com/jamescrowley321/identity-model/pull/895))

In 4.x a request with `mtls=` and an `http_client=` raised `ValueError`. In
5.0 the pair is accepted when `http_client` is built from a `Config`: the request goes through a short-lived client that
presents the certificate, built from your `http_client`'s `Config`
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
from py_identity_model import Config, HTTPClient

with HTTPClient(config=Config(ca_bundle="/etc/ssl/private-ca.pem")) as http_client:
    response = request_client_credentials_token(request, http_client=http_client)
```

This works only with an `HTTPClient` built from a `Config`. An `HTTPClient`
that wraps your own `httpx.Client` still raises `ValueError` when combined
with `mtls=`, because that client's TLS settings (a pinned CA, a proxy, a
custom transport) cannot be carried over to the certificate client. Set
`ca_bundle` on the `Config` instead. See [Mutual TLS](api/mtls.md).

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
  `Config` share them per `Config.ca_bundle`, and a client wrapping your own
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
  `cache_max_entries`, `jwks_kid_miss_cooldown`) are read from the cache's
  `Config`. On a client's `Config` they have no effect.
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
from py_identity_model import Config, ValidationCache, validate_token

cache = ValidationCache(config=Config(jwks_cache_ttl=900.0))  # once, at startup

claims = validate_token(token, validation_config, DISCO_URL, cache=cache)
```

The async validators take an `AsyncValidationCache`
(`from py_identity_model.aio import AsyncValidationCache`). Build a cache once
and keep it: a cache built per request starts empty and has no cooldown
history. In the FastAPI package, pass it as `cache=` to
`TokenValidationMiddleware` or `build_ws_authenticator`.

### The JWKS cache keeps keys for 1 hour, not 24 ([#953](https://github.com/jamescrowley321/identity-model/issues/953))

When the JWKS response has no `Cache-Control: max-age`, the key set is now
kept for 1 hour (`Config.jwks_cache_ttl` defaults to `3600`, was `86400`). A
key the provider pulls stops validating within the hour. A provider's
`max-age` still wins, clamped to 60 – 86400 seconds as before. A provider
without `max-age` sees up to one JWKS fetch per hour per process instead of
one per day.

To keep the 4.x lifetime:

```python
from py_identity_model import Config, ValidationCache

cache = ValidationCache(config=Config(jwks_cache_ttl=86400.0))
```

### `ClientAuthMethod.requires_secret` is removed ([#934](https://github.com/jamescrowley321/identity-model/issues/934))

The property had no reader in the library. `ClientAuthMethod` and its members
are unchanged. There is no replacement; compare against
`ClientAuthMethod.NONE` directly.

Before:

```python
if method.requires_secret:
    ...
```

After:

```python
from py_identity_model import ClientAuthMethod

if method is not ClientAuthMethod.NONE:
    ...
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

HTTP settings for the FastAPI package come from a py-identity-model `Config`
on an `AsyncHTTPClient`, passed as `http_client=` to
`TokenValidationMiddleware`, `build_oidc_router`, `build_ws_authenticator`
and `TokenManager`:

```python
from py_identity_model import Config
from py_identity_model.aio import AsyncHTTPClient

http_client = AsyncHTTPClient(config=Config(http_timeout=10.0))
app.include_router(build_oidc_router(settings, http_client=http_client), prefix="/auth")
```

fastapi-identity-model now requires `py-identity-model>=5.0.0,<6`.

### FastAPI: bound tokens are checked on every request ([#1021](https://github.com/jamescrowley321/identity-model/issues/1021))

`TokenValidationMiddleware` and `build_ws_authenticator` now check a token's
sender constraint (RFC 9449 §7.1, RFC 8705 §3). Unbound bearer tokens behave as
before.

- A DPoP-bound token (`cnf.jkt`) sent as `Bearer` is refused. Send it as
  `Authorization: DPoP <token>` with a `DPoP` proof for the request.
- A certificate-bound token (`cnf["x5t#S256"]`) is refused unless you pass
  `client_certificate=`, a callable that returns the request's client
  certificate:

```python
from urllib.parse import unquote


def client_certificate(request):
    # nginx: proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
    escaped = request.headers.get("X-Client-Cert")
    return unquote(escaped) if escaped else None


app.add_middleware(
    TokenValidationMiddleware,
    discovery_url=settings.discovery_url,
    audience=settings.audience,
    client_certificate=client_certificate,
)
```

  Read the certificate only from a header your TLS terminator sets and strips
  from client requests.

See [DPoP: FastAPI](api/dpop.md#fastapi) for `required_binding` and the
`DPoP` challenge.

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
| `pushed_authorization_request_endpoint` | absent | §5.3.2.2, RFC 9126 |
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
)
```

After, for a token with `"aud": [CLIENT_ID, "https://api.example.com"]`:

```python
claims = validate_id_token(
    id_token,
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
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
    validate_id_token_claims(claims, "RS256")  # accepted in 4.x
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
claims = validate_id_token(id_token, validation_config, disco_doc_address=DISCOVERY_URL)
```

After, keeping the 4.x behaviour:

```python
claims = validate_id_token(
    id_token, validation_config, disco_doc_address=DISCOVERY_URL, validate_azp=True
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
    id_token, config, disco_doc_address=DISCOVERY_URL, validate_azp=True
)
```

After:

```python
config = TokenValidationConfig(perform_disco=True, issuer=ISSUER, audience=CLIENT_ID)
claims = validate_id_token(
    id_token, config, disco_doc_address=DISCOVERY_URL, validate_azp=True
)
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

### `algorithms=None` allows only asymmetric algorithms ([#952](https://github.com/jamescrowley321/identity-model/issues/952))

In 4.x, a discovery-mode `TokenValidationConfig` with `algorithms=None` (the
default) accepted any algorithm that matched the resolved key, including
`HS256` with an `oct` key from the JWK Set. In 5.0, `None` means
`DEFAULT_ALLOWED_ALGORITHMS`: RS256/384/512, PS256/384/512, ES256/384/512 and
EdDSA, the same default as the Go and Rust libraries. A token signed with any
other algorithm raises `TokenValidationException`
(`"Algorithm 'HS256' is not in the allowed algorithms"`).

An explicit `algorithms` list works as before, and manual mode
(`perform_disco=False`) still requires one. To keep accepting an HMAC-signed
token, list its algorithm:

```python
config = TokenValidationConfig(
    perform_disco=True,
    audience="my-api",
    algorithms=["HS256"],
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
from py_identity_model import WeakKeyException, validate_token

try:
    claims = validate_token(token, validation_config, DISCOVERY_URL)
except WeakKeyException as exc:
    print(exc.details["kid"], exc.details["bits"], exc.details["min_bits"])
```

## UserInfo

### A UserInfo response without `sub` is an error ([#884](https://github.com/jamescrowley321/identity-model/pull/884))

Every UserInfo response must carry `sub` (OIDC Core §5.3.2). `get_userinfo`
returns an unsuccessful `UserInfoResponse` when the JSON body has no
non-empty string `sub`, whether or not you pass `expected_sub`. In 4.x this
was checked only when `expected_sub` was set.

```python
from py_identity_model import UserInfoRequest, get_userinfo

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
