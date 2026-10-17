# HTTP Client Management

Optional dependency injection for HTTP client lifecycle management.

All public I/O functions accept an optional `http_client` parameter. When it is
omitted, the library default client is used: one process-wide `HTTPClient` /
`AsyncHTTPClient` built from `Config()`, returned by
`get_default_http_client()` / `get_default_async_http_client()`. The sync
default client gives each thread its own `httpx.Client`.

A client only sends requests. It takes its timeout, retries, TLS and JWKS
size limits from a [`Config`](config.md) and holds no cache: the discovery
documents, keys and kid-miss cooldown used by token validation live on a
[validation cache](#validation-cache). A client built per request therefore
still shares the cached keys and the cooldown.

To use your own httpx client (for a proxy, or `verify=False` in a test), wrap
it: `HTTPClient(httpx.Client(verify=False), config=config)`. The wrapped client
keeps its own timeout and TLS settings; the `Config` still sets retries and
JWKS limits.

The library default clients are rebuilt in a forked child, so a pre-fork
server's workers never share connections. `close_async_http_client()` can be
called from any event loop.

## Sync Client

```python
from py_identity_model import Config, DiscoveryDocumentRequest, HTTPClient, get_discovery_document

with HTTPClient(config=Config(http_timeout=10.0)) as client:
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address="https://..."),
        http_client=client,
    )
```

::: py_identity_model.sync.managed_client.HTTPClient

## Async Client

```python
from py_identity_model import Config, DiscoveryDocumentRequest
from py_identity_model.aio import AsyncHTTPClient, get_discovery_document

async with AsyncHTTPClient(config=Config(http_timeout=10.0)) as client:
    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address="https://..."),
        http_client=client,
    )
```

::: py_identity_model.aio.managed_client.AsyncHTTPClient

## Validation Cache

`validate_token`, `validate_id_token` and `validate_logout_token` keep the
discovery document, the JWKS and the kid-miss cooldown on a `ValidationCache`
(async: `AsyncValidationCache`). Without `cache=`, they use the process-wide
default, `get_default_validation_cache()` /
`get_default_async_validation_cache()`, built from `Config()`. Pass your own to
set the cache TTLs, size or cooldown, or to keep one provider's keys apart
from the rest of the process:

```python
from py_identity_model import Config, HTTPClient, ValidationCache, validate_token

cache = ValidationCache(config=Config(jwks_cache_ttl=900.0, cache_max_entries=8))

with HTTPClient(config=Config(http_timeout=10.0)) as client:
    claims = validate_token(
        token, validation_config, DISCO_URL, http_client=client, cache=cache
    )
```

The cache reads `jwks_cache_ttl`, `discovery_cache_ttl`, `cache_max_entries`
and `jwks_kid_miss_cooldown` from its `Config`. The client reads the other
settings. One `Config` can be passed to both.

Build a cache once and keep it: a cache built per request starts empty and
has no cooldown history. The default cache is rebuilt in a forked child; a
cache you build yourself is not, so build it after the fork. One
`AsyncValidationCache` can serve several event loops: its locks are per loop.

`clear_discovery_cache(cache=None)` and `clear_jwks_cache(cache=None)` empty a
cache (the default one when `cache` is omitted; await the async versions).

::: py_identity_model.sync.validation_cache.ValidationCache

::: py_identity_model.sync.validation_cache.get_default_validation_cache

::: py_identity_model.aio.validation_cache.AsyncValidationCache

::: py_identity_model.aio.validation_cache.get_default_async_validation_cache
