# HTTP Client Management

Optional dependency injection for HTTP client lifecycle management.

All public I/O functions accept an optional `http_client` parameter. When it is
omitted, the library default client is used: one process-wide `HTTPClient` /
`AsyncHTTPClient` built from `Config()`, returned by
`get_default_http_client()` / `get_default_async_http_client()`. The sync
default client gives each thread its own `httpx.Client`.

Each client owns its discovery cache, JWKS cache and kid-miss cooldown, and
takes its timeout, retries, TLS and cache settings from a
[`Config`](config.md). Keep one long-lived client per configuration so the
caches are reused.

To use your own httpx client (for a proxy, or `verify=False` in a test), wrap
it: `HTTPClient(httpx.Client(verify=False), config=config)`. The wrapped client
keeps its own timeout and TLS settings; the `Config` still sets retries, JWKS
limits and the caches.

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
