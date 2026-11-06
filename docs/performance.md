# Performance Guide

This guide covers performance characteristics, caching behavior, and optimization strategies for py-identity-model.

## Overview

py-identity-model is designed for high performance with built-in caching and support for both synchronous and asynchronous I/O. Understanding these performance characteristics will help you optimize your application.

## Caching

### Discovery Document Caching

Discovery documents and JWKS are cached in-process to keep the steady-state
request path off the network. The cache is **not** `functools.lru_cache` /
`async_lru.alru_cache` — those were replaced (v3.0.0) with an explicit
**TTL + LRU** cache so entries expire on a schedule, key rotation is handled
automatically, and concurrent misses are coalesced into a single upstream
fetch. The cache *policy* lives in `core/jwks_cache.py`; the sync and async
cache stacks live in `sync/token_validation.py` and `aio/token_validation.py`.
The caches themselves belong to an HTTP client (`HTTPClient` /
`AsyncHTTPClient`): each client owns one discovery cache, one JWKS cache and
one kid-miss cooldown map, and its `Config` sets their TTLs, size and cooldown.

### What is cached

| Cache | Cache key | Backing store | Default TTL | `Config` setting |
|-------|-----------|---------------|-------------|------------------|
| Discovery document | `(address, policy.cache_key())` | `OrderedDict` | 3600s (1 hour) | `discovery_cache_ttl` |
| JWKS | `jwks_uri` | `OrderedDict` | 86400s (24 hours) | `jwks_cache_ttl` |

Both caches share the same policy machinery:

- **LRU eviction, 64 entries** by default (`Config.cache_max_entries`, applied
  to each cache separately). The store is an
  `OrderedDict`, not a plain dict, so a *read hit* refreshes recency
  (`touch_cache_entry`) and eviction targets the least-recently-**used** entry.
- **TTL resolution order.** For each entry the TTL is the first available of:
  (1) the response's `Cache-Control: max-age`, clamped to **[60s, 86400s]**
  (`MIN_CACHE_TTL_SECONDS` … `MAX_CACHE_TTL_SECONDS`), (2) the client's
  `Config` TTL. An out-of-range `Config` value is rejected when the `Config`
  is built.
- **Single-flight fetch.** Per-URI striped locks (32 stripes) ensure a cache
  miss issues exactly one upstream fetch; concurrent requests for the same URI
  wait on the stripe and then read the freshly-cached entry (a
  *double-checked* hit) rather than each hitting the network.
- **Kid-miss cooldown.** If a JWT's `kid` is absent from the cached JWKS the
  cache is treated as stale and a refresh is forced (OP key rotation). This is
  rate-limited per-URI — default 5s (`Config.jwks_kid_miss_cooldown`) — so an attacker forging tokens with
  random unknown kids cannot amplify inbound traffic into upstream JWKS fetches.
- **Per-event-loop locks (async).** The async write/fetch locks are keyed on
  the running event loop via `WeakKeyDictionary` (#399), so a test runner or
  embed that creates a new loop per scope does not hit
  `RuntimeError: <Lock> is bound to a different event loop`.

**Important:** caches are per client. Two clients (including a sync and an
async one) do not share cached data, so keep one long-lived client per
configuration. Entry points called without `http_client=` use the library
default client, built from `Config()`; its caches are shared by the process.

### Clearing Caches

Use the public cache-clear helpers. **Breaking change (v3.0.0):** the async
helpers are now `async def` — they acquire the cache write lock before
clearing so a fetch in flight can't write its result back into a "cleared"
cache — so callers must `await` them.

```python
# Sync
from py_identity_model import clear_discovery_cache, clear_jwks_cache

clear_discovery_cache()  # the library default client's caches
clear_jwks_cache()
clear_jwks_cache(http_client=client)  # one injected client's caches
```

```python
# Async — must be awaited
from py_identity_model.aio import clear_discovery_cache, clear_jwks_cache

await clear_discovery_cache()
await clear_jwks_cache()
```

There is no `_get_disco_response.cache_clear()` / `.cache_info()` — those are
`functools.lru_cache` APIs and the cache no longer uses `lru_cache`.

### Observing Cache Hit Rate

The cache exposes lightweight per-process counters via
`core/cache_metrics.py`, re-exported at the top level. Read a `snapshot()` and
compute whatever rate you need:

```python
from py_identity_model import get_cache_counters

snap = get_cache_counters().snapshot()
# {'disco_hits': ..., 'disco_misses': ..., 'jwks_hits': ...,
#  'jwks_misses': ..., 'jwks_refreshes': ...}

jwks_total = snap["jwks_hits"] + snap["jwks_misses"]
jwks_hit_rate = snap["jwks_hits"] / jwks_total if jwks_total else 0.0
```

Semantics:

- **hit** — request served from a fresh cached entry (no upstream call);
  **miss** — request that had to fetch from upstream;
  **refresh** — a *forced* upstream JWKS re-fetch (kid-miss or
  signature-failure key-rotation recovery). A refresh that coalesces onto
  another coroutine's in-flight fetch does no upstream work and is not counted.
- Counters currently cover the **async** cache paths
  (`_get_disco_response` / `_get_cached_jwks` / `_refresh_jwks`). The sync
  stack uses the same TTL/LRU structure but is not yet instrumented.
- Counters are **per-process**. Under `uvicorn --workers N` each worker keeps
  its own tally — aggregate snapshots across workers for a fleet-wide rate.
- The injected-`http_client` path bypasses the caches entirely and is
  deliberately **not** counted (it performs no caching, so a hit rate over it
  would be meaningless).
- `get_cache_counters().reset()` zeros every counter — useful for per-run
  baselines and tests.

## Performance Benchmarks

> **These figures are illustrative, order-of-magnitude examples from a developer
> machine — not measured SLOs or gate thresholds.** The authoritative measured
> numbers come from the load/soak harness (`src/tests/load/`), which uploads
> per-scenario RPS / latency / cache reports as CI artifacts. Those numbers are
> **directional**: the harness runs co-located (load generator, mock OP, and
> resource server share one runner), so absolute latency/RPS reflect that shared
> box, not an isolated deployment. Absolute values become trustworthy gates only on
> an isolated runner (see `src/tests/load/README.md`, Track C). Treat the tables
> below as "what good looks like," not as numbers to assert against.

### Token Validation Performance

Typical token validation times (with caching):

| Operation | First Call | Cached Call | Notes |
|-----------|-----------|-------------|-------|
| Discovery Document | ~500-1000ms | <1ms | Network latency dependent |
| JWKS Fetch | ~500-1000ms | <1ms | Network latency dependent |
| JWT Decode & Verify | ~1-5ms | ~1-5ms | No caching (always validates) |
| **Total (First)** | **~1-2s** | - | First request is slow |
| **Total (Cached)** | - | **~1-5ms** | Subsequent requests are fast |

**Key Insight:** The first token validation is slow due to network requests. Subsequent validations are very fast due to caching.

### Sync vs Async Performance

#### Single Operation

For a single token validation, sync and async have similar performance:

```python
import time

# Sync (second request, cached)
start = time.time()
claims = validate_token(token, config, disco_address)
print(f"Sync: {(time.time() - start) * 1000:.2f}ms")
# Output: Sync: 1.5ms

# Async (second request, cached)
start = time.time()
claims = await validate_token(token, config, disco_address)
print(f"Async: {(time.time() - start) * 1000:.2f}ms")
# Output: Async: 1.8ms
```

**Conclusion:** For single operations, sync and async have nearly identical performance.

#### Concurrent Operations

For multiple concurrent operations, async can be significantly faster:

```python
import asyncio
import time

tokens = [token1, token2, token3, token4, token5]

# Sequential sync validation
start = time.time()
for token in tokens:
    claims = validate_token(token, config, disco_address)
elapsed_sync = time.time() - start
print(f"Sync Sequential: {elapsed_sync * 1000:.0f}ms")
# Output: Sync Sequential: 7.5ms (5 tokens × 1.5ms each)

# Concurrent async validation
start = time.time()
results = await asyncio.gather(
    *[validate_token(token, config, disco_address) for token in tokens]
)
elapsed_async = time.time() - start
print(f"Async Concurrent: {elapsed_async * 1000:.0f}ms")
# Output: Async Concurrent: 2.0ms (overhead + max(all validations))

print(f"Speedup: {elapsed_sync / elapsed_async:.1f}x")
# Output: Speedup: 3.7x
```

**Conclusion:** Async provides significant performance benefits when processing multiple operations concurrently.

## Optimization Strategies

### 1. Minimize Discovery Calls

Discovery documents rarely change. Call once and cache:

**Bad:**
```python
def validate_every_request(token: str):
    # This fetches discovery doc every time!
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = get_discovery_document(disco_request)

    # Then validates token...
```

**Good:**
```python
# Discovery is cached automatically when using perform_disco=True
def validate_every_request(token: str):
    config = TokenValidationConfig(
        perform_disco=True,  # Uses cached discovery
        audience="api",
    )
    claims = validate_token(token, config, DISCO_ADDRESS)
    return claims
```

**Best:**
```python
# For ultimate performance, use validate_token with perform_disco=True
# This handles all caching automatically
config = TokenValidationConfig(perform_disco=True, audience="api")

def validate_request(token: str):
    return validate_token(token, config, DISCO_ADDRESS)
```

### 2. Use Async for Concurrent Operations

If you need to validate multiple tokens or make multiple requests:

**Slow (Sequential):**
```python
results = []
for token in tokens:
    claims = validate_token(token, config, disco_address)
    results.append(claims)
```

**Fast (Concurrent):**
```python
results = await asyncio.gather(
    *[validate_token(token, config, disco_address) for token in tokens],
    return_exceptions=True  # Don't fail entire batch on single error
)
```

### 3. HTTP Client Management & Connection Pooling

The library uses different HTTP client strategies for sync and async to optimize performance and thread safety.

#### Synchronous API: Thread-Local Clients

The library default sync client is one process-wide `HTTPClient` built from
`Config()`, so its caches are shared, but each thread gets its own
`httpx.Client` (via `threading.local()`), built on first use from the
client's `Config`.

**Benefits:**
- ✅ **No global state**: Eliminates race conditions
- ✅ **Thread isolation**: Each thread has its own connection pool
- ✅ **No locks needed**: Thread-local access is lock-free
- ✅ **Automatic cleanup**: Each thread manages its own client lifecycle

**Connection Pool per Thread:**
- Max Connections: 100 (httpx default)
- Max Keepalive: 20 connections (httpx default)
- Timeout: 30 seconds (py-identity-model default)

**Memory Trade-off:**
- 10 threads = 10 clients (one per thread)
- Each client has its own connection pool
- Acceptable trade-off for thread safety

#### Asynchronous API: Singleton Client

All async operations without `http_client=` share the library default
`AsyncHTTPClient`, whose `httpx.AsyncClient` is created once under a lock.

**Benefits:**
- ✅ **Shared connection pool**: All async operations share connections
- ✅ **Memory efficient**: Single client for all async operations
- ✅ **No I/O locks**: Lock only used during initialization
- ✅ **Optimal for async**: Matches async/await concurrency model

**Shared Connection Pool:**
- Max Connections: 100 (shared across all async operations)
- Max Keepalive: 20 connections (shared)
- Timeout: 30 seconds

#### Performance Comparison

| Aspect | Sync (Thread-Local) | Async (Singleton) |
|--------|---------------------|-------------------|
| Clients Created | One per thread | One per process |
| Connection Pool | Per-thread | Shared process-wide |
| Memory Usage | Higher (multiple clients) | Lower (single client) |
| Lock Contention | None (thread-local) | None (during I/O) |
| Best For | Multi-threaded apps | Async/await apps |

#### Advanced: Custom Connection Limits

For high-throughput applications, you may want to customize connection limits.

Wrap your own `httpx` client and pass it on every call. Its limits, timeout
and TLS settings apply; the `Config` sets retries, JWKS limits and caching:

```python
import httpx

from py_identity_model import Config
from py_identity_model.aio import AsyncHTTPClient, validate_token

client = AsyncHTTPClient(
    httpx.AsyncClient(
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        timeout=60.0,
        follow_redirects=False,
    ),
    config=Config(cache_max_entries=128),
)

claims = await validate_token(token, validation_config, disco_url, http_client=client)
```

To change only the timeout, `AsyncHTTPClient(config=Config(http_timeout=60.0))`
is enough.

### 4. Batch Token Validations

For batch processing, use async with controlled concurrency:

```python
import asyncio
from itertools import islice

async def validate_tokens_batched(tokens: list[str], batch_size: int = 50):
    """Validate tokens in batches to avoid overwhelming the system."""
    results = []

    # Process in batches
    for i in range(0, len(tokens), batch_size):
        batch = tokens[i:i + batch_size]

        batch_results = await asyncio.gather(
            *[validate_token(token, config, disco_address) for token in batch],
            return_exceptions=True
        )

        results.extend(batch_results)

        # Optional: add delay between batches
        if i + batch_size < len(tokens):
            await asyncio.sleep(0.1)

    return results
```

### 5. Warm Up the Cache

For production applications, warm up caches on startup:

```python
async def warmup_cache():
    """Warm up discovery document and JWKS caches on startup."""
    from py_identity_model.aio import get_discovery_document
    from py_identity_model import DiscoveryDocumentRequest

    disco_response = await get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )

    if disco_response.is_successful:
        # JWKS will be cached on first token validation
        print("✓ Cache warmed up")
    else:
        print("✗ Cache warmup failed")

# In FastAPI
@app.on_event("startup")
async def startup_event():
    await warmup_cache()
```

## Production Recommendations

### FastAPI / Async Frameworks

```python
from fastapi import FastAPI, Depends, HTTPException
from py_identity_model import TokenValidationConfig
from py_identity_model.aio import validate_token

app = FastAPI()

# Create config once
TOKEN_CONFIG = TokenValidationConfig(
    perform_disco=True,
    audience="api",
    options={
        "verify_signature": True,
        "verify_aud": True,
        "verify_exp": True,
        "verify_iss": True,
    },
)

# Warm up cache on startup
@app.on_event("startup")
async def startup():
    from py_identity_model.aio import get_discovery_document
    from py_identity_model import DiscoveryDocumentRequest

    disco = await get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )
    if disco.is_successful:
        print("✓ Discovery cache warmed")

# Use in dependency
async def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        claims = await validate_token(
            jwt=token,
            token_validation_config=TOKEN_CONFIG,
            disco_doc_address=DISCO_ADDRESS,
        )
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.get("/api/data")
async def protected_route(claims: dict = Depends(verify_token)):
    return {"data": "protected", "user": claims["sub"]}
```

### Flask / Sync Frameworks

```python
from flask import Flask, request, jsonify
from py_identity_model import TokenValidationConfig, validate_token

app = Flask(__name__)

# Create config once
TOKEN_CONFIG = TokenValidationConfig(
    perform_disco=True,
    audience="api",
)

# Warm up cache on first request
@app.before_first_request
def warmup():
    from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    )
    if disco.is_successful:
        print("✓ Discovery cache warmed")

def verify_token():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")

    try:
        claims = validate_token(
            jwt=token,
            token_validation_config=TOKEN_CONFIG,
            disco_doc_address=DISCO_ADDRESS,
        )
        return claims
    except Exception as e:
        return None

@app.route("/api/data")
def protected_route():
    claims = verify_token()
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"data": "protected", "user": claims["sub"]})
```

## Monitoring and Metrics

### Cache Hit Rate

Monitor cache performance in production:

```python
import logging
from py_identity_model import get_cache_counters

logger = logging.getLogger(__name__)

def log_cache_stats():
    """Log cache statistics periodically."""
    snap = get_cache_counters().snapshot()

    disco_total = snap["disco_hits"] + snap["disco_misses"]
    disco_rate = (snap["disco_hits"] / disco_total * 100) if disco_total else 0
    jwks_total = snap["jwks_hits"] + snap["jwks_misses"]
    jwks_rate = (snap["jwks_hits"] / jwks_total * 100) if jwks_total else 0

    logger.info(
        f"Discovery cache: {snap['disco_hits']} hits, "
        f"{snap['disco_misses']} misses, {disco_rate:.1f}% hit rate | "
        f"JWKS cache: {snap['jwks_hits']} hits, {snap['jwks_misses']} misses, "
        f"{snap['jwks_refreshes']} refreshes, {jwks_rate:.1f}% hit rate"
    )

# Log every 1000 requests or periodically. Counters are per-process — aggregate
# across workers for a fleet-wide rate.
```

### Performance Metrics

Track key metrics:

- **Token validation time** (p50, p95, p99)
- **Discovery cache hit rate**
- **JWKS cache hit rate**
- **Validation failures** (expired, invalid signature, etc.)
- **Network errors** (discovery/JWKS fetch failures)

Example with Prometheus:

```python
from prometheus_client import Counter, Histogram
import time

validation_duration = Histogram(
    'token_validation_duration_seconds',
    'Token validation duration'
)

validation_total = Counter(
    'token_validation_total',
    'Total token validations',
    ['result']  # success, expired, invalid, etc.
)

async def validate_with_metrics(token: str):
    start = time.time()

    try:
        claims = await validate_token(token, config, disco_address)
        validation_total.labels(result='success').inc()
        return claims
    except TokenExpiredException:
        validation_total.labels(result='expired').inc()
        raise
    except Exception:
        validation_total.labels(result='error').inc()
        raise
    finally:
        validation_duration.observe(time.time() - start)
```

## Summary

**Best Practices:**

1. ✅ Use `perform_disco=True` to enable automatic caching
2. ✅ Use async API for FastAPI and high-concurrency applications
3. ✅ Warm up caches on application startup
4. ✅ Monitor cache hit rates in production
5. ✅ Use connection pooling (automatic with httpx)
6. ✅ Batch concurrent operations with controlled concurrency
7. ✅ Track validation metrics (duration, failures, etc.)

**Performance Expectations:**

- **First validation**: ~1-2 seconds (network requests)
- **Cached validations**: ~1-5ms (very fast)
- **Async concurrency**: Up to 5-10x faster for batch operations
- **Cache hit rate**: Should be >95% in steady state

**When to Use Async:**

- FastAPI, Starlette, or other async frameworks
- High concurrency requirements (100+ req/s)
- Batch token processing
- Already using asyncio

**When Sync Is Fine:**

- Flask, Django, or other sync frameworks
- Low concurrency (<100 req/s)
- Simple CLI tools or scripts
- Single token validations
