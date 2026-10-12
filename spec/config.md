# identity-model — Configuration

The settings every identity-model library has, with their defaults, valid
ranges and cache rules. Python defines them; Go and Rust match this page.

## The library does not read the environment

No library code reads environment variables, files or any other source.
Settings take effect only when the caller passes them in: a `Config` on an
HTTP client in Python, options in Go, client builder methods in Rust.

Python's `py_identity_model.config_helpers` module (`config_from_env`,
`config_from_mapping`) converts string settings into a `Config`. It is optional:
the library never imports or calls it, so it runs only when a caller calls it.

## Settings

| Python | Go option | Rust builder method | Unit | Default | Valid |
|---|---|---|---|---|---|
| `http_timeout` | `WithTimeout` | `timeout` | seconds | `30` | `> 0` |
| `http_retry_max_attempts` | `WithRetryMaxAttempts` | `retry_max_attempts` | count | `3` | `≥ 0` |
| `http_retry_base_delay` | `WithRetryBaseDelay` | `retry_base_delay` | seconds | `1` | `≥ 0` |
| `ca_bundle` | `WithCABundle` | `ca_bundle` | path | `none` | `readable file` |
| `jwks_max_size` | `jwks.WithMaxSize` | `JwksClientBuilder::max_size` | bytes | `524288` | `≥ 1` |
| `jwks_max_keys` | `jwks.WithMaxKeys` | `JwksClientBuilder::max_keys` | count | `100` | `≥ 1` |
| `jwks_cache_ttl` | `jwks.WithCacheTTL` | `JwksClientBuilder::cache_ttl` | seconds | `86400` | `60 – 86400` |
| `jwks_kid_miss_cooldown` | `jwks.WithRefreshCooldown` | `JwksClientBuilder::refresh_cooldown` | seconds | `5` | `0 – 3600` |
| `discovery_cache_ttl` | `discovery.WithCacheTTL` | `DiscoveryClientBuilder::cache_ttl` | seconds | `3600` | `60 – 86400` |
| `cache_max_entries` | `discovery.WithMaxCacheEntries`, `jwks.WithMaxCacheEntries` | `DiscoveryClientBuilder::max_cache_entries`, `JwksClientBuilder::max_cache_entries` | count | `64` | `≥ 1` |

Ranges are inclusive unless written `>`.

- **`http_timeout`, retries and `ca_bundle`** apply to every request the library
  makes. In Go and Rust they are options on every package or client that makes
  HTTP requests.
- **`http_retry_max_attempts`**: `0` disables retries. Redeeming an
  authorization code is never retried, whatever this says: the code is
  single-use (RFC 6749 §4.1.2), and a retry after a lost response would present
  a used code. Go follows this; Python still retries it (#900).
- **`http_retry_base_delay`**: exponential backoff from this base; each retry's
  delay is capped at 120 seconds.
- **`ca_bundle`**: `none` verifies TLS with the HTTP stack's default CA bundle
  (httpx: certifi). TLS verification is always on.
- **`jwks_cache_ttl`, `discovery_cache_ttl`**: used only when the response has
  no `Cache-Control: max-age` (see [Cache rules](#cache-rules)).
- **`jwks_kid_miss_cooldown`**: the minimum time between JWKS refreshes
  triggered by an unknown `kid`. `0` disables the cooldown.
- **`cache_max_entries`**: one setting, applied separately to the JWKS cache
  and the discovery cache.
- **Types**: Python takes seconds as `float`; Go takes `time.Duration`; Rust
  takes `std::time::Duration`. Counts and sizes are integers.

An invalid value is rejected when the `Config` (Go: the client; Rust: the
builder's `build()`) is created. It is never replaced by its default. Errors
name the setting and the rule, never the value.

## Cache rules

- **Discovery:** the response's `Cache-Control: max-age` sets the lifetime,
  clamped to 60 – 86400 seconds. `no-store` or `no-cache` means the document is
  not cached. With no `max-age`, `discovery_cache_ttl` applies.
- **JWKS:** `max-age` sets the lifetime, with the same clamp. `no-store` and
  `no-cache` are deliberately ignored, because honouring them on key sets turns
  every validation into a fetch
  ([#396](https://github.com/jamescrowley321/identity-model/issues/396)). With
  no `max-age`, `jwks_cache_ttl` applies.
- **Size:** the JWKS cache and the discovery cache are each LRU and each hold at
  most `cache_max_entries` providers. There is no unbounded setting.

## Cache ownership

A cache belongs to the client that holds the settings, so every cache has
exactly one set of settings. Two clients don't share cached documents.

- **Python:** `HTTPClient` and `AsyncHTTPClient` take `config=` and own the
  discovery cache, the JWKS cache and the kid-miss cooldown. Every entry point
  takes `http_client=`; without one it uses the library default client, built
  from `Config()`.
- **Go:** the `discovery` and `jwks` packages each have a client that holds its
  options and owns its cache. Package-level functions use a default client
  built from the defaults.
- **Rust:** `DiscoveryClient` and `JwksClient` own their caches.

Client settings for login flows (discovery URL, client ID and secret, scope,
redirect URIs) are not library settings. The FastAPI package keeps them on
`OIDCSettings`.
