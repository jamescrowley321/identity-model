# identity-model — Configuration

The settings every identity-model library has, with their defaults, valid
ranges and cache rules. Python defines them. Go and Rust are being brought to
match ([#757](https://github.com/jamescrowley321/identity-model/issues/757),
[#758](https://github.com/jamescrowley321/identity-model/issues/758)); until
then they differ as listed in [Go and Rust today](#go-and-rust-today).

## The Python library does not read the environment

The Python library reads no environment variables, files or any other source.
Settings take effect only when the caller passes them in: a `Config` on an
HTTP client or a validation cache in Python, options in Go, client builder
methods in Rust.

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
| `jwks_cache_ttl` | `jwks.WithCacheTTL` | `JwksClientBuilder::cache_ttl` | seconds | `3600` | `60 – 86400` |
| `jwks_kid_miss_cooldown` | `jwks.WithRefreshCooldown` | `JwksClientBuilder::refresh_cooldown` | seconds | `5` | `0 – 3600` |
| `discovery_cache_ttl` | `discovery.WithCacheTTL` | `DiscoveryClientBuilder::cache_ttl` | seconds | `3600` | `60 – 86400` |
| `cache_max_entries` | `discovery.WithMaxCacheEntries`, `jwks.WithMaxCacheEntries` | `DiscoveryClientBuilder::max_cache_entries`, `JwksClientBuilder::max_cache_entries` | count | `64` | `≥ 1` |

Ranges are inclusive unless written `>`.

- **`http_timeout`, retries and `ca_bundle`** apply to every request the library
  makes. In Go and Rust they are options on every package or client that makes
  HTTP requests.
- **`http_retry_max_attempts`**: `0` disables retries.
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

## Algorithm allowlists

Each implementation keeps one JWS algorithm allowlist per purpose:

| Purpose | Python | Go | Rust |
|---|---|---|---|
| Verify: every inbound JWS (access and ID tokens, DPoP proofs, signed introspection responses, JARM responses) | `DEFAULT_ALLOWED_ALGORITHMS` | `jwt.defaultAllowedAlgorithms` | `DEFAULT_ALLOWED_ALGORITHMS` |
| Sign: outbound JWTs (client assertions, request objects) | `SUPPORTED_SIGNING_ALGORITHMS` | | |
| FAPI 2.0 | `FAPI2_ALLOWED_SIGNING_ALGORITHMS` | | |

- **Verify.** RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 and
  EdDSA (Ed25519). It is its own set, not derived from the signing set, so
  adding a signing algorithm never widens verification. It never contains an
  HMAC algorithm (`HS*`) or `none`, so a public key is never used as an HMAC
  secret ([RFC 8725 §2.1](https://www.rfc-editor.org/rfc/rfc8725#section-2.1)).
  Rust's set omits ES512: its verifier cannot check P-521 signatures yet
  ([#1011](https://github.com/jamescrowley321/identity-model/issues/1011)).
- **Sign.** The algorithms the library signs with. A DPoP key can be generated
  for ES256, ES384, ES512, PS256, RS256 or EdDSA.
- **FAPI 2.0.** PS256, ES256 and EdDSA
  ([FAPI 2.0 Security Profile §5.4.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1)).
  It applies only where the caller passes it, or where the FAPI 2.0 profile and
  validators check against it. It is never a default.

`algorithms` unset (`None` in Python) means the verify set wherever an
implementation verifies a JWS: discovery and manual (caller-supplied key) token
validation, DPoP proof verification, signed introspection responses and JARM. A JARM client with no
`algorithms` accepts the algorithms the authorization server advertises in
`authorization_signing_alg_values_supported` that are also in the verify set,
or the verify set when the server advertises none. An explicit list replaces
the default.

## Go and Rust today

Until [#757](https://github.com/jamescrowley321/identity-model/issues/757) (Go)
and [#758](https://github.com/jamescrowley321/identity-model/issues/758) (Rust)
land, Go and Rust differ from this page:

- They read `JWKS_CACHE_MAX_ENTRIES` and `DISCO_CACHE_MAX_ENTRIES` from the
  environment. `0`, from the environment or the max-cache-entries option,
  means unbounded.
- The discovery cache TTL and the JWKS cache TTL both default to 24 hours.
- Values are not range-checked. A zero TTL (Go: zero or negative) falls back
  to its default, as does a negative cooldown in Go; any other value is used
  as given.
- There is no retry, no `ca_bundle`, and no `jwks_max_size` or
  `jwks_max_keys`. Discovery and JWKS response bodies have a fixed 1 MiB cap.
- They don't read `Cache-Control`. Every response is cached for the configured
  TTL, with no 60 – 86400 clamp.
- Go has no client type: the `discovery` and `jwks` packages each use one
  package-level cache that every call shares.

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

A cache belongs to the object that holds its settings, so every cache has
exactly one set of settings.

- **Python:** HTTP clients only send requests and hold no cache. The discovery
  cache, the JWKS cache and the kid-miss cooldown live on a `ValidationCache` /
  `AsyncValidationCache`, which takes `config=` and reads `jwks_cache_ttl`,
  `discovery_cache_ttl`, `cache_max_entries` and `jwks_kid_miss_cooldown` from
  it. The token validators take `cache=`; without one they use the
  process-wide default cache, built from `Config()`, whichever `http_client`
  is passed. The default cache and the default HTTP clients are rebuilt in a
  forked child.
- **Go:** the `discovery` and `jwks` packages each have a client that holds its
  options and owns its cache. Package-level functions use a default client
  built from the defaults.
- **Rust:** `DiscoveryClient` and `JwksClient` own their caches.

Client settings for login flows (discovery URL, client ID and secret, scope,
redirect URIs) are not library settings. The FastAPI package keeps them on
`OIDCSettings`.
