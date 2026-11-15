# Configuration

The library's settings are on two plain, frozen, typed values:

- `HTTPConfig`: settings for an HTTP client (timeout, retries, TLS, JWKS size
  limits). `HTTPClient` and `AsyncHTTPClient` take it.
- `CacheConfig`: settings for a validation cache (cache TTLs, size, kid-miss
  cooldown). `ValidationCache` and `AsyncValidationCache` take it.

Each consumer takes only the config it reads, so a setting can't be passed
somewhere that silently ignores it. Passing the other type
(`HTTPClient(config=CacheConfig())`) raises `TypeError`.

Every setting has a default, so `HTTPConfig()` and `CacheConfig()` are complete
configurations. Values are validated when the config is created: if any are
invalid, one `ConfigError` names every invalid setting and nothing is
returned. An invalid value is never replaced by its default.

Neither has loaders or parses strings. Where the values come from (environment
variables, a file, a secrets manager) is up to you: build the configs in your
own code.

The library reads no environment variables. A setting takes effect only
through a config you pass in (see
[Passing the configs to the library](#passing-the-configs-to-the-library)).

## Building the configs in your own code

```python
from py_identity_model import CacheConfig, ConfigError, HTTPConfig

http_config = HTTPConfig(http_timeout=10.0)
cache_config = CacheConfig(cache_max_entries=128)

try:
    HTTPConfig(http_timeout=0, http_retry_max_attempts=-1)
except ConfigError as e:
    for issue in e.issues:  # every invalid setting, in field order
        print(issue)        # "http_timeout: must be greater than 0", ...
```

Fields are keyword-only. Pass typed values: `HTTPConfig(http_timeout="10")` is
rejected (`must be a number`), as are `bool`, NaN and infinity. A setting of
the other config (`HTTPConfig(cache_max_entries=128)`) is a `TypeError`.

## The same thing with a helper

`py_identity_model.config_helpers` has ready-made helpers that read string
settings, convert each one to its type and return a config. They are
optional: the library never imports this module, so nothing reads the
environment unless you call one.

```python
from py_identity_model.config_helpers import (
    cache_config_from_env,
    cache_config_from_mapping,
    http_config_from_env,
    http_config_from_mapping,
)

http_config = http_config_from_env()                 # HTTP_TIMEOUT, MAX_JWKS_KEYS, ...
cache_config = cache_config_from_env(prefix="APP_")  # APP_JWKS_CACHE_TTL, ...
http_config = http_config_from_mapping({"HTTP_TIMEOUT": "10"})
cache_config = cache_config_from_mapping({"JWKS_CACHE_MAX_ENTRIES": "128"})
```

`http_config_from_env(prefix)` is
`http_config_from_mapping(os.environ, prefix=prefix)`, and likewise for the
cache helpers. They read these keys, with the prefix in front of each:

| Config | Setting | Keys, first one set wins |
|---|---|---|
| `HTTPConfig` | `http_timeout` | `HTTP_TIMEOUT` |
| `HTTPConfig` | `http_retry_max_attempts` | `HTTP_RETRY_MAX_ATTEMPTS`, `HTTP_RETRY_COUNT` |
| `HTTPConfig` | `http_retry_base_delay` | `HTTP_RETRY_BASE_DELAY` |
| `HTTPConfig` | `ca_bundle` | `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` |
| `HTTPConfig` | `jwks_max_size` | `MAX_JWKS_SIZE` |
| `HTTPConfig` | `jwks_max_keys` | `MAX_JWKS_KEYS` |
| `CacheConfig` | `jwks_cache_ttl` | `JWKS_CACHE_TTL` |
| `CacheConfig` | `jwks_kid_miss_cooldown` | `KID_MISS_REFRESH_COOLDOWN` |
| `CacheConfig` | `discovery_cache_ttl` | `DISCO_CACHE_TTL` |
| `CacheConfig` | `cache_max_entries` | `JWKS_CACHE_MAX_ENTRIES` |

A key that is missing, empty or `None` is unset, and its setting keeps the
default. Other keys are ignored, including the other config's keys. A value
that can't be converted (`HTTP_TIMEOUT=fast`) or is out of range
(`HTTP_TIMEOUT=0`) raises one `ConfigError` listing every bad key. Each issue
names the key as you wrote it, prefix included
(`APP_HTTP_TIMEOUT: must be greater than 0`), never the value.

### Loading a `.env` file

The library has no `.env` parser. Read the file with
[python-dotenv](https://pypi.org/project/python-dotenv/) (install it yourself)
and pass the result to the mapping helpers:

```python
from dotenv import dotenv_values

from py_identity_model.config_helpers import (
    cache_config_from_mapping,
    http_config_from_mapping,
)

values = dotenv_values(".env")
http_config = http_config_from_mapping(values)
cache_config = cache_config_from_mapping(values)
```

`dotenv_values()` doesn't touch `os.environ`. It returns `None` for a line
with no `=`, which counts as unset.

### Writing your own

For any other source, write a small function that reads it, converts each
value to its type and returns a config. Conversion belongs in the helper;
validation stays in the config.

```python
from collections.abc import Mapping

from py_identity_model import HTTPConfig


def http_config_from_settings(settings: Mapping[str, str]) -> HTTPConfig:
    kwargs: dict[str, object] = {}
    if "timeout" in settings:
        kwargs["http_timeout"] = float(settings["timeout"])
    if "ca_bundle" in settings:
        kwargs["ca_bundle"] = settings["ca_bundle"]
    return HTTPConfig(**kwargs)
```

## Passing the configs to the library

`HTTPClient` (sync) and `AsyncHTTPClient` (async) take an `HTTPConfig` as
`config=`, and every entry point (discovery, JWKS, token validation, token
requests, UserInfo and the rest) takes `http_client=`. `ValidationCache` /
`AsyncValidationCache` take a `CacheConfig` as `config=`, and the token
validators take `cache=`:

```python
from py_identity_model import (
    CacheConfig,
    DiscoveryDocumentRequest,
    HTTPClient,
    HTTPConfig,
    ValidationCache,
    get_discovery_document,
    validate_token,
)

cache = ValidationCache(config=CacheConfig(cache_max_entries=128))

with HTTPClient(config=HTTPConfig(http_timeout=10.0)) as client:
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_URL), http_client=client
    )
    claims = validate_token(
        token, validation_config, DISCO_URL, http_client=client, cache=cache
    )
```

```python
from py_identity_model import CacheConfig, HTTPConfig
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache, validate_token

async_cache = AsyncValidationCache(config=CacheConfig(cache_max_entries=128))

async with AsyncHTTPClient(config=HTTPConfig(http_timeout=10.0)) as client:
    claims = await validate_token(
        token, validation_config, DISCO_URL, http_client=client, cache=async_cache
    )
```

- `config=None` means `HTTPConfig()` (or `CacheConfig()`) defaults, not the
  environment.
- Called without `http_client=`, an entry point uses the library default
  client, built from `HTTPConfig()`.
- Called without `cache=`, a validator uses the process-wide default cache,
  built from `CacheConfig()`. See
  [Validation cache](http-client.md#validation-cache).
- A `ValidationCache`'s state is private: its only public member is
  `config`. `clear_discovery_cache(cache=...)` and
  `clear_jwks_cache(cache=...)` clear one cache (the default one when `cache`
  is omitted).
- To wrap your own `httpx.Client` (for a proxy, custom TLS, or
  `verify=False` in a test), pass it as the first argument:
  `HTTPClient(httpx.Client(...), config=http_config)`. Its own timeout and TLS
  settings apply; the `HTTPConfig` still sets retries and JWKS limits. A
  wrapped client can't be combined with `mtls` (that raises `ValueError`); use
  `HTTPClient(config=HTTPConfig(ca_bundle=...))` instead.

!!! warning "Breaking change (py-identity-model 5.0): no environment variables"
    The library no longer reads any environment variable. `HTTP_TIMEOUT`,
    `HTTP_RETRY_MAX_ATTEMPTS` / `HTTP_RETRY_COUNT`, `HTTP_RETRY_BASE_DELAY`,
    `MAX_JWKS_SIZE`, `MAX_JWKS_KEYS`, `JWKS_CACHE_TTL`, `DISCO_CACHE_TTL`,
    `KID_MISS_REFRESH_COOLDOWN`, `JWKS_CACHE_MAX_ENTRIES`, `SSL_CERT_FILE`,
    `CURL_CA_BUNDLE` and `REQUESTS_CA_BUNDLE` are ignored by the library.
    Build an `HTTPConfig` and a `CacheConfig` and pass them on a client and a
    cache. To keep reading the same variables, use the helpers:

    ```python
    from py_identity_model import HTTPClient, ValidationCache
    from py_identity_model.config_helpers import (
        cache_config_from_env,
        http_config_from_env,
    )

    client = HTTPClient(config=http_config_from_env())
    cache = ValidationCache(config=cache_config_from_env())
    ```

    Also changed:

    - `HTTPClient` / `AsyncHTTPClient` take `config=` instead of `timeout=`
      and `verify=`. For `verify=False`, wrap your own `httpx.Client`.
    - An injected `http_client` no longer bypasses the discovery and JWKS
      caches or the kid-miss cooldown: they live on a `ValidationCache`
      (`cache=`), and the process-wide default cache is used when none is
      passed. It used to bypass them and log a warning.
    - `clear_discovery_cache` / `clear_jwks_cache` take an optional
      `cache`.
    - `get_retry_config`, `get_timeout`, `get_max_jwks_size` and
      `get_max_jwks_keys` are removed; `get_ssl_verify(config)` takes an
      `HTTPConfig` and is no longer cached.
    - A negative retry count is rejected when the `HTTPConfig` is built, so it
      can no longer reach the retry loop.

    httpx itself still honours `SSL_CERT_FILE` / `SSL_CERT_DIR` and proxy
    variables when it builds a client with its default `trust_env=True`. That
    is httpx's behavior, not the library's; wrap an
    `httpx.Client(trust_env=False, ...)` to turn it off.

## Settings

| Config | Setting | Type | Default | Valid |
|---|---|---|---|---|
| `HTTPConfig` | `http_timeout` | `float` | `30.0` s | > 0 |
| `HTTPConfig` | `http_retry_max_attempts` | `int` | `3` | ≥ 0 (0 disables retries) |
| `HTTPConfig` | `http_retry_base_delay` | `float` | `1.0` s, exponential backoff, each retry capped at 120 s | ≥ 0 |
| `HTTPConfig` | `ca_bundle` | `str \| None` | `None` (verify TLS with httpx's default bundle) | a readable file |
| `HTTPConfig` | `jwks_max_size` | `int` | `524288` bytes (512 KiB) | ≥ 1 |
| `HTTPConfig` | `jwks_max_keys` | `int` | `100` | ≥ 1 |
| `CacheConfig` | `jwks_cache_ttl` | `float` | `3600.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `CacheConfig` | `jwks_kid_miss_cooldown` | `float` | `5.0` s | 0 – 3600 (0 disables the cooldown) |
| `CacheConfig` | `discovery_cache_ttl` | `float` | `3600.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `CacheConfig` | `cache_max_entries` | `int` | `64`, applied separately to the JWKS cache and the discovery cache | ≥ 1 |

Error messages name the setting and the rule, never the value you passed.
`ConfigError` is a `ConfigurationException`.

The same settings, with their Go and Rust names and the cache rules, are on
the cross-language
[configuration page](https://github.com/jamescrowley321/identity-model/blob/main/spec/config.md).
Python defines them. Go and Rust still differ in places, as that page lists.

!!! warning "Breaking change: one `Config` split in two"
    The single `Config` is replaced by `HTTPConfig` and `CacheConfig`. A
    client used to accept the cache settings and ignore them, and a cache
    ignored the transport settings. Move each setting to the config of the
    object that reads it:

    ```python
    # Before
    config = Config(http_timeout=10.0, cache_max_entries=128)
    client = HTTPClient(config=config)
    cache = ValidationCache(config=config)

    # After
    client = HTTPClient(config=HTTPConfig(http_timeout=10.0))
    cache = ValidationCache(config=CacheConfig(cache_max_entries=128))
    ```

    `config_from_env` and `config_from_mapping` are replaced by
    `http_config_from_env` / `http_config_from_mapping` and
    `cache_config_from_env` / `cache_config_from_mapping`.

!!! warning "Breaking change: sources and loaders removed"
    `Config.from_env`, `Config.build`, `ConfigSource`, `EnvSource`,
    `MappingSource` and `Secret` have been removed, along with the dotted
    logical keys (`"http.timeout"`) and the `CFG-00x` issue codes. Build the
    configs with keyword arguments instead. `ConfigIssue` now has `setting`
    and `message`.

    The client settings (`client_id`, `client_secret`, discovery URL, scope,
    audience, redirect URIs, excluded paths) are not part of either config.
    For the FastAPI package they live on `OIDCSettings`.

    `jwks_cache_max_entries` and `discovery_cache_max_entries` are replaced
    by one `cache_max_entries`, which must be at least 1.

## API

::: py_identity_model.core.config.HTTPConfig

::: py_identity_model.core.config.CacheConfig

::: py_identity_model.core.config.ConfigError

::: py_identity_model.core.config.ConfigIssue

::: py_identity_model.core.client_auth_method.ClientAuthMethod

::: py_identity_model.config_helpers.http_config_from_mapping

::: py_identity_model.config_helpers.http_config_from_env

::: py_identity_model.config_helpers.cache_config_from_mapping

::: py_identity_model.config_helpers.cache_config_from_env
