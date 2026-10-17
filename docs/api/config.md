# Configuration

`Config` is a plain, frozen, typed value holding the library's settings. Every
setting has a default, so `Config()` is a complete configuration. Values are
validated when the `Config` is created: if any are invalid, one `ConfigError`
names every invalid setting and no `Config` is returned. An invalid value is
never replaced by its default.

`Config` has no loaders and parses no strings. Where the values come from
(environment variables, a file, a secrets manager) is up to you: build the
`Config` in your own code.

The library reads no environment variables. A setting takes effect only
through a `Config` you pass in, on an HTTP client (see
[Passing a `Config` to the library](#passing-a-config-to-the-library)).

## Building a `Config` in your own code

```python
from py_identity_model import Config, ConfigError

config = Config(http_timeout=10.0, cache_max_entries=128)

try:
    Config(http_timeout=0, http_retry_max_attempts=-1)
except ConfigError as e:
    for issue in e.issues:  # every invalid setting, in field order
        print(issue)        # "http_timeout: must be greater than 0", ...
```

Fields are keyword-only. Pass typed values: `Config(http_timeout="10")` is
rejected (`must be a number`), as are `bool`, NaN and infinity.

## The same thing with a helper

`py_identity_model.config_helpers` has two ready-made helpers that read string
settings, convert each one to its type and return a `Config`. They are
optional: the library never imports this module, so nothing reads the
environment unless you call one.

```python
from py_identity_model.config_helpers import config_from_env, config_from_mapping

config = config_from_env()                  # HTTP_TIMEOUT, MAX_JWKS_KEYS, ...
config = config_from_env(prefix="APP_")     # APP_HTTP_TIMEOUT, APP_MAX_JWKS_KEYS, ...
config = config_from_mapping({"HTTP_TIMEOUT": "10", "JWKS_CACHE_MAX_ENTRIES": "128"})
```

`config_from_env(prefix)` is `config_from_mapping(os.environ, prefix=prefix)`.
Both read these keys, with the prefix in front of each:

| Setting | Keys, first one set wins |
|---|---|
| `http_timeout` | `HTTP_TIMEOUT` |
| `http_retry_max_attempts` | `HTTP_RETRY_MAX_ATTEMPTS`, `HTTP_RETRY_COUNT` |
| `http_retry_base_delay` | `HTTP_RETRY_BASE_DELAY` |
| `ca_bundle` | `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` |
| `jwks_max_size` | `MAX_JWKS_SIZE` |
| `jwks_max_keys` | `MAX_JWKS_KEYS` |
| `jwks_cache_ttl` | `JWKS_CACHE_TTL` |
| `jwks_kid_miss_cooldown` | `KID_MISS_REFRESH_COOLDOWN` |
| `discovery_cache_ttl` | `DISCO_CACHE_TTL` |
| `cache_max_entries` | `JWKS_CACHE_MAX_ENTRIES` |

A key that is missing, empty or `None` is unset, and its setting keeps the
default. Other keys are ignored. A value that can't be converted
(`HTTP_TIMEOUT=fast`) or is out of range (`HTTP_TIMEOUT=0`) raises one
`ConfigError` listing every bad key. Each issue names the key as you wrote it,
prefix included (`APP_HTTP_TIMEOUT: must be greater than 0`), never the value.

### Loading a `.env` file

The library has no `.env` parser. Read the file with
[python-dotenv](https://pypi.org/project/python-dotenv/) (install it yourself)
and pass the result to `config_from_mapping`:

```python
from dotenv import dotenv_values

from py_identity_model.config_helpers import config_from_mapping

config = config_from_mapping(dotenv_values(".env"))
```

`dotenv_values()` doesn't touch `os.environ`. It returns `None` for a line
with no `=`, which counts as unset.

### Writing your own

For any other source, write a small function that reads it, converts each
value to its type and returns a `Config`. Conversion belongs in the helper;
validation stays in `Config`.

```python
from collections.abc import Mapping

from py_identity_model import Config


def config_from_settings(settings: Mapping[str, str]) -> Config:
    kwargs: dict[str, object] = {}
    if "timeout" in settings:
        kwargs["http_timeout"] = float(settings["timeout"])
    if "ca_bundle" in settings:
        kwargs["ca_bundle"] = settings["ca_bundle"]
    return Config(**kwargs)
```

## Passing a `Config` to the library

A `Config` is passed to an HTTP client and, for the cache settings, to a
validation cache. `HTTPClient` (sync) and `AsyncHTTPClient` (async) take
`config=`, and every entry point (discovery, JWKS, token validation, token
requests, UserInfo and the rest) takes `http_client=`. `ValidationCache` /
`AsyncValidationCache` take `config=` too, and the token validators take
`cache=`:

```python
from py_identity_model import (
    Config,
    DiscoveryDocumentRequest,
    HTTPClient,
    ValidationCache,
    get_discovery_document,
    validate_token,
)

config = Config(http_timeout=10.0, cache_max_entries=128)
cache = ValidationCache(config=config)

with HTTPClient(config=config) as client:
    disco = get_discovery_document(
        DiscoveryDocumentRequest(address=DISCO_URL), http_client=client
    )
    claims = validate_token(
        token, validation_config, DISCO_URL, http_client=client, cache=cache
    )
```

```python
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache, validate_token

async_cache = AsyncValidationCache(config=config)

async with AsyncHTTPClient(config=config) as client:
    claims = await validate_token(
        token, validation_config, DISCO_URL, http_client=client, cache=async_cache
    )
```

- `config=None` means `Config()` defaults, not the environment.
- Called without `http_client=`, an entry point uses the library default
  client, built from `Config()`.
- The cache settings (`jwks_cache_ttl`, `discovery_cache_ttl`,
  `cache_max_entries`, `jwks_kid_miss_cooldown`) apply to a
  [`ValidationCache`](http-client.md#validation-cache), not to a client:
  `ValidationCache(config=config)`, passed as `cache=` to the validators.
  Without `cache=`, the process-wide default cache, built from `Config()`, is
  used. A cache setting on a client's `Config` has no effect.
- `clear_discovery_cache(cache=...)` and `clear_jwks_cache(cache=...)` clear
  one cache (the default one when `cache` is omitted).
- To wrap your own `httpx.Client` (for a proxy, custom TLS, or
  `verify=False` in a test), pass it as the first argument:
  `HTTPClient(httpx.Client(...), config=config)`. Its own timeout and TLS
  settings apply; the `Config` still sets retries and JWKS limits. A wrapped client can't be combined with `mtls` (that raises
  `ValueError`); use `HTTPClient(config=Config(ca_bundle=...))` instead.

!!! warning "Breaking change (py-identity-model 5.0): no environment variables"
    The library no longer reads any environment variable. `HTTP_TIMEOUT`,
    `HTTP_RETRY_MAX_ATTEMPTS` / `HTTP_RETRY_COUNT`, `HTTP_RETRY_BASE_DELAY`,
    `MAX_JWKS_SIZE`, `MAX_JWKS_KEYS`, `JWKS_CACHE_TTL`, `DISCO_CACHE_TTL`,
    `KID_MISS_REFRESH_COOLDOWN`, `JWKS_CACHE_MAX_ENTRIES`, `SSL_CERT_FILE`,
    `CURL_CA_BUNDLE` and `REQUESTS_CA_BUNDLE` are ignored by the library.
    Build a `Config` and pass it on a client. To keep reading the same
    variables, use the helper:

    ```python
    from py_identity_model import HTTPClient
    from py_identity_model.config_helpers import config_from_env

    client = HTTPClient(config=config_from_env())
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
      `get_max_jwks_keys` are removed; `get_ssl_verify(config)` takes a
      `Config` and is no longer cached.
    - A negative retry count is rejected when the `Config` is built, so it
      can no longer reach the retry loop.

    httpx itself still honours `SSL_CERT_FILE` / `SSL_CERT_DIR` and proxy
    variables when it builds a client with its default `trust_env=True`. That
    is httpx's behavior, not the library's; wrap an
    `httpx.Client(trust_env=False, ...)` to turn it off.

## Settings

| Setting | Type | Default | Valid |
|---|---|---|---|
| `http_timeout` | `float` | `30.0` s | > 0 |
| `http_retry_max_attempts` | `int` | `3` | ≥ 0 (0 disables retries) |
| `http_retry_base_delay` | `float` | `1.0` s, exponential backoff, each retry capped at 120 s | ≥ 0 |
| `ca_bundle` | `str \| None` | `None` (verify TLS with httpx's default bundle) | a readable file |
| `jwks_max_size` | `int` | `524288` bytes (512 KiB) | ≥ 1 |
| `jwks_max_keys` | `int` | `100` | ≥ 1 |
| `jwks_cache_ttl` | `float` | `3600.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `jwks_kid_miss_cooldown` | `float` | `5.0` s | 0 – 3600 (0 disables the cooldown) |
| `discovery_cache_ttl` | `float` | `3600.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `cache_max_entries` | `int` | `64`, applied separately to the JWKS cache and the discovery cache | ≥ 1 |

Error messages name the setting and the rule, never the value you passed.
`ConfigError` is a `ValueError`.

The same settings, with their Go and Rust names and the cache rules, are on
the cross-language
[configuration page](https://github.com/jamescrowley321/identity-model/blob/main/spec/config.md).
Python defines them. Go and Rust still differ in places, as that page lists.

!!! warning "Breaking change: sources and loaders removed"
    `Config.from_env`, `Config.build`, `ConfigSource`, `EnvSource`,
    `MappingSource` and `Secret` have been removed, along with the dotted
    logical keys (`"http.timeout"`) and the `CFG-00x` issue codes. Build a
    `Config` with keyword arguments instead. `ConfigIssue` now has
    `setting` and `message`.

    The client settings (`client_id`, `client_secret`, discovery URL, scope,
    audience, redirect URIs, excluded paths) are no longer part of `Config`.
    For the FastAPI package they live on `OIDCSettings`.

    `jwks_cache_max_entries` and `discovery_cache_max_entries` are replaced
    by one `cache_max_entries`, which must be at least 1.

## API

::: py_identity_model.core.config.Config

::: py_identity_model.core.config.ConfigError

::: py_identity_model.core.config.ConfigIssue

::: py_identity_model.core.config.ClientAuthMethod

::: py_identity_model.config_helpers.config_from_mapping

::: py_identity_model.config_helpers.config_from_env
