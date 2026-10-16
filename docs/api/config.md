# Configuration

`Config` is a plain, frozen, typed value holding the library's settings. Every
setting has a default, so `Config()` is a complete configuration. Values are
validated when the `Config` is created: if any are invalid, one `ConfigError`
names every invalid setting and no `Config` is returned. An invalid value is
never replaced by its default.

`Config` has no loaders and parses no strings. Where the values come from
(environment variables, a file, a secrets manager) is up to you: build the
`Config` in your own code.

!!! note
    The library's discovery, JWKS and HTTP functions don't take a `Config` yet.
    Until they do, they keep reading the environment variables described in the
    [Performance Guide](../performance.md).

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

## Settings

| Setting | Type | Default | Valid |
|---|---|---|---|
| `http_timeout` | `float` | `30.0` s | > 0 |
| `http_retry_max_attempts` | `int` | `3` | ≥ 0 (0 disables retries) |
| `http_retry_base_delay` | `float` | `1.0` s, exponential backoff, each retry capped at 120 s | ≥ 0 |
| `ca_bundle` | `str \| None` | `None` (verify TLS with httpx's default bundle) | a readable file |
| `jwks_max_size` | `int` | `524288` bytes (512 KiB) | ≥ 1 |
| `jwks_max_keys` | `int` | `100` | ≥ 1 |
| `jwks_cache_ttl` | `float` | `86400.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `jwks_kid_miss_cooldown` | `float` | `5.0` s | 0 – 3600 (0 disables the cooldown) |
| `discovery_cache_ttl` | `float` | `3600.0` s, used only when the response has no `Cache-Control: max-age` | 60 – 86400 |
| `cache_max_entries` | `int` | `64`, applied separately to the JWKS cache and the discovery cache | ≥ 1 |

Error messages name the setting and the rule, never the value you passed.
`ConfigError` is a `ValueError`.

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
