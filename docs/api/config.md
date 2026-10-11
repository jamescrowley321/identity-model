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

When your settings live somewhere else, write a small function that reads
them, converts each value to its type and returns a `Config`. Conversion
belongs in the helper; validation stays in `Config`.

```python
from collections.abc import Mapping

from py_identity_model import Config


def config_from_settings(settings: Mapping[str, str]) -> Config:
    kwargs: dict[str, object] = {}
    if "HTTP_TIMEOUT" in settings:
        kwargs["http_timeout"] = float(settings["HTTP_TIMEOUT"])
    if "CACHE_MAX_ENTRIES" in settings:
        kwargs["cache_max_entries"] = int(settings["CACHE_MAX_ENTRIES"])
    if "CA_BUNDLE" in settings:
        kwargs["ca_bundle"] = settings["CA_BUNDLE"]
    return Config(**kwargs)


config = config_from_settings({"HTTP_TIMEOUT": "10", "CACHE_MAX_ENTRIES": "128"})
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
