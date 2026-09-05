# Configuration

A typed, fail-closed configuration surface. `Config` resolves settings from
pluggable sources (environment variables by default), validates **everything
up front**, and either returns an immutable, fully-typed value or raises a
single `ConfigError` carrying *every* problem at once — no partial
configuration ever escapes, and error messages name keys, never values.

This is an opt-in layer: construct a `Config` and read its typed fields in
your own wiring. The library's existing per-call configuration
(`TokenValidationConfig`, request models) is unchanged.

```python
from py_identity_model import ClientAuthMethod, Config, ConfigError

try:
    cfg = Config.from_env(group="client", client_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC)
except ConfigError as e:
    for issue in e.issues:  # every problem, reported together
        print(issue)        # e.g. "CFG-001: required key 'client.id' is missing (client.id)"
    raise

cfg.http_timeout            # float, validated > 0
cfg.client_id               # str
cfg.client_secret.expose()  # Secret: redacted in repr/str, read explicitly
```

## Sources and precedence

Values resolve per key, first hit wins:

1. `overrides` — explicit in-code values passed to `Config.build`
2. your `sources`, in the order given (earlier wins)
3. the environment (`EnvSource`, appended last unless `env=False`)
4. the built-in default

```python
from py_identity_model import Config, EnvSource, MappingSource

cfg = Config.build(
    sources=[
        MappingSource({"client.discovery_url": url, "client.id": cid}, name="vault"),
        EnvSource(prefix="MYAPP_"),
    ],
    overrides={"http.timeout": "5"},
    env=False,          # don't also read the default OIDC_-prefixed environment
    group="client",
)
```

A custom source is anything satisfying the `ConfigSource` protocol — return
raw strings for the keys you can supply and nothing else; typing, defaulting,
and validation stay in the library. A source that raises fails construction
closed (`CFG-004`).

## Keys

HTTP and cache keys read unprefixed environment variables; the client group
takes the `EnvSource` prefix (default `OIDC_`).

| Logical key | Env var (default) | Type | Default |
|---|---|---|---|
| `http.timeout` | `HTTP_TIMEOUT` | float > 0 | `30.0` |
| `http.retry.max_attempts` | `HTTP_RETRY_MAX_ATTEMPTS` | int >= 0 | `3` |
| `http.retry.base_delay` | `HTTP_RETRY_BASE_DELAY` | float >= 0 | `1.0` |
| `jwks.max_size` | `MAX_JWKS_SIZE` | int >= 1 | `524288` |
| `jwks.max_keys` | `MAX_JWKS_KEYS` | int >= 1 | `100` |
| `jwks.cache.ttl` | `JWKS_CACHE_TTL` | float, 60–86400 | `86400.0` |
| `discovery.cache.ttl` | `DISCO_CACHE_TTL` | float, 60–86400 | `3600.0` |
| `jwks.kid_miss_cooldown` | `KID_MISS_REFRESH_COOLDOWN` | float, 0–3600 | `5.0` |
| `jwks.cache.max_entries` | `JWKS_CACHE_MAX_ENTRIES` | int >= 0 | `64` |
| `discovery.cache.max_entries` | `DISCO_CACHE_MAX_ENTRIES` | int >= 0 | `64` |
| `client.discovery_url` | `OIDC_DISCOVERY_URL` | absolute URL | required in group |
| `client.id` | `OIDC_CLIENT_ID` | str | required in group |
| `client.secret` | `OIDC_CLIENT_SECRET` | `Secret` | — |
| `client.scope` | `OIDC_SCOPE` | str | `"openid profile email"` |
| `client.audience` | `OIDC_AUDIENCE` | str | falls back to `client.id` |
| `client.redirect_uri` | `OIDC_REDIRECT_URI` | URL | `""` |
| `client.post_login_redirect` | `OIDC_POST_LOGIN_REDIRECT` | str | `"/"` |
| `client.post_logout_redirect` | `OIDC_POST_LOGOUT_REDIRECT` | str | `"/"` |
| `client.excluded_paths` | `OIDC_EXCLUDED_PATHS` | str list | `("/docs", "/openapi.json", "/health")` |

The client group is validated as a unit: requesting `group="client"` requires
`client.discovery_url` and `client.id` (`CFG-001`), a `client_auth_method`
that needs a secret requires `client.secret` (`CFG-002`), and supplying a
client key *without* requesting the group is itself an error (`CFG-002`).
Issue codes: `CFG-001` missing key, `CFG-002` incomplete group, `CFG-003`
invalid value, `CFG-004` source failure.

## API

::: py_identity_model.core.config.Config

::: py_identity_model.core.config.ConfigError

::: py_identity_model.core.config.ConfigIssue

::: py_identity_model.core.config.Secret

::: py_identity_model.core.config.ClientAuthMethod

### Sources

::: py_identity_model.core.config.ConfigSource

::: py_identity_model.core.config.EnvSource

::: py_identity_model.core.config.MappingSource
