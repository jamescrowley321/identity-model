# identity-model — Configuration Contract

This is the **normative, cross-language contract for configuration behavior**: the canonical key registry, how values are resolved from sources, how validation fails, and how secrets are redacted. Every language implements this contract idiomatically; behavioral parity is proven by the conformance definitions in [`conformance/config.json`](conformance/config.json) with fixtures in [`test-fixtures/config/`](test-fixtures/config/).

Normative keywords (MUST / SHOULD / MAY) follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Design Principles

1. **One registry.** Every configuration key the library reads is defined here — logical ID, environment name, type, default, and validation semantics. A key without a registry row MUST NOT exist in any implementation.
2. **Sources supply raw strings; the library owns meaning.** A `ConfigSource` returns raw string values only. Typing, defaulting, clamping, validation, and redaction always happen in the library after resolution — no source can bypass them.
3. **Fail closed, once.** The typed `Config` surface validates the complete configuration at construction. There is no configuration state that yields a constructed-but-degraded `Config`.
4. **Backward compatible by construction.** The typed surface is opt-in. The library's pre-existing environment behavior is preserved bit-for-bit as this contract's *legacy mode* — including its documented per-language divergences and rough edges. Nothing about existing deployments changes.
5. **No security-weakening keys.** Toggles that weaken a security default (e.g. allowing `http://` issuers or endpoints) MUST remain code-only (builder/option flags). The registry MUST NOT ever contain a key whose value can lower a security posture. This rule is normative and permanent.

## Resolution Model

### Sources

A `ConfigSource` (Rust trait / Go interface / Python Protocol / TypeScript interface) exposes one operation, conceptually:

```
resolve(keys: [logical key IDs]) -> map of logical key ID -> raw string value
```

- Resolution is **library-driven and bulk**: the library passes the registry's key list; the source is consulted **exactly once per construction** and returns the subset it can supply (a snapshot — no torn reads across keys).
- A source MAY return keys it was not asked for; the library MUST discard unknown keys silently (forward compatibility).
- A source MUST NOT perform typing, defaulting, clamping, or validation.
- A source that fails (raises/errors) fails the construction closed with `CFG-004`; it MUST NOT be silently skipped.
- The default source is `EnvSource`, which maps logical keys to the environment variable names in the registry. Client-group keys accept a configurable prefix (default `OIDC_`).
- Sources are trusted only to supply values. A hostile or buggy source can at worst supply values that validation rejects or accepts per this contract — it cannot suppress validation, security gating, or redaction.

### Precedence

For each key, the first hit wins, in this total order:

1. **Explicit override** — a value set directly in code (builder method, option, constructor argument). Overrides are not a source; they short-circuit resolution for that key.
2. **Consumer-supplied sources, in the order given** — earlier in the list = higher precedence.
3. **`EnvSource`** — implicitly last. The default construction (`Config::from_env()` and per-language equivalents) is exactly `sources = [EnvSource]`. A consumer MAY list `EnvSource` explicitly to reposition it.
4. **Registry default** — applies only when no source yields the key. Required keys have no default and fail closed in strict mode.

**Aliases** resolve *within* a source before falling through: a source is consulted for the primary env name, then the alias; a source that yields either wins over any lower-precedence source. When both are set in one source, the primary wins (matching today's `HTTP_RETRY_MAX_ATTEMPTS` over `HTTP_RETRY_COUNT`).

There is no merging within a key — whole-value wins only.

### Modes

The resolver has exactly two modes. Consumers only ever see strict mode; legacy mode exists so that migrating the library's internal reads is provably behavior-preserving.

- **`legacy`** — today's per-language semantics, bit-for-bit, as recorded in the registry's *Legacy semantics* column — including divergences between languages and behaviors that raise unhandled errors. Legacy resolution is invoked **at the same call sites where the environment read happens today**; routing changes, timing does not. Legacy mode is internal library surface and MUST NOT be exposed on public typed constructors.
- **`strict`** — the typed `Config` construction mode. Missing required key → `CFG-001`; incomplete key group → `CFG-002`; unparseable or out-of-domain value → `CFG-003` (invalid values are never silently defaulted; absent optional keys still take registry defaults); erroring source → `CFG-004`. Construction is atomic: on any error, no `Config` value exists, and **all** errors for the construction are collected and reported together, ordered by registry order.

Strict-mode value parsing is uniform across languages:

- **bool** — case-insensitive `true|false|1|0`; anything else → `CFG-003`.
- **int / float** — decimal only, surrounding whitespace trimmed; anything else → `CFG-003`; range/clamp rules per registry row. Non-finite floats (NaN/Inf) → `CFG-003`.
- **URL** — must parse as absolute with a scheme; scheme requirements (https-only) follow the consuming component's existing policy and are never weakened via configuration (Principle 5).
- **Empty or whitespace-only string from a source = key present with an invalid value** → `CFG-003` for typed keys. Absence means the source did not return the key. (This deliberately kills the `getenv(key, "")` ambiguity class.)

## Key Registry

Logical key IDs are dotted lowercase. Environment names, defaults, and legacy semantics are transcribed from the implementations as of 2026-09-03 and are load-bearing: legacy mode MUST reproduce them exactly. "n/a" in a language column means the language does not read that key today; when it adopts the key (e.g. via the parity roadmap), it MUST do so through this contract.

### HTTP transport

| Logical key | Env name(s) | Type | Default | Strict validation | Legacy semantics | Py | Go | Rust |
|---|---|---|---|---|---|---|---|---|
| `http.timeout` | `HTTP_TIMEOUT` | float secs | `30.0` | > 0 | py: `float(getenv)`; invalid value raises unhandled `ValueError` at read time | ✔ | n/a | n/a |
| `http.retry.max_attempts` | `HTTP_RETRY_MAX_ATTEMPTS`, alias `HTTP_RETRY_COUNT` | int | `3` | ≥ 0 (`0` disables retries) | py: primary wins over alias when both set; `0` honored; invalid raises unhandled `ValueError` | ✔ | n/a | n/a |
| `http.retry.base_delay` | `HTTP_RETRY_BASE_DELAY` | float secs | `1.0` | ≥ 0 | py: `float(getenv)`; invalid raises unhandled `ValueError`. Per-retry delay is additionally capped at 120 s internally (not a key) | ✔ | n/a | n/a |

### JWKS & discovery

| Logical key | Env name(s) | Type | Default | Strict validation | Legacy semantics | Py | Go | Rust |
|---|---|---|---|---|---|---|---|---|
| `jwks.max_size` | `MAX_JWKS_SIZE` | int bytes | `524288` (512 KB) | > 0 | py: `int(getenv)`; invalid raises unhandled `ValueError` | ✔ | n/a¹ | n/a¹ |
| `jwks.max_keys` | `MAX_JWKS_KEYS` | int | `100` | ≥ 1 | py: `max(1, int(getenv))` — values < 1 clamp to 1; invalid raises unhandled `ValueError` | ✔ | n/a | n/a |
| `jwks.cache.ttl` | `JWKS_CACHE_TTL` | float secs | `86400` (24 h) | clamp [60, 86400] | py: priority `Cache-Control: max-age` → env → default; NaN/Inf/invalid → default; out-of-range clamps. go/rust: static 24 h option default, env not read | ✔ | n/a² | n/a² |
| `discovery.cache.ttl` | `DISCO_CACHE_TTL` | float secs | `3600` (1 h) | clamp [60, 86400] | py: same priority/clamping as above. go/rust: static 24 h option default, env not read (known divergence — parity roadmap H3) | ✔ | n/a² | n/a² |
| `jwks.kid_miss_cooldown` | `KID_MISS_REFRESH_COOLDOWN` | float secs | `5.0` | clamp [0, 3600]; `0` = opt-out | py: invalid/NaN → default; clamps. go/rust: static 5 s option default, env not read | ✔ | n/a² | n/a² |
| `jwks.cache.max_entries` | `JWKS_CACHE_MAX_ENTRIES` | int | `64` | ≥ 0; `0` = unbounded | **Documented divergence.** py: unset/empty → 64; `< 1` (incl. `0`) → warn + 64; invalid → warn + 64. go/rust: empty → 64; invalid/negative → 64; **`0` → unbounded** (escape hatch) | ✔ | ✔ | ✔ |
| `discovery.cache.max_entries` | `DISCO_CACHE_MAX_ENTRIES` | int | `64` | ≥ 0; `0` = unbounded | go/rust: as above. py: not read (jwks and discovery caches are capped independently only in go/rust) | n/a | ✔ | ✔ |

¹ go/rust enforce a fixed 1 MiB body cap in code, not via this key.
² go/rust expose the equivalent knob as a per-client option today; the env-driven key applies when they adopt it via this contract.

### TLS / CA bundles (Python-only legacy surface)

| Logical key | Env name(s) | Type | Default | Strict validation | Legacy semantics | Py | Go | Rust |
|---|---|---|---|---|---|---|---|---|
| `tls.cert_file` | `SSL_CERT_FILE` | path | — (system CA) | non-empty path | py: first set of `SSL_CERT_FILE` → `CURL_CA_BUNDLE` → `REQUESTS_CA_BUNDLE` wins (cached per process). Import-time compat shim: when `SSL_CERT_FILE` and `CURL_CA_BUNDLE` are unset and `REQUESTS_CA_BUNDLE` is set, its value is copied into `SSL_CERT_FILE` | ✔ | n/a | n/a |
| `tls.ca_bundle` | `CURL_CA_BUNDLE` | path | — | non-empty path | ↑ (second in chain) | ✔ | n/a | n/a |
| `tls.ca_bundle_requests` | `REQUESTS_CA_BUNDLE` | path | — | non-empty path | ↑ (third in chain; `requests`-era compat) | ✔ | n/a | n/a |

Go and Rust configure TLS per-client in code (custom HTTP client / rustls); they MUST NOT grow env-driven TLS keys outside this registry.

### Client settings group

Environment names take a prefix, default `OIDC_` (e.g. `OIDC_CLIENT_ID`). The group validates **as a unit** in strict mode (see Group Rules).

| Logical key | Env name | Type | Default | Notes | Secret |
|---|---|---|---|---|---|
| `client.discovery_url` | `{prefix}DISCOVERY_URL` | URL | — | **required**; https-only per existing discovery policy | no |
| `client.id` | `{prefix}CLIENT_ID` | string | — | **required** | no |
| `client.secret` | `{prefix}CLIENT_SECRET` | string | — | required iff the client-auth method in use needs one | **yes** |
| `client.scope` | `{prefix}SCOPE` | string | `openid profile email` | | no |
| `client.audience` | `{prefix}AUDIENCE` | string | value of `client.id` | | no |
| `client.redirect_uri` | `{prefix}REDIRECT_URI` | URL | `""` | required by flows that use it | no |
| `client.post_login_redirect` | `{prefix}POST_LOGIN_REDIRECT` | string | `/` | | no |
| `client.post_logout_redirect` | `{prefix}POST_LOGOUT_REDIRECT` | string | `/` | | no |
| `client.excluded_paths` | `{prefix}EXCLUDED_PATHS` | string list | `/docs, /openapi.json, /health` | comma-split, items trimmed, empties dropped | no |

Legacy semantics (today's `fastapi-identity-model` `OIDCSettings.from_env`): empty string for a required key raises `ValueError("Missing required env var …")` — i.e. legacy already treats empty-as-missing for required keys; optional keys fall back to the defaults above; `audience` defaults to `client_id` post-construction.

**Group Rules (strict mode):**

- When the client group is **requested** (a client-group-consuming construction), `client.discovery_url` and `client.id` are each required — each missing one → `CFG-001`.
- When the client group is **not requested**, any client-group key yielded by resolution without `client.discovery_url` → `CFG-002` naming group `client` (a fragment of a client is worse than none).
- `client.secret` absent while the selected client-auth method requires one → `CFG-002` naming group `client` and `client.secret`.

### Test tier (`TEST_*`)

Harness/integration keys — same resolution machinery, tier `test`, excluded from client-group validation, never read by library runtime code: `TEST_DISCO_ADDRESS`, `TEST_JWKS_ADDRESS`, `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET` (**secret**), `TEST_SCOPE`, `TEST_PKCE_PUBLIC_CLIENT_ID`, `TEST_REDIRECT_URI`, `TEST_OPAQUE_CLIENT_ID`, `TEST_OPAQUE_CLIENT_SECRET` (**secret**), `TEST_REQUIRE_LIVE` (bool), `TEST_REQUIRE_HTTPS` (bool). Registry rows for these carry no defaults (test config is always explicit). Their logical key IDs are mechanical: `test.` + the env name lowercased without the `TEST_` prefix (e.g. `TEST_REQUIRE_LIVE` → `test.require_live`).

## Error Taxonomy

Canonical error codes, allocated `CFG-001`–`CFG-099` (append-only, never renumbered):

| Code | Meaning |
|---|---|
| `CFG-001` | Missing required key |
| `CFG-002` | Incomplete key group |
| `CFG-003` | Invalid value (unparseable, out of domain, empty-string-present) |
| `CFG-004` | Source failure (a source raised/errored during resolution) |

**Error message format:** `<code>: <human description> (<logical key(s)>)` — e.g. `CFG-002: incomplete key group 'client' — missing: client.secret`.

- Messages MUST reference logical key IDs; the env name MAY appear as a remediation hint (e.g. `set OIDC_CLIENT_SECRET`).
- Messages MUST NOT contain any configured value — secret or not.
- All errors for one construction MUST be collected and reported together, ordered by registry order.

## Secret Redaction

- Secret-classified keys: `client.secret`, `TEST_CLIENT_SECRET`, `TEST_OPAQUE_CLIENT_SECRET` (see registry `Secret` columns). Classification lives here only; implementations MUST NOT maintain their own lists.
- The canonical redaction placeholder is exactly `<redacted>`.
- A secret-classified value MUST NOT appear in: error messages, native debug/display output (`Debug`/`Display`, `String()`/`GoString()`/`Format`, `repr`/`str`, `toString`/`toJSON`/inspect), any serialization the Config type offers, log output, or test fixtures.
- Redaction is a property of the Config/secret type — accessing the raw value MUST be an explicit accessor call, never an implicit string coercion.

## Conformance

The observable behaviors of this contract are enumerated as test cases in [`conformance/config.json`](conformance/config.json) (IDs `CFG-101`+: 1xx strict validation, 2xx legacy-mode equivalence, 3xx precedence/composition, 4xx redaction, 5xx source behavior), with shared input fixtures in [`test-fixtures/config/`](test-fixtures/config/).

`config.json` is currently a **prose contract** (no executable `vectors`), like most capability files: each language's implementation proves it with its own tests keyed to the `CFG-1xx` IDs. Promoting these cases to executable vectors requires, in the same change, extending `tools/spec_coverage_gate.py` and all language runners to per-capability coverage reports — the gate intentionally hard-fails when a second capability carries executable vectors, so partial promotion cannot silently go ungated.
