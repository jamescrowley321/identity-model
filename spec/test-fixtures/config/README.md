# Configuration test fixtures

Shared, language-neutral inputs for the configuration conformance cases in
[`../../vectors/config.json`](../../vectors/config.json). Each fixture describes a
resolution scenario (or a parametrized family of them) and its expected outcome under the
contract in [`../../config.md`](../../config.md). `config.json` is a prose contract today (no
executable `vectors`), so these fixtures are the reference inputs each language's own tests key
to by case id (`CFG-1xx`…).

## Envelope

A fixture is a JSON object. It is **either** a single scenario (top-level `sources` /
`overrides` / `expect`) **or** a parametrized family (`cases: [ … ]`). Both share the same
top-level scalar fields; in a `cases[]` fixture those top-level scalars are defaults inherited
by every case, and each case may add its own inputs and carries its own `expect`.

```jsonc
{
  "description": "human summary",
  "mode": "strict" | "legacy",
  "group": "client" | null,
  "client_auth_method": "client_secret_basic" | "client_secret_post" | "none" | null,
  "client_prefix": "OIDC_",              // optional; EnvSource client-group prefix (default "OIDC_")
  "key": "logical.key",                  // optional; the single logical key a fixture pins

  // ── single-scenario shape ──
  "sources": [ <source>, … ],
  "overrides": { "logical.key": "raw value" },
  "expect": <expect>,

  // ── OR parametrized shape ──
  "cases": [ <case>, … ],

  "note": "optional free-text annotation"
}
```

### Top-level fields

- `description` — human summary; conventionally prefixed with the `CFG-…` case id it backs.
- `mode` — resolver mode under test (`strict` for the typed surface, `legacy` for
  behavior-preservation of today's reads).
- `group` — which key group the construction requests (`"client"` when the client group is
  required; `null` when it is not). Governs whether a missing client key is `CFG-001`
  (required, group requested) vs `CFG-002` (stray fragment, group not requested).
- `client_auth_method` — when the client group is requested, the selected client-auth
  method; `client_secret_basic`/`client_secret_post` require `client.secret`, `none` does not.
- `client_prefix` — optional; the EnvSource prefix applied to **client-group** env names
  (default `OIDC_`, e.g. `OIDC_CLIENT_ID`). Only client-group keys take the prefix.
- `key` — optional; the single logical key a fixture (or case) resolves, used by the legacy
  single-key fixtures and the strict bool-parsing fixture. When per-case values differ (as in
  `legacy-clamp-ttl.json`), `key` appears **on each case** instead of at the top level.

### Sources

`sources` is an ordered list, **highest precedence first**. Each source is one of:

- `{ "name": "label", "type": "env" | "map", "values": { … } }` — supplies raw string
  values. `type: "env"` keys are **environment variable names** (exercise `EnvSource`
  behaviors: prefix, alias, TLS chain). `type: "map"` keys are **logical key ids** (exercise
  generic-source behavior).
- `{ "name": "label", "type": "map", "raises": true }` — a source whose `resolve` operation
  errors. It supplies no values; it drives the fail-closed `CFG-004` path (see
  `source-error-failclosed.json`). `raises` and `values` are mutually exclusive.

`overrides` — explicit in-code overrides, keyed by logical key id; highest precedence of all
(short-circuits resolution for that key, ahead of every source).

### Cases (parametrized fixtures)

`cases: [ … ]` holds one entry per scenario. Every case carries its own `expect` and may
supply any subset of these inputs; anything omitted inherits the fixture's top-level value:

- `raw` — a single raw string value for the fixture/case `key` (shorthand for a one-key
  source). `null` means the key is **unset** (the source did not return it). Used by legacy
  single-key fixtures and strict bool parsing.
- `env` — a map of environment variable name → raw string; shorthand for a single
  `type: "env"` source.
- `sources` / `overrides` — same shapes as the top-level fields, scoped to this case.
- `key` — the logical key this case resolves (when it varies per case).
- `client_prefix` / `client_auth_method` / `group` / `mode` — per-case overrides of the
  corresponding top-level scalar.
- `note` — optional per-case annotation.

### Expect

`expect` carries one or more result assertions for a scenario. A fixture that fails closed uses
the `error` shape; a redaction fixture may combine `error` with `rendered_*` (see
`redaction-error-message.json`):

- `{ "config": { "logical.key": <typed value>, … } }` — successful strict construction; the
  listed keys must hold the given typed values.
- `{ "error": { "code": "CFG-00N", "keys": ["logical.key", …] } }` — strict construction
  fails closed with exactly this error, no `Config` produced. For a group error (`CFG-002`)
  the first entry in `keys` is the group name (`"client"`).
- `{ "error": { "errors": [ {code, keys}, … ], "ordered_by": "registry order" } }` — atomic
  collection: **all** errors for one construction reported together, registry-ordered.
- `{ "error": { "code": "CFG-004", "source": "<source name>" } }` — an erroring source
  (`raises: true`) fails construction closed and is named, never silently skipped.
- `{ "resolved": { "logical.key": <value> } }` — legacy-mode resolution result (single value).
- `{ "resolved_by_language": { "python": <v>, "go": <v>, "rust": <v> } }` — legacy-mode
  resolution when the languages diverge. A value of `"n/a"` means that language does not read
  the key today (config.md registry `n/a` convention), so it produces no value.
- `{ "rendered_includes": ["<redacted>"], "rendered_excludes": ["<sentinel>"] }` — redaction:
  rendered/serialized/logged output must include the placeholder and exclude the sentinel value.

A `note` field may appear inside `expect` (and inside a case, or at the fixture top level) as a
free-text annotation; it is never load-bearing.

## Fixture shapes in this directory

- **Single scenario** (top-level `sources`/`overrides`/`expect`): `strict-defaults`,
  `strict-empty-string`, `strict-invalid-url`, `strict-invalid-value`, `strict-missing-required`,
  `strict-missing-secret`, `strict-partial-group`, `strict-zero-unbounded`,
  `precedence-default-fallback`, `precedence-override-wins`, `precedence-source-order`,
  `redaction-debug`, `redaction-serialized`, `redaction-error-message`, `redaction-log`,
  `source-over-return`, `source-error-failclosed`.
- **Parametrized `cases[]`**: `strict-bool-parsing`, `strict-collected-errors` (single
  scenario but multi-error `expect`), `precedence-alias-within-source`, `precedence-env-last`,
  `precedence-client-prefix`, `legacy-alias-retry`, `legacy-clamp-ttl`, `legacy-kid-miss-cooldown`,
  `legacy-ssl-chain`, `legacy-cache-entries-divergence`, `legacy-disco-cache-entries-divergence`.

Fixtures are illustrative reference inputs, not a wire format; a language runner that later
executes these promotes the relevant cases to `vectors` in `config.json` (and must extend
`tools/spec_coverage_gate.py` + every runner to per-capability coverage in the same change).
