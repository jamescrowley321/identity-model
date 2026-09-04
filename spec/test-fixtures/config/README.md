# Configuration test fixtures

Shared, language-neutral inputs for the configuration conformance cases in
[`../../conformance/config.json`](../../conformance/config.json). Each fixture describes a
resolution scenario and its expected outcome under the contract in
[`../../config.md`](../../config.md). `config.json` is a prose contract today (no executable
`vectors`), so these fixtures are the reference inputs each language's own tests key to by
case id (`CFG-1xx`…).

## Schema

```json
{
  "description": "human summary",
  "mode": "strict" | "legacy",
  "group": "client" | null,
  "client_auth_method": "client_secret_basic" | "none" | null,
  "sources": [
    { "name": "label", "type": "env" | "map", "values": { "KEY": "raw string" } }
  ],
  "overrides": { "logical.key": "value" },
  "expect": { ... }
}
```

- `mode` — resolver mode under test (`strict` for the typed surface, `legacy` for
  behavior-preservation of today's reads).
- `group` — which key group the construction requests (`"client"` when the client group is
  required; `null` when it is not). Governs whether a missing client key is `CFG-001`
  (required, group requested) vs `CFG-002` (stray fragment, group not requested).
- `client_auth_method` — when the client group is requested, the selected client-auth
  method; `client_secret_basic`/`client_secret_post` require `client.secret`, `none` does not.
- `sources` — ordered, **highest precedence first**. `type: "env"` values are keyed by
  environment variable name (exercise `EnvSource` behaviors: prefix, alias, TLS chain).
  `type: "map"` values are keyed by logical key id (exercise generic-source behavior).
- `overrides` — explicit in-code overrides, keyed by logical key id; highest precedence of all.
- `expect` — exactly one shape:
  - `{ "config": { "logical.key": <typed value> } }` — successful strict construction; the
    listed keys must hold the given typed values.
  - `{ "error": { "code": "CFG-00N", "keys": ["logical.key"] } }` or
    `{ "error": { "errors": [ {code, keys}, … ] } }` — strict construction fails closed with
    exactly these error(s), no `Config` produced.
  - `{ "resolved": { "logical.key": <value> } }` or `{ "resolved_by_language": { "python": {…}, "go": {…}, "rust": {…} } }`
    — legacy-mode resolution result (per-language when the languages diverge).
  - `{ "rendered_includes": ["<redacted>"], "rendered_excludes": ["<sentinel>"] }` — redaction:
    rendered/serialized output must include the placeholder and exclude the sentinel value.

Fixtures are illustrative reference inputs, not a wire format; a language runner that later
executes these promotes the relevant cases to `vectors` in `config.json` (and must extend
`tools/spec_coverage_gate.py` + every runner to per-capability coverage in the same change).
