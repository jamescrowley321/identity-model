# Cross-Language Specification

This directory is the **single source of truth** for what every identity-model library must do. It is language-agnostic: no implementation code lives here.

## Contents

| Path | Purpose |
|------|---------|
| [`capabilities.md`](capabilities.md) | Canonical capability matrix with normative (MUST/SHOULD/MAY) behavior and per-language status |
| [`config.md`](config.md) | Configuration contract: canonical key registry, source/precedence resolution, validation modes, error taxonomy, secret redaction |
| `vectors/*.json` | Machine-readable, language-agnostic test-case definitions (one file per capability) |
| `test-fixtures/` | Shared input data (discovery documents, JWK sets, tokens) referenced by conformance tests |

## How It's Used

1. A capability is specified in `capabilities.md` with RFC references and normative requirements.
2. Its observable behaviors become test cases in `vectors/<capability>.json`. Each case carries the human contract (`id`, `title`, `given`, `when`, `then`, `references`) and, where expressible, one or more **executable `vectors`** (see below). A case that cannot be expressed as a static vector (e.g. a live JWKS refresh) sets `execution: "native"` with a `reason` and `native_test`.
3. Each language implements a **thin conformance runner** that loads these JSON files and executes the vectors against its own implementation — using `test-fixtures/` for static inputs and the shared provider in [`../infra`](../infra) for live integration. It is *thin* because the vectors carry both inputs and expected outcomes; only the mapping of canonical outcomes to that language's API/error types is per-language. Go's runner lives in [`../go/internal/conformance`](../go/internal/conformance).
4. CI gates merges: a language that marks a capability `implemented` in `capabilities.md` MUST pass its conformance vectors, and each runner asserts **full coverage** — every case id must be executed or explicitly `native`, so a language cannot silently skip a case.

## Conformance Test Definition Shape

```json
{
  "capability": "discovery",
  "spec": "OpenID Connect Discovery 1.0",
  "tests": [
    {
      "id": "DISC-003",
      "title": "Detect issuer mismatch",
      "given": "A discovery document whose issuer differs from the requested issuer",
      "when": "Discovery is invoked",
      "then": "An issuer-mismatch error is raised",
      "fixture": "discovery/issuer-mismatch.json",
      "references": ["§4.3"]
    }
  ]
}
```

### Executable vectors

A case becomes machine-checkable by adding `vectors`. Expected outcomes use **canonical, language-neutral** codes — `malformed`, `alg_none`, `unsupported_alg`, `signature`, `key_conversion`, `claim_validation` — that each runner maps to its own error type, so the expected result lives in the shared spec rather than in per-language test code. Time-based claims (`exp`/`nbf`/`iat`) are duration strings resolved against `options.now` at run time, so minted tokens stay fresh.

```json
{
  "id": "JWT-005",
  "title": "Reject expired token",
  "given": "...", "when": "...", "then": "...",
  "vectors": [
    {
      "token": { "signing_key": "fixture", "alg": "RS256",
                 "claims": { "iss": "...", "aud": "...", "exp": "-1h", "iat": "-2h" } },
      "options": { "now": "2023-11-14T22:13:20Z" },
      "expect": { "outcome": "reject", "error": "claim_validation", "claim": "exp" }
    }
  ]
}
```

See [`vectors/validation.json`](vectors/validation.json) for the full set.

## Current Coverage

| Capability | Conformance file | Fixtures |
|------------|-----------------|----------|
| OIDC Discovery | `vectors/discovery.json` (DISC-001..010) | `test-fixtures/discovery/` |
| JWKS | `vectors/jwks.json` (JWKS-001..007) | `test-fixtures/jwks/` |
| Validation | `vectors/validation.json` (JWT-001..013) — **executable vectors** | `test-fixtures/validation/` |

Validation is the first capability with executable vectors and a runner in
**every language**: Go `go/internal/conformance`, Python
`src/tests/unit/test_spec_conformance.py`, Rust `rust/tests/spec_conformance.rs`
— 12 executable cases + 1 native case each. Each runner asserts full coverage
internally, and the **cross-language coverage gate**
(`tools/spec_coverage_gate.py`, `make spec-coverage`, CI job
`spec-vector-coverage`) fails naming any missing `(language, vector-id)` pair —
no language can silently skip a case another executes. The remaining capability
files (client-credentials, authorization-code, userinfo, etc.) are prose
contracts today and gain vectors + per-language runners as each is adopted.
