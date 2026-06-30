# Cross-Language Specification

This directory is the **single source of truth** for what every identity-model language binding must do. It is language-agnostic: no implementation code lives here.

## Contents

| Path | Purpose |
|------|---------|
| [`capabilities.md`](capabilities.md) | Canonical capability matrix with normative (MUST/SHOULD/MAY) behavior and per-language status |
| `conformance/*.json` | Machine-readable, language-agnostic test-case definitions (one file per capability) |
| `test-fixtures/` | Shared input data (discovery documents, JWK sets, tokens) referenced by conformance tests |

## How It's Used

1. A capability is specified in `capabilities.md` with RFC references and normative requirements.
2. Its observable behaviors become test cases in `conformance/<capability>.json` (each with `id`, `title`, `given`, `when`, `then`, `references`, and optional `fixture`).
3. Each language implements a **conformance test runner** that loads these JSON files and executes the cases against its own implementation — using `test-fixtures/` for static inputs and the shared provider in [`../infra`](../infra) for live integration.
4. CI gates merges: a language that marks a capability `implemented` in `capabilities.md` MUST pass its conformance tests.

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

## Current Coverage

| Capability | Conformance file | Fixtures |
|------------|-----------------|----------|
| OIDC Discovery | `conformance/discovery.json` (DISC-001..010) | `test-fixtures/discovery/` |
| JWKS | `conformance/jwks.json` (JWKS-001..007) | `test-fixtures/jwks/` |

Validation, client-credentials, authorization-code, and userinfo definitions land alongside their implementations.
