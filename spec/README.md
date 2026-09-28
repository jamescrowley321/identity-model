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
2. Its observable behaviors become test cases in `vectors/<capability>.json`. Each case carries the human contract (`id`, `title`, `given`, `when`, `then`, `references`) and, where expressible, one or more **executable `vectors`** (see below).
3. Each language implements a **thin conformance runner** that loads these JSON files and executes the vectors against its own implementation — using `test-fixtures/` for static inputs and the shared provider in [`../infra`](../infra) for live integration. It is *thin* because the vectors carry both inputs and expected outcomes; only the mapping of canonical outcomes to that language's API/error types is per-language. Go's runner lives in [`../go/internal/conformance`](../go/internal/conformance).
4. CI gates merges: a language that marks a capability `implemented` in `capabilities.md` MUST pass its conformance vectors, and each runner asserts **full coverage** — every case id must be executed, so a language cannot silently skip a case.

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

These capabilities carry executable vectors and a runner in **every language**:

| capability | cases | vectors | Go | Python | Rust |
| --- | --- | --- | --- | --- | --- |
| validation | 12 | 13 | `go/internal/conformance/validation_test.go` | `py/src/tests/unit/test_spec_conformance.py` | `rust/tests/spec_conformance.rs` |
| id-token | 11 | 30 | `go/internal/conformance/idtoken_conformance_test.go` | `py/src/tests/unit/test_id_token_conformance.py` | `rust/tests/spec_conformance_id_token.rs` |
| revocation | 5 | 7 | `go/internal/conformance/revocation_test.go` | `py/src/tests/unit/test_spec_revocation_conformance.py` | `rust/tests/spec_conformance_revocation.rs` |

Each runner runs in its language's ordinary unit suite and fails if any case in
the file is not executed, or runs fewer vectors than the spec carries for it.
A case a language does not meet yet is marked in that language's runner as an
expected failure (Python: `xfail(strict=True)`) with a linked issue, so the
suite fails once it starts passing.

### HTTP vectors

Capabilities that call an endpoint use HTTP vectors. Each vector carries:

- `input`: the call's arguments (capability-specific).
- `http`: canned responses keyed by request path: `status` and optional
  `body_fixture` (relative to `test-fixtures/`). The runner serves them
  from a local mock server and replaces the literal `https://server.example.com`
  in a fixture with that server's base URL.
- `expect_request`: the request the client must send (`path`, `method`, and
  optional `headers` and `form`).
- `expect`: `outcome` `accept` or `reject`; a reject carries the canonical OAuth
  `error` code and HTTP `status`.

The remaining capability files
(client-credentials, authorization-code, userinfo, etc.) are prose contracts
today and gain vectors + per-language runners as each is adopted.
