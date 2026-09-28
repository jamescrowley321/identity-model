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
      "references": ["§4.3"]
    }
  ]
}
```

Besides `tests`, a capability file may carry `notes` (prose that says how its vectors are read:
input keys, defaults and conventions) and `required_fields` (the members a response MUST carry).
`required_fields` documents the requirement; runners enforce it only through the reject vectors
that omit those members. Each executable vector may carry a `name`, which labels it in runner
output and forms the Python parametrize id (`<id>-<name>`) that known gaps are keyed by.

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
| OIDC Discovery | `vectors/discovery.json` (DISC-001..010) — **executable vectors** | `test-fixtures/discovery/` |
| JWKS | `vectors/jwks.json` (JWKS-001..008) — **executable vectors** | `test-fixtures/jwks/` |
| Validation | `vectors/validation.json` (JWT-001..013) — **executable vectors** | `test-fixtures/validation/` |
| ID Token | `vectors/id-token.json` (IDT-001..011) — **executable vectors** | `test-fixtures/validation/` |
| Revocation | `vectors/revocation.json` (REV-001..005) — **executable vectors** | `test-fixtures/revocation/` |
| UserInfo | `vectors/userinfo.json` (UI-001..007) — **executable vectors** | `test-fixtures/userinfo/` |
| Token Introspection | `vectors/introspection.json` (INTR-001..006) — **executable vectors** | `test-fixtures/introspection/` |
| Token Exchange | `vectors/token-exchange.json` (EXCH-001..006) — **executable vectors** | `test-fixtures/token-exchange/` |
| Client Credentials | `vectors/client-credentials.json` (CC-001..006) — **executable vectors** | `test-fixtures/token/` |
| Authorization Code + PKCE | `vectors/authorization-code.json` (ACG-001..005) — **executable vectors** | `test-fixtures/authorization-code/` |
| DPoP | `vectors/dpop.json` (DPOP-001..008) — **executable vectors** (Go, Python) | `test-fixtures/dpop/` |

These capabilities carry executable vectors and a runner in **every language** that implements them:

| capability | cases | vectors | Go | Python | Rust |
| --- | --- | --- | --- | --- | --- |
| validation | 12 | 13 | `go/internal/conformance/validation_test.go` | `py/src/tests/unit/test_spec_conformance.py` | `rust/tests/spec_conformance.rs` |
| id-token | 11 | 30 | `go/internal/conformance/idtoken_conformance_test.go` | `py/src/tests/unit/test_id_token_conformance.py` | `rust/tests/spec_conformance_id_token.rs` |
| revocation | 5 | 7 | `go/internal/conformance/revocation_test.go` | `py/src/tests/unit/test_spec_revocation_conformance.py` | `rust/tests/spec_conformance_revocation.rs` |
| userinfo | 7 | 9 | `go/internal/conformance/userinfo_test.go` | `py/src/tests/unit/test_spec_userinfo_conformance.py` | `rust/tests/spec_conformance_userinfo.rs` |
| jwks | 8 | 15 | `go/internal/conformance/jwks_test.go` | `py/src/tests/unit/test_spec_jwks_conformance.py` | `rust/tests/spec_conformance_jwks.rs` |
| discovery | 10 | 12 | `go/internal/conformance/discovery_test.go` | `py/src/tests/unit/test_spec_discovery_conformance.py` | `rust/tests/spec_conformance_discovery.rs` |
| introspection | 6 | 11 | `go/internal/conformance/introspection_test.go` | `py/src/tests/unit/test_spec_introspection_conformance.py` | `rust/tests/spec_conformance_introspection.rs` |
| token-exchange | 6 | 14 | `go/internal/conformance/token_exchange_test.go` | `py/src/tests/unit/test_spec_token_exchange_conformance.py` | `rust/tests/spec_conformance_token_exchange.rs` |
| client-credentials | 6 | 8 | `go/internal/conformance/client_credentials_test.go` | `py/src/tests/unit/test_spec_client_credentials_conformance.py` | `rust/tests/spec_conformance_client_credentials.rs` |
| authorization-code | 5 | 6 | `go/internal/conformance/authorization_code_test.go` | `py/src/tests/unit/test_spec_authorization_code_conformance.py` | `rust/tests/spec_conformance_authorization_code.rs` |
| dpop | 8 | 27 | `go/internal/conformance/dpop_test.go` | `py/src/tests/unit/test_spec_dpop_conformance.py` | — (no Rust DPoP) |

Each runner runs in its language's ordinary unit suite and fails if any case in
the file is not executed, or runs fewer vectors than the spec carries for it.
A case a language does not meet yet is marked in that language's runner as an
expected failure (Python: `xfail(strict=True)`) with a linked issue, so the
suite fails once it starts passing.

### HTTP vectors

Capabilities that call an endpoint use HTTP vectors. Each vector carries:

- `input`: the call's arguments (capability-specific).
- `http`: canned responses keyed by request path: `status`, optional `headers`
  and optional `body_fixture` (relative to `test-fixtures/`). The runner serves them
  from a local mock server and replaces the literal `https://server.example.com`
  in a fixture with that server's base URL.
- `http_sequence` (optional): a list of responses per path; the n-th request to
  the path gets the n-th response and the last one repeats.
- `expect_request`: the request the client must send (`path`, `method`, and
  optional `headers` and `form`). An empty expected header or form value means
  it must be absent.
- `expect_calls` (optional): the exact number of requests per path.
- `expect`: `outcome` `accept` or `reject`; a reject carries the canonical
  `error` code, and optionally the HTTP `status`, the `fields` it names, and the
  OAuth `error_description` and `error_uri`; an
  accept may carry `result` fields compared by exact equality. A JWKS accept
  carries the resulting `keys`. UserInfo adds `www_authenticate` (the expected
  challenge; absent means the error response must carry no challenge) to a
  reject. UserInfo and introspection accepts may carry `claims` (typed standard
  members) and `custom_claims` (overflow-map entries).

A pure-logic case in an HTTP capability (e.g. PKCE) is a data vector with no
`http`: `input.operation` names the function and `expect.result` carries its
output. DPoP data vectors reference key-pair fixtures in `input.key`; a built
proof is compared by its decoded `header` and `payload`, with the generated
`jti` and `iat` checked only for presence and freshness.

The remaining capability file (`config.json`) is a prose contract today and
gains vectors + per-language runners when adopted.
