# identity-model

Production-grade, RFC-compliant OIDC/OAuth2 **client** libraries across multiple languages, sharing one cross-language conformance specification.

Inspired by the design philosophy of [Duende Software's IdentityModel](https://github.com/IdentityModel/IdentityModel) (.NET) — clean abstractions, comprehensive RFC coverage, and a developer experience that makes complex protocols accessible — adapted idiomatically for each target language. This is an "inspired by," not an affiliation; full credit to Duende for establishing the patterns.

> **Status:** Foundation / scaffolding. This repository currently stands up the monorepo structure, shared conformance spec, and shared test infrastructure. Core-tier implementations land per-language next. The production Python reference implementation, [`py-identity-model`](https://github.com/jamescrowley321/py-identity-model), will be merged into `python/` at a later date.

## Language Matrix

| Language | Package | Registry | Import | Status |
|----------|---------|----------|--------|--------|
| Python | `py-identity-model` | PyPI | `from py_identity_model import ...` | Reference impl (separate repo, merges later) |
| Go | `github.com/jamescrowley321/identity-model/go` | Go modules | `import ".../identity-model/go/pkg/discovery"` | Scaffolded |
| Rust | `identity-model` | crates.io | `use identity_model::discovery::...` | Scaffolded |
| Node/TS | `@identity-model/node` | npm | `import { ... } from '@identity-model/node'` | Planned |

## Capability Tiers

| Tier | Capabilities |
|------|--------------|
| **Core** | OIDC Discovery · JWKS retrieval + caching · JWT validation · Client Credentials · Authorization Code + PKCE · UserInfo |
| **Extended** | Token Introspection · Token Revocation · Token Exchange · DPoP |
| **Advanced** | PAR · RAR · CIBA · JARM |

See [`spec/capabilities.md`](spec/capabilities.md) for the canonical capability matrix and per-language status.

## Repository Layout

```
identity-model/
├── go/                 # Go implementation (github.com/jamescrowley321/identity-model/go)
├── rust/               # Rust implementation (crate: identity-model)
├── spec/               # Cross-language conformance specification
│   ├── capabilities.md # Canonical capability matrix
│   ├── conformance/    # Machine-readable, language-agnostic test definitions
│   └── test-fixtures/  # Shared fixtures (discovery docs, JWKs, tokens)
├── infra/              # Shared test infrastructure (node-oidc-provider)
├── docs/               # Cross-language documentation
└── .github/workflows/  # Path-filtered CI matrix
```

## Conformance Model

Each capability has a language-agnostic definition in `spec/conformance/*.json`. Every language binding implements a test runner that loads these definitions and executes them against its own implementation, run against the shared `infra/` provider. CI enforces that a language claiming a capability "implemented" passes the shared conformance tests for it.

## Getting Started

| Language | Commands |
|----------|----------|
| Go | `cd go && go build ./... && go test ./...` |
| Rust | `cd rust && cargo check && cargo test` |
| Infra | `cd infra && docker compose up -d` (shared OIDC provider on `:9000`) |

## License

Apache License 2.0 — see [LICENSE](LICENSE).
