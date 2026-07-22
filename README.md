# identity-model

Production-grade, RFC-compliant OIDC/OAuth2 **client** libraries across multiple languages, sharing one cross-language conformance specification.

Inspired by the design philosophy of [Duende Software's IdentityModel](https://github.com/IdentityModel/IdentityModel) (.NET) — clean abstractions, comprehensive RFC coverage, and a developer experience that makes complex protocols accessible — adapted idiomatically for each target language. This is an "inspired by," not an affiliation; full credit to Duende for establishing the patterns.

> **Status:** Foundation / scaffolding. This repository currently stands up the monorepo structure, shared conformance spec, and shared test infrastructure. Core-tier implementations land per-language next. The production Python reference implementation, [`py-identity-model`](https://github.com/jamescrowley321/py-identity-model), will be merged into `python/` at a later date.

## Language Matrix

| Language | Package | Registry | Import | Status |
|----------|---------|----------|--------|--------|
| Python | `py-identity-model` | PyPI | `from py_identity_model import ...` | Reference impl (separate repo, merges later) |
| Go | `github.com/jamescrowley321/identity-model/go` | Go modules | `import ".../identity-model/go/pkg/discovery"` | Scaffolded |
| Rust | `identity-model-rs` | crates.io | `use identity_model::discovery::...` | Scaffolded |
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
├── infra/              # Shared test infra (node-oidc-provider + IdentityServer)
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
| Infra | `make infra-up` (node-oidc-provider `:9000`, IdentityServer `:9001`) |
| Integration | `make test-integration-local` (full local provider matrix) |

## Versioning

While the libraries are pre-stable, each language publishes **`0.0.x`** releases. Per [SemVer](https://semver.org/), `0.0.x` carries **no API-stability guarantees** — any release may contain breaking changes. We stay on `0.0.x` deliberately until the Core tier is implemented and conformance-passing in a language, then graduate that language toward `0.x`/`1.0`.

- **Versioning is independent per language** — Go and Rust advance their own `0.0.x` lines; they are not lock-stepped.
- **Rust** (`identity-model-rs` on crates.io; imported as `identity_model`): the `version` in `rust/Cargo.toml`.
- **Go** (`github.com/jamescrowley321/identity-model/go`): released via git tags. Because the module lives in a subdirectory, tags are prefixed — `go/v0.0.x`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
