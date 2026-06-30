# Getting Started

identity-model is a family of OIDC/OAuth2 client libraries that share one cross-language conformance specification. This page orients contributors to the foundation that currently exists.

## Prerequisites

| Tool | Version | For |
|------|---------|-----|
| Go | 1.22+ | `go/` implementation |
| Rust | 1.85+ (edition 2024) | `rust/` implementation |
| Docker + Compose | recent | shared OIDC provider in `infra/` |

## Layout at a Glance

- [`go/`](../go) — Go module, scaffolded (`go build ./... && go test ./...`).
- [`rust/`](../rust) — Rust crate, scaffolded (`cargo test`).
- [`spec/`](../spec) — the cross-language contract: capability matrix, conformance test definitions, fixtures.
- [`infra/`](../infra) — one `node-oidc-provider` all languages test against (`docker compose up -d`, port 9000).

## Typical Loop

```bash
# 1. Start the shared provider
cd infra && docker compose up -d && cd ..

# 2. Work in a language
cd go   && go test ./...   && cd ..
cd rust && cargo test      && cd ..

# 3. Keep the spec in sync — update spec/conformance/*.json and
#    spec/capabilities.md whenever a capability's behavior changes.
```

## Where Things Are Headed

The Core tier (Discovery, JWKS, JWT validation, Client Credentials, Authorization Code + PKCE, UserInfo) is specified in [`spec/capabilities.md`](../spec/capabilities.md) and implemented per language next. The production Python reference, `py-identity-model`, merges into `python/` at a later date.
