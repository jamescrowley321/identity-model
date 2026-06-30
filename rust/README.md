# identity-model (Rust)

Rust implementation of the [identity-model](../README.md) OIDC/OAuth2 client library.

- **Crate:** `identity-model` (crates.io)
- **Edition:** 2024 · **MSRV:** 1.85
- **Add:** `cargo add identity-model`

## Module Layout

| Module | Purpose | Spec |
|--------|---------|------|
| `discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `token` | Client credentials, auth code, PKCE | RFC 6749 / 7636 |
| `userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |
| `error` | `IdentityError` — the crate error type | — |

## Design Conventions

- Async via `tokio`; HTTP via `reqwest` with `rustls`.
- JWT handling via the `jsonwebtoken` crate.
- Builder-pattern configuration; `Result<T, IdentityError>` everywhere (`thiserror`).
- Caches use `tokio::sync::RwLock` for thread-safe async access.

## Getting Started

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo run --example basic_setup
```

Integration tests run against the shared provider in [`../infra`](../infra).

> **Status:** Scaffolded. Implementation tracks the cross-language [`spec/`](../spec).
