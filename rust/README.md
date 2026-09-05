# identity-model (Rust)

A native Rust library for OpenID Connect and OAuth 2.0 clients: discovery,
JWKS retrieval and key resolution, JWT validation, and the token and UserInfo
endpoints.

- **Crate:** [`rs-identity-model`](https://crates.io/crates/rs-identity-model) on crates.io
- **Edition:** 2024 · **MSRV:** 1.96
- **Install:** `cargo add rs-identity-model`

## Module Layout

| Module | Purpose | Spec |
|--------|---------|------|
| `discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `jwt` | JWT signature + claims validation, ID token validation, plus injectable/composable claims validators | RFC 7519 / 7515, OIDC Core 1.0 §3.1.3.7 |
| `token` | Client credentials, auth code, PKCE | RFC 6749 / 7636 |
| `introspection` | Token introspection client | RFC 7662 |
| `userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |
| `error` | `IdentityError` — the crate error type | — |

## Design Conventions

- Async via `tokio`; HTTP via `reqwest` with `rustls`.
- JWT handling via the `jsonwebtoken` crate.
- Builder-pattern configuration; `Result<T, IdentityError>` everywhere (`thiserror`).
- Caches use `tokio::sync::RwLock` for thread-safe async access.
- Security hardening: secrets are redacted from `Debug`/error output, `azp` and
  clock-skew are validated during JWT verification, and redirect-scheme downgrades
  are rejected.

## Getting Started

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo run --example basic_setup
cargo run --example combined_claims_validator
```

Integration tests run against the shared provider in [`../infra`](../infra)
(`make infra-up` from the repo root).

## Claims Validation (injectable policy)

After the signature, algorithm-allowlist, and registered-claim checks pass,
`validate_token` runs an optional caller-supplied *claims validator* over the
decoded claims — the hook an application uses to enforce its own policy (tenant
membership, custom scopes, role checks). The API is composable and portable
across the Python and Go libraries:

- `require_claims([...])` — every named claim must be present and non-empty.
- `require_claim_value(name, value)` — the claim must be present and equal `value`.
- `require_scopes([...])` — every scope must be granted via the `scope` (space
  delimited) or `scp` (array) claim; a malformed scope claim fails closed.
- `combine_claims_validators([...], CombineMode::All | Any)` — compose several
  validators (all-must-pass, or any-must-pass with aggregated reasons).
- `from_fn(|claims| ...)` — adapt an arbitrary closure into a validator.

A rejection surfaces as `IdentityError::ClaimsValidation { reason, claim }`,
carrying the offending claim without parsing a message string. Inject a validator
with `ValidationOptions::builder().claims_validator(...)`. See
[`examples/combined_claims_validator.rs`](examples/combined_claims_validator.rs)
for a runnable `combine` demonstration. Behavioural parity with the sibling
libraries is enforced by the shared vectors in
[`../spec/test-fixtures/claims-validation/vectors.json`](../spec/test-fixtures/claims-validation/vectors.json),
driven by `tests/claims_validation_conformance.rs`.

## Capabilities

The Core tier (discovery, JWKS, JWT validation including the OIDC ID-token
profile, client-credentials and authorization-code + PKCE, UserInfo) is
implemented, as is Extended token introspection (RFC 7662). Revocation, token
exchange, and DPoP are not yet implemented. Behavioral parity with the Python
and Go libraries is enforced by the cross-language conformance vectors in
[`../spec`](../spec).
