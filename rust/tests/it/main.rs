//! The integration-test binary for `rs-identity-model`.
//!
//! Cargo compiles each file directly under `tests/` into its own binary, each
//! linking the full dependency graph (reqwest, tokio, aws-lc). This crate
//! instead follows the single-binary convention: everything under `tests/it/`
//! is one crate, split into modules by *what a test needs to run*, so the
//! module path in `cargo test` output says which kind of test it is:
//!
//! | module          | needs                        | gate                       |
//! |-----------------|------------------------------|----------------------------|
//! | `conformance::` | the shared `../spec` fixtures | none — runs in `cargo test` |
//! | `local::`       | a server this binary starts   | none — runs in `cargo test` |
//! | `live::`        | a real OIDC provider          | `#[ignore]`; `cargo test -- --ignored` |
//!
//! `common::` holds the helpers those modules share: provider selection from
//! the `TEST_*` environment, the skip-or-fail rule, fixture-key loading and the
//! headless authorization-code driver. Inline unit tests stay next to the code
//! they cover under `src/`, as usual.
//!
//! Run one group by module path, for example:
//!
//! ```text
//! cargo test --test it conformance::
//! cargo test --test it local::dpop_resource_server::
//! cargo test --test it -- --ignored live::revocation::
//! ```

mod common;
mod conformance;
mod live;
mod local;
