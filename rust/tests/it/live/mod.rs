//! Tests that need a real OIDC provider.
//!
//! Every test here is `#[ignore]`-gated so a bare `cargo test` (no provider up)
//! stays green. The `integration-tests-rust` CI job boots the local `infra/`
//! node-oidc-provider (`:9010`), runs the unit suite, then runs these with
//! `cargo test -- --ignored` via `make test-integration-rust`, where every
//! missing prerequisite is a failure.
//!
//! Run locally:
//!
//! ```text
//! make infra-up
//! make test-integration-rust      # or: cd rust && cargo test -- --ignored
//! make infra-down
//! ```
//!
//! Provider selection follows the shared `TEST_*` convention documented on
//! [`crate::common::env`]. A missing prerequisite — an unreachable provider,
//! an unsourced profile, a client the profile does not define, an endpoint the
//! discovery document does not advertise — fails; only the OP-behaviour probes
//! in `id_token_validation` skip, with a reason.

mod claims_validation;
mod discovery;
mod dpop;
mod id_token_validation;
mod introspection;
mod jwks;
mod jwt_validation;
mod revocation;
mod spec_http_vectors;
mod token_client;
mod userinfo;
