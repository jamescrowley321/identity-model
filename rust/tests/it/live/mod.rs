//! Tests that need a real OIDC provider.
//!
//! Every test here is `#[ignore]`-gated so a bare `cargo test` (no provider up)
//! stays green. The `integration-tests-rust` CI job boots the local `infra/`
//! node-oidc-provider (`:9010`), runs the unit suite, then runs these with
//! `cargo test -- --ignored` under `TEST_REQUIRE_LIVE=1`, which turns every
//! infrastructure skip into a failure.
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
//! [`crate::common::env`]. A test that needs a capability the selected profile
//! lacks (an endpoint the discovery document does not advertise, a client type
//! the profile does not define) skips with a reason; an unreachable provider
//! is a skip locally and a failure under `TEST_REQUIRE_LIVE=1`.

mod claims_validation;
mod discovery;
mod dpop;
mod id_token_validation;
mod introspection;
mod jwks;
mod jwt_validation;
mod revocation;
mod token_client;
mod userinfo;
