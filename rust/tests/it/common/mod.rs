//! Helpers shared by the integration-test modules. Nothing here is a test.
//!
//! Each submodule is one concern, so a test file imports only what it uses:
//!
//! * [`env`] — provider selection from the shared `TEST_*` environment
//!   convention and the skip-or-fail rule the live suite is gated on.
//! * [`live`] — talking to the provider `env` selected: discovery with a skip
//!   on unreachable, and a raw client-credentials token request.
//! * [`fixtures`] — the shared `../spec/test-fixtures/validation` signing key
//!   and a token minter for it.
//! * [`authcode`] — the headless authorization-code driver for
//!   node-oidc-provider's `devInteractions` (cookie jar + redirect follower).

pub mod authcode;
pub mod env;
pub mod fixtures;
pub mod live;
