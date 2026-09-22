//! Tests that stand up their own server or drive the crate's real pipeline
//! with locally minted tokens — no provider, no `#[ignore]`, run in every bare
//! `cargo test`.
//!
//! These sit between the inline unit tests (which mock at the function
//! boundary) and the `live::` suite (which needs infrastructure): the bytes
//! travel over a real socket or through the real validation path, but every
//! party to the exchange is in this process, so the tests are deterministic.

mod claims_validation;
mod dpop_resource_server;
mod token_exchange;
