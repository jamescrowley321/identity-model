//! OIDC Discovery client: fetch, validate, and cache provider metadata.
//!
//! [`DiscoveryClient`] requests `{issuer}/.well-known/openid-configuration`,
//! validates the required metadata fields and the issuer match, and caches the
//! result with a configurable TTL backed by a [`tokio::sync::RwLock`]. Behaviour
//! is proven against the cross-language conformance IDs `DISC-001`..`DISC-010`
//! in `spec/conformance/discovery.json`.
//!
//! RFC / spec references: OpenID Connect Discovery 1.0 §3, §4.
//!
//! ```no_run
//! # async fn run() -> identity_model::Result<()> {
//! use identity_model::DiscoveryClient;
//!
//! let client = DiscoveryClient::new();
//! let metadata = client.discover("https://accounts.example.com").await?;
//! assert!(!metadata.jwks_uri.is_empty());
//! # Ok(())
//! # }
//! ```

mod cache;
mod client;
mod metadata;

pub use client::{DiscoveryClient, DiscoveryClientBuilder};
pub use metadata::ProviderMetadata;
