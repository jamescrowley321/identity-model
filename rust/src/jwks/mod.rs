//! JWKS client: fetch, cache, and resolve JSON Web Keys by `kid`.
//!
//! [`JwksClient`] fetches the JWK Set at a `jwks_uri` (typically the `jwks_uri`
//! from discovery), validates each key's required parameters, and caches the set
//! with a configurable TTL backed by a [`tokio::sync::RwLock`]. A key is resolved
//! by its `kid` against the cached set ([`JsonWebKeySet::resolve_key`]); a miss
//! can force one refresh and retry to support key rotation
//! ([`JwksClient::resolve_key`] / [`JwksClient::force_refresh`]). Behaviour is
//! proven against the cross-language conformance IDs `JWKS-001`..`JWKS-007` in
//! `spec/conformance/jwks.json`.
//!
//! RFC / spec references: RFC 7517 (JWK), RFC 7518 (JWA).
//!
//! ```no_run
//! # async fn run() -> identity_model::Result<()> {
//! use identity_model::JwksClient;
//!
//! let client = JwksClient::new();
//! let key_set = client.fetch("https://accounts.example.com/jwks").await?;
//! let key = key_set.resolve_key("rsa-sig-key")?;
//! assert_eq!(key.kty, "RSA");
//! # Ok(())
//! # }
//! ```

mod cache;
mod client;
mod key;

pub use client::{JwksClient, JwksClientBuilder};
pub use key::{JsonWebKey, JsonWebKeySet};
