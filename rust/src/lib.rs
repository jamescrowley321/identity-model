//! # identity-model
//!
//! Production-grade, RFC-compliant OIDC/OAuth2 **client** library for Rust —
//! part of the cross-language [identity-model](https://github.com/jamescrowley321/identity-model)
//! family that shares one conformance specification across languages.
//!
//! ## Status
//!
//! Foundation scaffold. Module surfaces and the error type are in place;
//! capability implementations (discovery, JWKS, JWT validation, token flows,
//! UserInfo) land per the cross-language `spec/`.
//!
//! ## Module Overview
//!
//! - [`discovery`] — OIDC Discovery client
//! - [`jwks`] — JWKS fetch + key resolution
//! - [`jwt`] — JWT signature + claims validation
//! - [`token`] — client credentials, authorization code, PKCE
//! - [`userinfo`] — UserInfo endpoint client
//! - [`error`] — the crate error type, [`IdentityError`]

pub mod discovery;
pub mod error;
pub mod jwks;
pub mod jwt;
pub mod token;
pub mod userinfo;

pub use discovery::{DiscoveryClient, DiscoveryClientBuilder, ProviderMetadata};
pub use error::IdentityError;
pub use jwks::{JsonWebKey, JsonWebKeySet, JwksClient, JwksClientBuilder};
pub use jwt::{
    Audience, Claims, DEFAULT_ALLOWED_ALGORITHMS, ValidationOptions, ValidationOptionsBuilder,
    validate_token, validate_token_with_jwks,
};
pub use token::{
    ClientAuthMethod, PkceChallenge, TokenClient, TokenClientBuilder, TokenResponse,
    authorization_url,
};
pub use userinfo::{Address, UserInfoClient, UserInfoClientBuilder, UserInfoResponse};

/// Convenience alias for results returned across the crate.
pub type Result<T> = std::result::Result<T, IdentityError>;
