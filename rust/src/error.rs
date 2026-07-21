//! Crate-wide error type for identity-model.

use thiserror::Error;

/// The unified error type returned by all fallible identity-model operations.
///
/// Every public function returns `Result<T, IdentityError>`.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// An HTTP transport or status error.
    #[error("http error: {0}")]
    Http(String),

    /// A response body could not be deserialized as expected.
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// A token or document failed validation (signature, claims, issuer, etc.).
    #[error("validation error: {0}")]
    Validation(String),

    /// A client or builder was misconfigured (missing required fields).
    #[error("configuration error: {0}")]
    Configuration(String),

    /// A signing key with the requested `kid` was not found in the JWKS.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// The token endpoint replied with a non-2xx OAuth 2.0 error response
    /// (RFC 6749 §5.2).
    #[error("token endpoint error {error:?}{}: HTTP {status}", .description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    TokenEndpoint {
        /// The RFC 6749 §5.2 `error` code, e.g. `invalid_client`.
        error: String,
        /// The human-readable `error_description`, if present.
        description: Option<String>,
        /// The `error_uri` pointing at documentation, if present.
        error_uri: Option<String>,
        /// The HTTP status of the error response.
        status: u16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        assert_eq!(
            IdentityError::Validation("token expired".into()).to_string(),
            "validation error: token expired"
        );
        assert_eq!(
            IdentityError::KeyNotFound("abc".into()).to_string(),
            "key not found: abc"
        );
    }

    #[test]
    fn is_std_error() {
        // Confirms IdentityError participates in the std error ecosystem.
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&IdentityError::Http("boom".into()));
    }
}
