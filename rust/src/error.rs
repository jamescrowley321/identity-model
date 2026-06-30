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
