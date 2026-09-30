//! Typed discovery failures.

use crate::IdentityError;
use thiserror::Error;

/// Failures from [`super::DiscoveryClient::discover`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The discovery endpoint returned a non-success status (DISC-006).
    #[error("unexpected HTTP status {status} from {endpoint}")]
    UnexpectedStatus { status: u16, endpoint: String },
    /// The body is not a JSON provider metadata document (DISC-007).
    #[error("invalid discovery document from {endpoint}: {reason}")]
    InvalidJson { endpoint: String, reason: String },
    /// Required metadata fields are absent or empty, in spec order (DISC-008).
    #[error("discovery document from {endpoint} is missing required field(s): {}", .fields.join(", "))]
    MissingFields {
        fields: Vec<String>,
        endpoint: String,
    },
    /// The document's issuer differs from the requested issuer (DISC-003).
    #[error("issuer mismatch: requested {requested:?} but document declares {actual:?}")]
    IssuerMismatch { requested: String, actual: String },
    /// The issuer scheme violates the client's HTTPS requirement (DISC-010).
    #[error("issuer {issuer:?} must use https (enable allow_http for development)")]
    HttpsRequired { issuer: String },
    /// Transport failures, oversized bodies and an empty issuer URL.
    #[error(transparent)]
    Other(#[from] IdentityError),
}

impl From<DiscoveryError> for IdentityError {
    fn from(error: DiscoveryError) -> Self {
        match error {
            DiscoveryError::Other(error) => error,
            error @ DiscoveryError::UnexpectedStatus { .. } => Self::Http(error.to_string()),
            error @ DiscoveryError::InvalidJson { .. } => Self::Deserialization(error.to_string()),
            error => Self::Validation(error.to_string()),
        }
    }
}
