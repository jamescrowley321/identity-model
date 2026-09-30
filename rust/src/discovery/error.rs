//! Structured discovery failures for callers that need more than diagnostics.

use crate::IdentityError;
use thiserror::Error;

/// Failures from [`super::DiscoveryClient::discover_detailed`].
///
/// The legacy `discover` method retains its existing [`IdentityError`] variants.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The discovery endpoint returned a non-success status.
    #[error("unexpected HTTP status {status} from {endpoint}")]
    HttpStatus { status: u16, endpoint: String },
    /// The document's issuer differs from the requested issuer.
    #[error("issuer mismatch: requested {requested:?} but document declares {actual:?}")]
    IssuerMismatch { requested: String, actual: String },
    /// Required metadata fields are absent or empty, in spec order.
    #[error("discovery document from {endpoint} is missing required field(s): {}", .fields.join(", "))]
    MissingFields {
        fields: Vec<String>,
        endpoint: String,
    },
    /// The issuer scheme violates the client's HTTPS requirement.
    #[error("issuer {issuer:?} must use https (enable allow_http for development)")]
    HttpsRequired { issuer: String },
    /// Other failures retain their crate-wide type (including deserialization).
    #[error(transparent)]
    Other(#[from] IdentityError),
}

impl From<DiscoveryError> for IdentityError {
    fn from(error: DiscoveryError) -> Self {
        match error {
            DiscoveryError::Other(error) => error,
            error @ DiscoveryError::HttpStatus { .. } => Self::Http(error.to_string()),
            error => Self::Validation(error.to_string()),
        }
    }
}
