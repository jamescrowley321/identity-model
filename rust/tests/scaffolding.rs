//! Integration-level smoke test: confirms the crate compiles and its public
//! re-exports are reachable from a downstream crate's perspective.

use identity_model::{IdentityError, Result};

/// A trivial fallible operation exercising the crate's `Result` alias and
/// error type from an external-crate vantage point.
fn require_positive(n: u8) -> Result<u8> {
    if n > 0 {
        Ok(n)
    } else {
        Err(IdentityError::Validation("value must be positive".into()))
    }
}

#[test]
fn public_reexports_accessible() {
    let err = IdentityError::Configuration("missing token_endpoint".into());
    assert!(err.to_string().contains("configuration error"));

    let val = require_positive(7).expect("7 is positive");
    assert_eq!(val, 7);

    assert!(require_positive(0).is_err());
}
