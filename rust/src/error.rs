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

    /// An ID Token failed one of the OpenID Connect ID-Token *profile* rules
    /// layered on top of standard JWT validation — the required `sub`, or the
    /// opt-in `azp` / `nonce` / `max_age` / `at_hash` / `c_hash` checks (OIDC
    /// Core 1.0 §3.1.3.7 / §3.3.2.11). Kept distinct from
    /// [`IdentityError::Validation`] (signature/iss/aud/exp) so a caller can
    /// tell a profile violation apart from a base-JWT failure. The profile
    /// fails **closed**: an unknown or missing header `alg` on an
    /// `at_hash`/`c_hash` check is this error, never a silently skipped check.
    #[error("id token validation error: {0}")]
    IdTokenValidation(String),

    /// An ID Token's `aud` carries values the client does not trust (OIDC Core
    /// 1.0 §3.1.3.7 step 3: the ID Token MUST be rejected if it contains
    /// additional audiences not trusted by the Client). Carries the untrusted
    /// `aud` values, in token order. The trusted set is the configured
    /// `client_id` plus any
    /// [`trusted_audiences`](crate::IdTokenValidationOptionsBuilder::trusted_audiences);
    /// with neither configured every `aud` value is untrusted (fail closed).
    #[error("id token validation error: ID token 'aud' contains untrusted audiences: {0:?}")]
    IdTokenUntrustedAudience(Vec<String>),

    /// [`validate_azp(true)`](crate::IdTokenValidationOptionsBuilder::validate_azp)
    /// was set without a `client_id`. OIDC Core 1.0 §3.1.3.7 step 5 compares a
    /// present `azp` with the client's own `client_id`, so with none configured
    /// the check cannot run as asked. A caller misconfiguration, not a token
    /// defect: it is reported before any claim is read (and, from
    /// [`validate_id_token`](crate::validate_id_token), before any JWKS fetch).
    #[error("configuration error: validate_azp requires a client_id to compare 'azp' against")]
    IdTokenAzpRequiresClientId,

    /// A caller-supplied claims validator (issue #603) rejected the token's
    /// claims. Carries a structured reason and the offending claim name (when
    /// the validator identified one), so a rejection surfaces *why* without
    /// parsing a message string. Kept distinct from [`IdentityError::Validation`]
    /// so a validation pipeline — and `combine_claims_validators` in `Any` mode —
    /// can tell a clean claims rejection from any other failure. Constructed from
    /// a [`crate::ClaimsValidationError`] via `From`.
    #[error("claims validation error: {reason}{}", .claim.as_deref().map(|c| format!(" (claim {c:?})")).unwrap_or_default())]
    ClaimsValidation {
        /// Why the claims were rejected.
        reason: String,
        /// The offending claim name, when the validator identified one.
        claim: Option<String>,
    },

    /// A DPoP proof failed verification (RFC 9449 §4.3, DPOP-006).
    ///
    /// `field` names the offending proof member — `"alg"`, `"typ"`, `"jwk"`,
    /// `"signature"`, `"jti"`, `"htm"`, `"htu"`, `"iat"`, `"ath"`, `"nonce"` — so
    /// a caller can tell a method/URI mismatch from a signature or structural
    /// failure without parsing a message string. Kept distinct from
    /// [`IdentityError::Validation`] because a rejected proof is a
    /// *sender-constraint* failure: the access token it accompanied may itself be
    /// perfectly valid, and the right response is a `DPoP` challenge rather than a
    /// plain token rejection.
    #[error("dpop proof verification failed{}: {reason}", .field.as_deref().map(|f| format!(" for {f:?}")).unwrap_or_default())]
    DpopVerification {
        /// The offending proof member, when one can be named.
        field: Option<String>,
        /// Why the proof was rejected.
        reason: String,
    },

    /// A client or builder was misconfigured (missing required fields).
    #[error("configuration error: {0}")]
    Configuration(String),

    /// A signing key with the requested `kid` was not found in the JWKS.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// A token with no `kid` could be verified by more than one key in the
    /// JWKS (JWKS-009). With no `kid`, the set is narrowed to signing keys
    /// (`use` absent or `sig`, RFC 7517 §4.2), then to keys whose `alg` is
    /// absent or equals the header `alg` (§4.4) and whose `kty` matches it,
    /// each step applied only when it leaves a key; `count` keys were left. Distinct from [`IdentityError::KeyNotFound`],
    /// which reports a `kid` that matches no key.
    #[error("ambiguous key: token has no kid and {count} keys could verify alg {alg:?} {kids:?}")]
    AmbiguousKey {
        /// The token header `alg`.
        alg: String,
        /// The ids of the remaining keys that have one.
        kids: Vec<String>,
        /// The number of remaining keys.
        count: usize,
    },

    /// The key resolved for a token declares an `alg` (RFC 7517 §4.4) other
    /// than the token header `alg`, so it is not used (JWKS-010). Applies
    /// whether the key was found by `kid` or selected without one; distinct
    /// from [`IdentityError::KeyNotFound`] and [`IdentityError::AmbiguousKey`].
    #[error("key algorithm mismatch: key {kid:?} declares alg {key_alg:?}, token alg is {alg:?}")]
    KeyAlgorithmMismatch {
        /// The resolved key's `kid` (empty when it has none).
        kid: String,
        /// The `alg` the key declares.
        key_alg: String,
        /// The token header `alg`.
        alg: String,
    },

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

    /// The UserInfo endpoint replied with a non-2xx status (OIDC Core 1.0
    /// §5.3.3). Carries the HTTP status and any `WWW-Authenticate` challenge a
    /// Bearer-protected resource returns to describe the failure (RFC 6750 §3).
    #[error("userinfo endpoint error: HTTP {status}{}", .www_authenticate.as_deref().map(|w| format!(": {w}")).unwrap_or_default())]
    UserInfo {
        /// The HTTP status of the error response.
        status: u16,
        /// The `WWW-Authenticate` challenge header, if present.
        www_authenticate: Option<String>,
        /// A short snippet of the response body for diagnostics.
        body: String,
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
        assert_eq!(
            IdentityError::AmbiguousKey {
                alg: "RS256".into(),
                kids: vec!["a".into(), "b".into()],
                count: 2,
            }
            .to_string(),
            r#"ambiguous key: token has no kid and 2 keys could verify alg "RS256" ["a", "b"]"#
        );
        assert_eq!(
            IdentityError::KeyAlgorithmMismatch {
                kid: "k1".into(),
                key_alg: "RS384".into(),
                alg: "RS256".into(),
            }
            .to_string(),
            r#"key algorithm mismatch: key "k1" declares alg "RS384", token alg is "RS256""#
        );
        assert_eq!(
            IdentityError::Configuration("missing token_endpoint".into()).to_string(),
            "configuration error: missing token_endpoint"
        );
    }

    #[test]
    fn is_std_error() {
        // Confirms IdentityError participates in the std error ecosystem.
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&IdentityError::Http("boom".into()));
    }
}
