//! Crate-wide error type for identity-model.

use thiserror::Error;

/// The unified error type returned by all fallible identity-model operations.
///
/// Every public function returns `Result<T, IdentityError>`. JWT and ID Token
/// validation failures are typed variants ([`MalformedToken`],
/// [`AlgorithmNone`], [`SignatureInvalid`], [`Expired`], [`IssuerMismatch`],
/// [`MissingClaim`], ...), so a caller tells them apart by matching, never by
/// message text. New variants may be added in minor releases.
///
/// [`MalformedToken`]: IdentityError::MalformedToken
/// [`AlgorithmNone`]: IdentityError::AlgorithmNone
/// [`SignatureInvalid`]: IdentityError::SignatureInvalid
/// [`Expired`]: IdentityError::Expired
/// [`IssuerMismatch`]: IdentityError::IssuerMismatch
/// [`MissingClaim`]: IdentityError::MissingClaim
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// An HTTP transport or status error.
    #[error("http error: {0}")]
    Http(String),

    /// A response body could not be deserialized as expected.
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// A document or request failed a validation rule outside JWT validation
    /// (a JWK, a JWKS or endpoint URI, a UserInfo response). JWT and ID Token
    /// validation never report this variant; they use the typed variants below.
    #[error("validation error: {0}")]
    Validation(String),

    /// The token is not a well-formed compact JWS (RFC 7515 §7.1): wrong
    /// segment count, a segment that is not base64url, a header that is not a
    /// JSON object or lacks `alg`, or a payload that is not a JSON object
    /// (RFC 7519 §7.2). Carries a diagnostic detail.
    #[error("malformed token: {0}")]
    MalformedToken(String),

    /// The token uses the unsecured `none` algorithm (RFC 7519 §6), which is
    /// always rejected, before any key resolution.
    #[error("unsecured token with algorithm \"none\" is rejected")]
    AlgorithmNone,

    /// The token header `alg` is not in the configured allowlist (or is not a
    /// supported asymmetric algorithm), so it is rejected before signature
    /// verification (algorithm-confusion defence).
    #[error("unsupported or disallowed algorithm {alg:?}")]
    AlgorithmNotAllowed {
        /// The token header `alg`.
        alg: String,
    },

    /// The JWS signature does not verify under the resolved key (RFC 7515
    /// §5.2).
    #[error("signature verification failed")]
    SignatureInvalid,

    /// The resolved JWK cannot be turned into a verification key: an
    /// unsupported `kty` or curve, unusable key material, or a key whose
    /// family cannot verify the token's `alg`.
    #[error("convert key {kid:?}: {reason}")]
    KeyConversion {
        /// The key's `kid` (empty when it has none).
        kid: String,
        /// Why the key cannot be used.
        reason: String,
    },

    /// A claim the validation requires is absent: `iat`, a required `exp` or
    /// `nbf`, a configured `required_claims` entry (absent, null or empty), or
    /// an ID Token profile claim — `sub`, `aud`, `azp` (multiple audiences),
    /// `auth_time` (with `max_age`), `at_hash` / `c_hash` (issued with the ID
    /// Token).
    #[error("claim {claim:?} invalid: required claim is missing")]
    MissingClaim {
        /// The claim name.
        claim: String,
    },

    /// A claim has the wrong JSON type or an out-of-range value (RFC 7519 §2,
    /// §4.1).
    #[error("claim {claim:?} invalid: {reason}")]
    MalformedClaim {
        /// The claim name.
        claim: String,
        /// What is wrong with its value.
        reason: String,
    },

    /// The token's `exp` has passed, beyond the allowed clock skew (RFC 7519
    /// §4.1.4).
    #[error("claim \"exp\" invalid: token expired at {exp} (now {now})")]
    Expired {
        /// The token's `exp`, seconds since the Unix epoch.
        exp: i64,
        /// The time it was checked against.
        now: i64,
    },

    /// The token's `nbf` is in the future, beyond the allowed clock skew (RFC
    /// 7519 §4.1.5).
    #[error("claim \"nbf\" invalid: token is not valid before {nbf} (now {now})")]
    NotYetValid {
        /// The token's `nbf`, seconds since the Unix epoch.
        nbf: i64,
        /// The time it was checked against.
        now: i64,
    },

    /// The token's `iss` is not the expected issuer (RFC 7519 §4.1.1, OIDC
    /// Core 1.0 §3.1.3.7 step 2). `actual` is `None` when the claim is absent.
    #[error("claim \"iss\" invalid: expected {expected:?}, got {actual:?}")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The token's `iss`, if any.
        actual: Option<String>,
    },

    /// The token's `aud` does not contain the expected audience (RFC 7519
    /// §4.1.3, OIDC Core 1.0 §3.1.3.7 step 3).
    #[error(
        "claim \"aud\" invalid: does not contain expected audience {expected:?} (token audiences: {actual:?})"
    )]
    AudienceMismatch {
        /// The configured audience.
        expected: String,
        /// The token's audiences, in token order.
        actual: Vec<String>,
    },

    /// The token does not carry the expected `nonce`: absent or different
    /// (OIDC Core 1.0 §3.1.3.7 step 11).
    #[error("claim \"nonce\" invalid: does not match the expected value")]
    NonceMismatch,

    /// An ID Token's `azp` is not the configured `client_id` (OIDC Core 1.0
    /// §3.1.3.7 step 5), with
    /// [`validate_azp`](crate::IdTokenValidationOptionsBuilder::validate_azp).
    #[error("claim \"azp\" invalid: expected {expected:?}, got {actual:?}")]
    AuthorizedPartyMismatch {
        /// The configured `client_id`.
        expected: String,
        /// The token's `azp`.
        actual: String,
    },

    /// An ID Token's `auth_time` is older than the requested `max_age` plus
    /// leeway (OIDC Core 1.0 §3.1.3.7 step 12).
    #[error(
        "claim \"auth_time\" invalid: {auth_time} is older than max_age {max_age}s (now {now})"
    )]
    MaxAgeExceeded {
        /// The token's `auth_time`, seconds since the Unix epoch.
        auth_time: i64,
        /// The requested `max_age`, in seconds.
        max_age: i64,
        /// The time it was checked against.
        now: i64,
    },

    /// An ID Token's `at_hash` or `c_hash` does not match the access token or
    /// authorization code (OIDC Core 1.0 §3.3.2.11). `claim` names which.
    #[error("claim {claim:?} invalid: does not match the bound value")]
    TokenHashMismatch {
        /// `at_hash` or `c_hash`.
        claim: String,
    },

    /// An `at_hash` / `c_hash` check cannot select a hash for the ID Token
    /// header `alg` (OIDC Core 1.0 §3.3.2.11): `None` when the header has no
    /// `alg`. The check fails closed rather than being skipped.
    #[error("unsupported ID token alg {alg:?} for at_hash/c_hash validation")]
    UnsupportedHashAlgorithm {
        /// The ID Token header `alg`, if any.
        alg: Option<String>,
    },

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

    /// [`validate_id_token`](crate::validate_id_token) was called with neither
    /// a profile [`client_id`](crate::IdTokenValidationOptionsBuilder::client_id)
    /// nor a base audience to default it from. OIDC Core 1.0 §3.1.3.7 step 3
    /// requires the ID Token to list the client as an audience, so with no
    /// client id the token cannot be bound to this client. A caller
    /// misconfiguration, reported before any JWKS fetch or token parse.
    #[error(
        "configuration error: ID token validation requires a client_id (or a base audience) to check 'aud' against"
    )]
    IdTokenClientIdRequired,

    /// A caller-supplied claims validator (issue #603) rejected the token's
    /// claims. Carries a structured reason and the offending claim name (when
    /// the validator identified one), so a rejection surfaces *why* without
    /// parsing a message string. Kept distinct from the built-in claim variants
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

    /// A signing key with the requested `kid` was not found in the JWKS. When
    /// resolving a key to verify a signature, a `use` `enc` key never matches
    /// (RFC 7517 §4.2); an empty `kid` means the token had no `kid` and the
    /// set holds no signing key (JWKS-011).
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// A token with no `kid` could be verified by more than one key in the
    /// JWKS (JWKS-009). With no `kid`, only signing keys (`use` absent or
    /// `sig`, RFC 7517 §4.2) are candidates; they are narrowed to keys whose
    /// `alg` is absent or equals the header `alg` (§4.4) and whose `kty`
    /// matches it, each of those two steps applied only when it leaves a key;
    /// `count` keys were left. Distinct from [`IdentityError::KeyNotFound`],
    /// which reports that no signing key matched.
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

    /// The key resolved to verify a token is below the strength floor: an RSA
    /// modulus under [`MIN_RSA_KEY_BITS`](crate::MIN_RSA_KEY_BITS) (RFC 7518
    /// §3.3) or an EC coordinate under
    /// [`MIN_EC_KEY_BITS`](crate::MIN_EC_KEY_BITS) (FAPI 2.0 Security Profile
    /// §5.4.1). The key is not skipped and the JWK Set is not refreshed.
    #[error(
        "weak key: {kty} verification key {kid:?} is {bits} bits; at least {min_bits} required"
    )]
    WeakKey {
        /// The key's `kid` (empty when it has none).
        kid: String,
        /// `RSA` or `EC`.
        kty: String,
        /// The key's size in bits.
        bits: usize,
        /// The floor it missed.
        min_bits: usize,
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
    fn jwt_variant_display_messages() {
        let cases = [
            (
                IdentityError::MalformedToken("empty header segment".into()),
                "malformed token: empty header segment",
            ),
            (
                IdentityError::AlgorithmNone,
                r#"unsecured token with algorithm "none" is rejected"#,
            ),
            (
                IdentityError::AlgorithmNotAllowed {
                    alg: "HS256".into(),
                },
                r#"unsupported or disallowed algorithm "HS256""#,
            ),
            (
                IdentityError::SignatureInvalid,
                "signature verification failed",
            ),
            (
                IdentityError::KeyConversion {
                    kid: "k1".into(),
                    reason: "RSA key: parameter \"n\" is empty".into(),
                },
                r#"convert key "k1": RSA key: parameter "n" is empty"#,
            ),
            (
                IdentityError::MissingClaim {
                    claim: "iat".into(),
                },
                r#"claim "iat" invalid: required claim is missing"#,
            ),
            (
                IdentityError::MalformedClaim {
                    claim: "exp".into(),
                    reason: "must be a numeric date".into(),
                },
                r#"claim "exp" invalid: must be a numeric date"#,
            ),
            (
                IdentityError::Expired { exp: 10, now: 20 },
                r#"claim "exp" invalid: token expired at 10 (now 20)"#,
            ),
            (
                IdentityError::NotYetValid { nbf: 30, now: 20 },
                r#"claim "nbf" invalid: token is not valid before 30 (now 20)"#,
            ),
            (
                IdentityError::IssuerMismatch {
                    expected: "https://op".into(),
                    actual: None,
                },
                r#"claim "iss" invalid: expected "https://op", got None"#,
            ),
            (
                IdentityError::AudienceMismatch {
                    expected: "rp".into(),
                    actual: vec!["other".into()],
                },
                r#"claim "aud" invalid: does not contain expected audience "rp" (token audiences: ["other"])"#,
            ),
            (
                IdentityError::NonceMismatch,
                r#"claim "nonce" invalid: does not match the expected value"#,
            ),
            (
                IdentityError::AuthorizedPartyMismatch {
                    expected: "rp".into(),
                    actual: "other".into(),
                },
                r#"claim "azp" invalid: expected "rp", got "other""#,
            ),
            (
                IdentityError::MaxAgeExceeded {
                    auth_time: 1,
                    max_age: 60,
                    now: 100,
                },
                r#"claim "auth_time" invalid: 1 is older than max_age 60s (now 100)"#,
            ),
            (
                IdentityError::TokenHashMismatch {
                    claim: "at_hash".into(),
                },
                r#"claim "at_hash" invalid: does not match the bound value"#,
            ),
            (
                IdentityError::UnsupportedHashAlgorithm { alg: None },
                "unsupported ID token alg None for at_hash/c_hash validation",
            ),
        ];
        for (err, want) in cases {
            assert_eq!(err.to_string(), want, "{err:?}");
        }
    }

    #[test]
    fn is_std_error() {
        // Confirms IdentityError participates in the std error ecosystem.
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&IdentityError::Http("boom".into()));
    }
}
