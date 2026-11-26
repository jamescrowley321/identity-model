//! The one mapping from a library error to the reason class the runner checks
//! against `expected_modules.json` (the text before the first `:` of a recorded
//! error).
//!
//! Typed variants map directly. The crate reports most JWT claim failures as
//! `IdentityError::Validation` / `IdTokenValidation` naming the offending claim,
//! so those map by the claim name the crate reports. A failure that names no
//! claim (an unsecured or disallowed `alg`, a bad signature) is told apart by
//! facts about the token itself, never by the message prose.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs_identity_model::{Claims, DEFAULT_ALLOWED_ALGORITHMS, DiscoveryError, IdentityError};
use serde_json::Value;

/// A rejection reason class, as recorded in `error: "<reason>: <detail>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    InvalidIssuer,
    InvalidAudience,
    InvalidExpiration,
    InvalidIssuedAt,
    InvalidSubject,
    InvalidSignature,
    KeySelection,
    InvalidAlgorithm,
    AlgNone,
    NonceMismatch,
    InvalidAtHash,
    InvalidCHash,
    IdTokenValidation,
    IssuerMismatch,
    DiscoveryFailed,
    StateValidation,
    AuthorizationError,
    MissingCode,
    TokenExchange,
    MissingIdToken,
    UserinfoValidation,
}

impl Reason {
    /// The wire form of the reason class.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidAudience => "invalid_audience",
            Self::InvalidExpiration => "invalid_expiration",
            Self::InvalidIssuedAt => "invalid_issued_at",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidSignature => "invalid_signature",
            Self::KeySelection => "key_selection",
            Self::InvalidAlgorithm => "invalid_algorithm",
            Self::AlgNone => "alg_none",
            Self::NonceMismatch => "nonce_mismatch",
            Self::InvalidAtHash => "invalid_at_hash",
            Self::InvalidCHash => "invalid_c_hash",
            Self::IdTokenValidation => "id_token_validation",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::DiscoveryFailed => "discovery_failed",
            Self::StateValidation => "state_validation",
            Self::AuthorizationError => "authorization_error",
            Self::MissingCode => "missing_code",
            Self::TokenExchange => "token_exchange",
            Self::MissingIdToken => "missing_id_token",
            Self::UserinfoValidation => "userinfo_validation",
        }
    }
}

/// What the harness can tell about a rejected ID token without trusting it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenFacts {
    /// The protected header's `alg`, when the header decodes.
    pub alg: Option<String>,
    /// The payload decodes to a claims set the library accepts the shape of.
    pub claims_well_formed: bool,
    /// The library resolves a verification key for the token from the OP's JWKS.
    pub key_resolved: bool,
}

impl TokenFacts {
    /// Reads the header `alg` and checks the payload shape of a compact JWS.
    /// `key_resolved` starts false; the caller sets it after asking the JWKS client.
    pub fn inspect(token: &str) -> Self {
        let mut segments = token.trim().split('.');
        let (Some(header), Some(payload), Some(_), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Self::default();
        };
        let alg = decode_segment(header).and_then(|h| h.get("alg")?.as_str().map(str::to_owned));
        let claims_well_formed =
            decode_segment(payload).is_some_and(|p| Claims::from_json(p).is_ok());
        Self {
            alg,
            claims_well_formed,
            key_resolved: false,
        }
    }

    /// The header `kid` and `alg` the JWKS client resolves a key by.
    pub fn header_kid(token: &str) -> String {
        token
            .trim()
            .split('.')
            .next()
            .and_then(decode_segment)
            .and_then(|h| h.get("kid")?.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
}

fn decode_segment(segment: &str) -> Option<Value> {
    let raw = URL_SAFE_NO_PAD.decode(segment).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Classifies an ID token rejection.
pub fn classify_id_token(error: &IdentityError, facts: &TokenFacts) -> Reason {
    match error {
        IdentityError::AmbiguousKey { .. }
        | IdentityError::KeyNotFound(_)
        | IdentityError::KeyAlgorithmMismatch { .. }
        | IdentityError::WeakKey { .. } => Reason::KeySelection,
        IdentityError::IdTokenUntrustedAudience(_) => Reason::InvalidAudience,
        IdentityError::Validation(message) => match validation_claim(message) {
            Some(claim) => claim_reason(claim),
            None => unnamed_reason(facts),
        },
        IdentityError::IdTokenValidation(message) => {
            id_token_claim(message).map_or(Reason::IdTokenValidation, claim_reason)
        }
        _ => Reason::IdTokenValidation,
    }
}

/// Classifies a discovery failure.
pub fn classify_discovery(error: &DiscoveryError) -> Reason {
    match error {
        DiscoveryError::IssuerMismatch { .. } => Reason::IssuerMismatch,
        _ => Reason::DiscoveryFailed,
    }
}

/// The claim a `claim "<name>" invalid: …` validation error names.
fn validation_claim(message: &str) -> Option<&str> {
    message.strip_prefix("claim \"")?.split('"').next()
}

/// The claim an ID-Token-profile error names (`… 'sub' claim …`).
fn id_token_claim(message: &str) -> Option<&str> {
    let (_, rest) = message.split_once('\'')?;
    rest.split_once('\'').map(|(claim, _)| claim)
}

fn claim_reason(claim: &str) -> Reason {
    match claim {
        "iss" => Reason::InvalidIssuer,
        "aud" | "azp" => Reason::InvalidAudience,
        "exp" | "nbf" => Reason::InvalidExpiration,
        "iat" => Reason::InvalidIssuedAt,
        "sub" => Reason::InvalidSubject,
        "nonce" => Reason::NonceMismatch,
        "at_hash" => Reason::InvalidAtHash,
        "c_hash" => Reason::InvalidCHash,
        "alg" => Reason::InvalidAlgorithm,
        _ => Reason::IdTokenValidation,
    }
}

/// A validation failure naming no claim happened before the claims were read:
/// the algorithm gate, key conversion or the signature check.
fn unnamed_reason(facts: &TokenFacts) -> Reason {
    match facts.alg.as_deref() {
        Some(alg) if alg.eq_ignore_ascii_case("none") => Reason::AlgNone,
        Some(alg) if DEFAULT_ALLOWED_ALGORITHMS.contains(&alg) => {
            if facts.claims_well_formed && facts.key_resolved {
                Reason::InvalidSignature
            } else {
                Reason::IdTokenValidation
            }
        }
        _ => Reason::InvalidAlgorithm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn segment(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"))
    }

    fn token(header: &Value, payload: &Value) -> String {
        format!("{}.{}.c2ln", segment(header), segment(payload))
    }

    fn signed_facts() -> TokenFacts {
        TokenFacts {
            alg: Some("RS256".into()),
            claims_well_formed: true,
            key_resolved: true,
        }
    }

    fn validation(message: &str) -> IdentityError {
        IdentityError::Validation(message.into())
    }

    fn id_token(message: &str) -> IdentityError {
        IdentityError::IdTokenValidation(message.into())
    }

    #[test]
    fn claim_named_validation_errors_map_by_claim() {
        let cases = [
            (
                r#"claim "iss" invalid: expected "a", got "b""#,
                Reason::InvalidIssuer,
            ),
            (
                r#"claim "aud" invalid: does not contain expected audience"#,
                Reason::InvalidAudience,
            ),
            (
                r#"claim "iat" invalid: required claim is missing"#,
                Reason::InvalidIssuedAt,
            ),
            (
                r#"claim "exp" invalid: token expired at 1"#,
                Reason::InvalidExpiration,
            ),
            (
                r#"claim "nbf" invalid: token is not yet valid"#,
                Reason::InvalidExpiration,
            ),
            (
                r#"claim "nonce" invalid: nonce does not match expected value"#,
                Reason::NonceMismatch,
            ),
            (
                r#"claim "sub" invalid: required claim is missing or empty"#,
                Reason::InvalidSubject,
            ),
            (
                r#"claim "custom" invalid: required claim is missing or empty"#,
                Reason::IdTokenValidation,
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                classify_id_token(&validation(message), &signed_facts()),
                expected,
                "{message}"
            );
        }
    }

    #[test]
    fn id_token_profile_errors_map_by_claim() {
        let cases = [
            (
                "ID token missing required 'sub' claim",
                Reason::InvalidSubject,
            ),
            (
                "ID token missing required 'aud' claim",
                Reason::InvalidAudience,
            ),
            (
                "ID token 'nonce' claim does not match the expected value",
                Reason::NonceMismatch,
            ),
            (
                "ID token 'azp' claim does not match the configured client_id",
                Reason::InvalidAudience,
            ),
            (
                "ID token 'at_hash' claim does not match access_token",
                Reason::InvalidAtHash,
            ),
            (
                "ID token 'auth_time' is older than the permitted max_age",
                Reason::IdTokenValidation,
            ),
            ("no claim named here", Reason::IdTokenValidation),
        ];
        for (message, expected) in cases {
            assert_eq!(
                classify_id_token(&id_token(message), &signed_facts()),
                expected,
                "{message}"
            );
        }
    }

    #[test]
    fn typed_errors_map_directly() {
        let ambiguous = IdentityError::AmbiguousKey {
            alg: "RS256".into(),
            kids: vec!["a".into(), "b".into()],
            count: 2,
        };
        assert_eq!(
            classify_id_token(&ambiguous, &signed_facts()),
            Reason::KeySelection
        );
        assert_eq!(
            classify_id_token(&IdentityError::KeyNotFound("k".into()), &signed_facts()),
            Reason::KeySelection
        );
        assert_eq!(
            classify_id_token(
                &IdentityError::IdTokenUntrustedAudience(vec!["x".into()]),
                &signed_facts()
            ),
            Reason::InvalidAudience
        );
        assert_eq!(
            classify_id_token(&IdentityError::Http("boom".into()), &signed_facts()),
            Reason::IdTokenValidation
        );
    }

    #[test]
    fn unnamed_failures_are_told_apart_by_the_token() {
        let rejected = validation("rejected");
        let none = TokenFacts {
            alg: Some("none".into()),
            ..TokenFacts::default()
        };
        assert_eq!(classify_id_token(&rejected, &none), Reason::AlgNone);
        let hs = TokenFacts {
            alg: Some("HS256".into()),
            ..signed_facts()
        };
        assert_eq!(classify_id_token(&rejected, &hs), Reason::InvalidAlgorithm);
        assert_eq!(
            classify_id_token(&rejected, &TokenFacts::default()),
            Reason::InvalidAlgorithm
        );
        assert_eq!(
            classify_id_token(&rejected, &signed_facts()),
            Reason::InvalidSignature
        );
        let unresolved = TokenFacts {
            key_resolved: false,
            ..signed_facts()
        };
        assert_eq!(
            classify_id_token(&rejected, &unresolved),
            Reason::IdTokenValidation
        );
        let bad_claims = TokenFacts {
            claims_well_formed: false,
            ..signed_facts()
        };
        assert_eq!(
            classify_id_token(&rejected, &bad_claims),
            Reason::IdTokenValidation
        );
    }

    #[test]
    fn discovery_errors_keep_the_issuer_mismatch_type() {
        let mismatch = DiscoveryError::IssuerMismatch {
            requested: "https://a/".into(),
            actual: "https://b/".into(),
        };
        assert_eq!(classify_discovery(&mismatch), Reason::IssuerMismatch);
        let status = DiscoveryError::UnexpectedStatus {
            status: 500,
            endpoint: "https://a/.well-known/openid-configuration".into(),
        };
        assert_eq!(classify_discovery(&status), Reason::DiscoveryFailed);
    }

    #[test]
    fn inspect_reads_header_and_payload_shape() {
        let jwt = token(
            &json!({"alg": "RS256", "kid": "k1"}),
            &json!({"iss": "https://op/", "sub": "s", "aud": "c"}),
        );
        assert_eq!(
            TokenFacts::inspect(&jwt),
            TokenFacts {
                alg: Some("RS256".into()),
                claims_well_formed: true,
                key_resolved: false,
            }
        );
        assert_eq!(TokenFacts::header_kid(&jwt), "k1");

        let bad_aud = token(&json!({"alg": "RS256"}), &json!({"aud": 5}));
        assert_eq!(
            TokenFacts::inspect(&bad_aud),
            TokenFacts {
                alg: Some("RS256".into()),
                claims_well_formed: false,
                key_resolved: false,
            }
        );
        assert_eq!(TokenFacts::header_kid(&bad_aud), "");
        assert_eq!(TokenFacts::inspect("not-a-jwt"), TokenFacts::default());
        assert_eq!(TokenFacts::inspect("a.b.c.d"), TokenFacts::default());
    }

    #[test]
    fn reason_wire_forms_match_the_manifest_classes() {
        let cases = [
            (Reason::InvalidIssuer, "invalid_issuer"),
            (Reason::InvalidAudience, "invalid_audience"),
            (Reason::InvalidIssuedAt, "invalid_issued_at"),
            (Reason::InvalidSubject, "invalid_subject"),
            (Reason::NonceMismatch, "nonce_mismatch"),
            (Reason::AlgNone, "alg_none"),
            (Reason::InvalidSignature, "invalid_signature"),
            (Reason::KeySelection, "key_selection"),
            (Reason::UserinfoValidation, "userinfo_validation"),
            (Reason::IssuerMismatch, "issuer_mismatch"),
        ];
        for (reason, wire) in cases {
            assert_eq!(reason.as_str(), wire);
        }
    }
}
