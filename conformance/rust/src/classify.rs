//! The one mapping from a library error to the reason class the runner checks
//! against `expected_modules.json` (the text before the first `:` of a recorded
//! error).
//!
//! Every error maps by its typed variant, never by message text. A missing or
//! malformed claim maps by the claim name the variant carries.

use rs_identity_model::{DiscoveryError, IdentityError};

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
    UserinfoFailed,
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
            Self::UserinfoFailed => "userinfo_failed",
        }
    }
}

/// Classifies an ID token rejection by the crate's typed error variant.
pub fn classify_id_token(error: &IdentityError) -> Reason {
    match error {
        IdentityError::AmbiguousKey { .. }
        | IdentityError::KeyNotFound(_)
        | IdentityError::KeyAlgorithmMismatch { .. }
        | IdentityError::WeakKey { .. } => Reason::KeySelection,
        IdentityError::AlgorithmNone => Reason::AlgNone,
        IdentityError::AlgorithmNotAllowed { .. }
        | IdentityError::UnsupportedHashAlgorithm { .. } => Reason::InvalidAlgorithm,
        IdentityError::SignatureInvalid => Reason::InvalidSignature,
        IdentityError::IssuerMismatch { .. } => Reason::InvalidIssuer,
        IdentityError::AudienceMismatch { .. }
        | IdentityError::IdTokenUntrustedAudience(_)
        | IdentityError::AuthorizedPartyMismatch { .. } => Reason::InvalidAudience,
        IdentityError::Expired { .. } | IdentityError::NotYetValid { .. } => {
            Reason::InvalidExpiration
        }
        IdentityError::NonceMismatch => Reason::NonceMismatch,
        IdentityError::MissingClaim { claim }
        | IdentityError::MalformedClaim { claim, .. }
        | IdentityError::TokenHashMismatch { claim } => claim_reason(claim),
        _ => Reason::IdTokenValidation,
    }
}

/// Classifies a UserInfo failure. Only a response the RP received and refused
/// is `userinfo_validation` (OIDC Core 1.0 §5.3.2 `sub` checks, §5.3.3 error
/// status), as the Python harness records it. A failure before the response
/// could be checked (transport, configuration, an undecodable body) is
/// `userinfo_failed`, so it can never pass a module expecting the `sub` check.
pub fn classify_userinfo(error: &IdentityError) -> Reason {
    match error {
        IdentityError::Validation(_) | IdentityError::UserInfo { .. } => Reason::UserinfoValidation,
        _ => Reason::UserinfoFailed,
    }
}

/// Classifies a discovery failure.
pub fn classify_discovery(error: &DiscoveryError) -> Reason {
    match error {
        DiscoveryError::IssuerMismatch { .. } => Reason::IssuerMismatch,
        _ => Reason::DiscoveryFailed,
    }
}

/// The reason for a missing or malformed claim, or a hash binding, by the
/// claim the crate names.
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
        _ => Reason::IdTokenValidation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rs_identity_model::{
        Claims, IdTokenValidationOptions, JsonWebKey, ValidationOptions, validate_id_token_claims,
        validate_token,
    };
    use serde_json::{Value, json};

    fn segment(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"))
    }

    fn token(header: &Value, payload: &Value) -> String {
        format!("{}.{}.c2ln", segment(header), segment(payload))
    }

    /// The error the crate's own `validate_token` returns for `jwt`. Every case
    /// here is rejected before the key is used.
    fn token_error(jwt: &str) -> IdentityError {
        let key: JsonWebKey =
            serde_json::from_value(json!({"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB"}))
                .expect("jwk");
        validate_token(jwt, &key, &ValidationOptions::new()).expect_err("token rejected")
    }

    /// The error the crate's own ID-Token profile check returns for `claims`.
    fn profile_error(
        claims: Value,
        header_alg: &str,
        options: IdTokenValidationOptions,
    ) -> IdentityError {
        let claims = Claims::from_json(claims).expect("claims");
        validate_id_token_claims(&claims, Some(header_alg), &options).expect_err("profile rejects")
    }

    fn client() -> rs_identity_model::IdTokenValidationOptionsBuilder {
        IdTokenValidationOptions::builder().client_id("rp")
    }

    #[test]
    fn header_rejections_from_the_crate_map_by_variant() {
        let payload = json!({"iss": "https://op/", "sub": "s", "aud": "rp"});
        let cases = [
            (
                "alg none",
                token(&json!({"alg": "none"}), &payload),
                Reason::AlgNone,
            ),
            (
                "alg outside the allowlist",
                token(&json!({"alg": "HS256"}), &payload),
                Reason::InvalidAlgorithm,
            ),
            (
                "not a JWS",
                "not-a-jwt".to_string(),
                Reason::IdTokenValidation,
            ),
        ];
        for (case, jwt, expected) in cases {
            let error = token_error(&jwt);
            assert_eq!(classify_id_token(&error), expected, "{case}: {error:?}");
        }
    }

    #[test]
    fn profile_rejections_from_the_crate_map_by_variant() {
        let base = || json!({"sub": "s", "aud": "rp"});
        let with = |extra: Value| {
            let mut claims = base();
            claims
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            claims
        };
        let cases = [
            (
                "missing sub",
                profile_error(json!({"aud": "rp"}), "RS256", client().build()),
                Reason::InvalidSubject,
            ),
            (
                "missing aud",
                profile_error(json!({"sub": "s"}), "RS256", client().build()),
                Reason::InvalidAudience,
            ),
            (
                "untrusted audience",
                profile_error(
                    with(json!({"aud": ["rp", "other"]})),
                    "RS256",
                    client().build(),
                ),
                Reason::InvalidAudience,
            ),
            (
                "azp mismatch",
                profile_error(
                    with(json!({"azp": "other"})),
                    "RS256",
                    client().validate_azp(true).build(),
                ),
                Reason::InvalidAudience,
            ),
            (
                "nonce mismatch",
                profile_error(
                    with(json!({"nonce": "sent"})),
                    "RS256",
                    client().nonce("expected").build(),
                ),
                Reason::NonceMismatch,
            ),
            (
                "missing nonce",
                profile_error(base(), "RS256", client().nonce("expected").build()),
                Reason::NonceMismatch,
            ),
            (
                "at_hash mismatch",
                profile_error(
                    with(json!({"at_hash": "AAAA"})),
                    "RS256",
                    client().access_token("at").build(),
                ),
                Reason::InvalidAtHash,
            ),
            (
                "c_hash missing",
                profile_error(base(), "RS256", client().code("code").build()),
                Reason::InvalidCHash,
            ),
            (
                "hash alg unsupported",
                profile_error(
                    with(json!({"at_hash": "AAAA"})),
                    "RS999",
                    client().access_token("at").build(),
                ),
                Reason::InvalidAlgorithm,
            ),
            (
                "max_age exceeded",
                profile_error(
                    with(json!({"auth_time": 1})),
                    "RS256",
                    client().max_age(60).now(1_000).build(),
                ),
                Reason::IdTokenValidation,
            ),
        ];
        for (case, error, expected) in cases {
            assert_eq!(classify_id_token(&error), expected, "{case}: {error:?}");
        }
    }

    #[test]
    fn base_claim_and_signature_variants_map_directly() {
        let claim = |name: &str| IdentityError::MissingClaim { claim: name.into() };
        let cases = [
            (
                IdentityError::IssuerMismatch {
                    expected: "https://op/".into(),
                    actual: Some("https://evil/".into()),
                },
                Reason::InvalidIssuer,
            ),
            (
                IdentityError::AudienceMismatch {
                    expected: "rp".into(),
                    actual: vec!["other".into()],
                },
                Reason::InvalidAudience,
            ),
            (
                IdentityError::Expired { exp: 1, now: 2 },
                Reason::InvalidExpiration,
            ),
            (
                IdentityError::NotYetValid { nbf: 3, now: 2 },
                Reason::InvalidExpiration,
            ),
            (claim("iat"), Reason::InvalidIssuedAt),
            (
                IdentityError::MalformedClaim {
                    claim: "iat".into(),
                    reason: "must be a numeric date".into(),
                },
                Reason::InvalidIssuedAt,
            ),
            (claim("custom"), Reason::IdTokenValidation),
            (IdentityError::SignatureInvalid, Reason::InvalidSignature),
            (
                IdentityError::KeyConversion {
                    kid: "k1".into(),
                    reason: "unsupported key type".into(),
                },
                Reason::IdTokenValidation,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify_id_token(&error), expected, "{error:?}");
        }
    }

    #[test]
    fn key_selection_and_other_errors_map_directly() {
        let ambiguous = IdentityError::AmbiguousKey {
            alg: "RS256".into(),
            kids: vec!["a".into(), "b".into()],
            count: 2,
        };
        assert_eq!(classify_id_token(&ambiguous), Reason::KeySelection);
        assert_eq!(
            classify_id_token(&IdentityError::KeyNotFound("k".into())),
            Reason::KeySelection
        );
        assert_eq!(
            classify_id_token(&IdentityError::Http("boom".into())),
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

    /// Fetches from a mock UserInfo endpoint answering `response` with the
    /// crate's own client, so the classified error is the one the crate emits.
    async fn userinfo_error(response: Option<wiremock::ResponseTemplate>) -> IdentityError {
        use rs_identity_model::UserInfoClient;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        let endpoint = match response {
            Some(template) => {
                Mock::given(method("GET"))
                    .and(path("/userinfo"))
                    .respond_with(template)
                    .mount(&server)
                    .await;
                format!("{}/userinfo", server.uri())
            }
            // Nothing listens on a port just released: a transport failure.
            None => {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                let address = listener.local_addr().expect("address");
                drop(listener);
                format!("http://{address}/userinfo")
            }
        };
        UserInfoClient::builder()
            .userinfo_endpoint(&endpoint)
            .allow_http(true)
            .build()
            .expect("userinfo client")
            .fetch_with_subject("access-token", "expected-sub")
            .await
            .expect_err("the fetch is rejected")
    }

    #[tokio::test]
    async fn userinfo_rejections_of_the_response_are_userinfo_validation() {
        use wiremock::ResponseTemplate;

        let cases = [
            (
                "sub mismatch",
                ResponseTemplate::new(200).set_body_json(json!({"sub": "other-sub"})),
            ),
            (
                "missing sub",
                ResponseTemplate::new(200).set_body_json(json!({"name": "n"})),
            ),
            ("non-2xx status", ResponseTemplate::new(401)),
        ];
        for (case, template) in cases {
            let error = userinfo_error(Some(template)).await;
            assert_eq!(
                classify_userinfo(&error),
                Reason::UserinfoValidation,
                "{case}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn userinfo_failures_that_never_checked_the_sub_are_not_validation() {
        use wiremock::ResponseTemplate;

        let undecodable = userinfo_error(Some(
            ResponseTemplate::new(200).set_body_raw("not json", "application/json"),
        ))
        .await;
        assert_eq!(
            classify_userinfo(&undecodable),
            Reason::UserinfoFailed,
            "{undecodable}"
        );
        let transport = userinfo_error(None).await;
        assert_eq!(
            classify_userinfo(&transport),
            Reason::UserinfoFailed,
            "{transport}"
        );
        let configuration = rs_identity_model::UserInfoClient::builder()
            .userinfo_endpoint("http://op.example/userinfo")
            .allow_http(true)
            .build()
            .expect("userinfo client")
            .fetch_with_subject("", "expected-sub")
            .await
            .expect_err("an empty access token is refused");
        assert_eq!(
            classify_userinfo(&configuration),
            Reason::UserinfoFailed,
            "{configuration}"
        );
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
            (Reason::UserinfoFailed, "userinfo_failed"),
            (Reason::IssuerMismatch, "issuer_mismatch"),
        ];
        for (reason, wire) in cases {
            assert_eq!(reason.as_str(), wire);
        }
    }
}
