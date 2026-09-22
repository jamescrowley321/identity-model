//! Request parameters for the OAuth 2.0 Token Exchange grant (RFC 8693).
//!
//! [`TokenExchangeRequest`] carries the per-call parameters of an exchange:
//! the REQUIRED `subject_token` / `subject_token_type`, the optional
//! `actor_token` (with its REQUIRED-when-present `actor_token_type`), and the
//! optional `requested_token_type`, `scope`, `resource`, and `audience`
//! targeting hints (RFC 8693 §2.1).
//!
//! They live in a per-call request rather than on [`TokenClientBuilder`]
//! because they describe one exchange, not the client: the same
//! [`TokenClient`] trades many different subject tokens over its lifetime.
//!
//! Behavioural contract: `spec/vectors/token-exchange.json`
//! (`EXCH-001`..`EXCH-006`).
//!
//! [`TokenClient`]: super::TokenClient
//! [`TokenClientBuilder`]: super::TokenClientBuilder

use std::fmt;

use crate::{IdentityError, Result};

/// Placeholder printed in place of token material in `Debug` output (#24).
const REDACTED: &str = "<redacted>";

/// An OAuth 2.0 access token (RFC 8693 §3).
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// An OAuth 2.0 refresh token (RFC 8693 §3).
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
/// An OpenID Connect ID Token (RFC 8693 §3).
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// A SAML 1.1 assertion (RFC 8693 §3).
pub const TOKEN_TYPE_SAML1: &str = "urn:ietf:params:oauth:token-type:saml1";
/// A SAML 2.0 assertion (RFC 8693 §3).
pub const TOKEN_TYPE_SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";
/// A JWT that is not one of the more specific types (RFC 8693 §3).
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The six token type identifier URIs defined in RFC 8693 §3, in the order the
/// section lists them.
///
/// They are used verbatim as `subject_token_type`, `actor_token_type`, and
/// `requested_token_type` request parameters and as the `issued_token_type`
/// response field; an implementation MUST NOT abbreviate or normalise them
/// (EXCH-003).
pub const TOKEN_TYPE_URIS: [&str; 6] = [
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_ID_TOKEN,
    TOKEN_TYPE_SAML1,
    TOKEN_TYPE_SAML2,
    TOKEN_TYPE_JWT,
];

/// The parameters of one RFC 8693 token exchange request (RFC 8693 §2.1).
///
/// Build one with [`TokenExchangeRequest::new`], which takes the two REQUIRED
/// parameters, then chain the optional ones. Supplying only the subject token
/// requests an **impersonation** token; adding
/// [`actor_token`](TokenExchangeRequest::actor_token) makes it a **delegation**
/// exchange (RFC 8693 §1.1).
///
/// `Debug` redacts the subject and actor tokens so they cannot leak into logs
/// (#24); their presence is still visible.
///
/// ```
/// use rs_identity_model::{TokenExchangeRequest, TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT};
///
/// // Delegation: an actor acting on behalf of the subject, scoped to one API.
/// let request = TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN)
///     .actor_token("actor.tok", TOKEN_TYPE_JWT)
///     .audience("https://api.example.com")
///     .scope("https://api.example.com/read");
/// ```
#[derive(Clone)]
pub struct TokenExchangeRequest {
    /// The security token being exchanged (REQUIRED).
    pub(crate) subject_token: String,
    /// The type URI of `subject_token` (REQUIRED).
    pub(crate) subject_token_type: String,
    /// The token representing the acting party, for a delegation exchange.
    pub(crate) actor_token: Option<String>,
    /// The type URI of `actor_token`; REQUIRED whenever `actor_token` is set.
    pub(crate) actor_token_type: Option<String>,
    /// The desired type of the issued token; the server MAY issue another.
    pub(crate) requested_token_type: Option<String>,
    /// The requested scope, sent as a single space-delimited parameter.
    pub(crate) scope: Option<String>,
    /// Target resource URIs; each is sent as its own repeated parameter.
    pub(crate) resources: Vec<String>,
    /// Target audiences; each is sent as its own repeated parameter.
    pub(crate) audiences: Vec<String>,
}

impl fmt::Debug for TokenExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenExchangeRequest")
            .field("subject_token", &REDACTED)
            .field("subject_token_type", &self.subject_token_type)
            .field("actor_token", &self.actor_token.as_ref().map(|_| REDACTED))
            .field("actor_token_type", &self.actor_token_type)
            .field("requested_token_type", &self.requested_token_type)
            .field("scope", &self.scope)
            .field("resources", &self.resources)
            .field("audiences", &self.audiences)
            .finish()
    }
}

impl TokenExchangeRequest {
    /// Starts an impersonation exchange of `subject_token`, whose type is named
    /// by `subject_token_type` — one of the [`TOKEN_TYPE_URIS`] (RFC 8693 §3).
    /// Both are REQUIRED (RFC 8693 §2.1).
    pub fn new(subject_token: impl Into<String>, subject_token_type: impl Into<String>) -> Self {
        Self {
            subject_token: subject_token.into(),
            subject_token_type: subject_token_type.into(),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            scope: None,
            resources: Vec::new(),
            audiences: Vec::new(),
        }
    }

    /// Attaches the acting party's token, turning the request into a delegation
    /// exchange (RFC 8693 §1.1, §2.1). `token_type` is one of the
    /// [`TOKEN_TYPE_URIS`] and is REQUIRED whenever an actor token is present.
    ///
    /// Both arguments must be non-empty: an empty one is rejected when the
    /// exchange is validated, so an accidental empty actor token cannot quietly
    /// turn a delegation into an impersonation. Simply do not call this method
    /// to request impersonation.
    pub fn actor_token(mut self, token: impl Into<String>, token_type: impl Into<String>) -> Self {
        self.actor_token = Some(token.into());
        self.actor_token_type = Some(token_type.into());
        self
    }

    /// Names the desired type of the issued token (RFC 8693 §2.1). The server
    /// MAY issue a different type, which it reports in `issued_token_type`.
    pub fn requested_token_type(mut self, uri: impl Into<String>) -> Self {
        self.requested_token_type = Some(uri.into());
        self
    }

    /// Requests `scope`, sent as a single space-delimited `scope` parameter
    /// (RFC 6749 §3.3). When unset, no `scope` parameter is sent.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Adds a target resource URI (RFC 8693 §2.1). `resource` MAY appear more
    /// than once, so repeated calls accumulate rather than replace.
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    /// Adds a target audience (RFC 8693 §2.1). `audience` MAY appear more than
    /// once, so repeated calls accumulate rather than replace.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Checks the RFC 8693 §2.1 parameter requirements before a request is
    /// built, so a malformed exchange never reaches the wire.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] when `subject_token` or
    /// `subject_token_type` is empty, when a present `actor_token` is the empty
    /// string, or when an `actor_token` is present without a non-empty
    /// `actor_token_type`.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.subject_token.is_empty() {
            return Err(IdentityError::Validation(
                "token exchange: subject_token is required".to_string(),
            ));
        }
        if self.subject_token_type.is_empty() {
            return Err(IdentityError::Validation(
                "token exchange: subject_token_type is required".to_string(),
            ));
        }
        // An actor token that is present but empty is rejected rather than
        // dropped: silently sending a subject-only request would downgrade the
        // delegation the caller asked for into an impersonation
        // (RFC 8693 §1.1). A caller who wants impersonation omits
        // `actor_token` entirely.
        if self.actor_token.as_deref().is_some_and(str::is_empty) {
            return Err(IdentityError::Validation(
                "token exchange: actor_token must not be empty when provided".to_string(),
            ));
        }
        // actor_token_type is REQUIRED whenever actor_token is present
        // (RFC 8693 §2.1), and a type that is present but empty is as unusable
        // as an absent one. The absent and empty cases are folded into one
        // check on purpose: `actor_token()` is the only way to set either half
        // and it always sets both, so a separate "type is None" arm would be
        // unreachable through the public API and could never be tested.
        if self.actor_token.is_some()
            && !self
                .actor_token_type
                .as_deref()
                .is_some_and(|t| !t.is_empty())
        {
            return Err(IdentityError::Validation(
                "token exchange: actor_token_type is required and must not be empty \
                 when actor_token is set"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EXCH-003: the exported constants are the six RFC 8693 §3 URIs, verbatim
    // and in section order. The cross-language fixture
    // spec/test-fixtures/token-exchange/token-type-uris.json holds the same set;
    // tests/it/local/token_exchange.rs asserts the two agree.
    #[test]
    fn token_type_uris_are_the_six_rfc_8693_uris() {
        assert_eq!(
            TOKEN_TYPE_URIS,
            [
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:refresh_token",
                "urn:ietf:params:oauth:token-type:id_token",
                "urn:ietf:params:oauth:token-type:saml1",
                "urn:ietf:params:oauth:token-type:saml2",
                "urn:ietf:params:oauth:token-type:jwt",
            ]
        );
    }

    // A minimal impersonation request carries no actor or targeting parameters.
    #[test]
    fn new_builds_a_bare_impersonation_request() {
        let request = TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN);
        assert_eq!(request.subject_token, "subject.tok");
        assert_eq!(request.subject_token_type, TOKEN_TYPE_ACCESS_TOKEN);
        assert!(request.actor_token.is_none());
        assert!(request.actor_token_type.is_none());
        assert!(request.requested_token_type.is_none());
        assert!(request.scope.is_none());
        assert!(request.resources.is_empty());
        assert!(request.audiences.is_empty());
        request.validate().expect("a bare impersonation is valid");
    }

    // RFC 8693 §2.1: resource and audience MAY each appear more than once, so
    // the builder accumulates instead of replacing.
    #[test]
    fn resource_and_audience_accumulate() {
        let request = TokenExchangeRequest::new("s", TOKEN_TYPE_ACCESS_TOKEN)
            .resource("https://rs1.example.com")
            .resource("https://rs2.example.com")
            .audience("aud-a")
            .audience("aud-b");
        assert_eq!(
            request.resources,
            ["https://rs1.example.com", "https://rs2.example.com"]
        );
        assert_eq!(request.audiences, ["aud-a", "aud-b"]);
    }

    // RFC 8693 §2.1 REQUIRED: an empty subject_token is rejected locally.
    #[test]
    fn validate_rejects_empty_subject_token() {
        let err = TokenExchangeRequest::new("", TOKEN_TYPE_ACCESS_TOKEN)
            .validate()
            .expect_err("empty subject_token must be rejected");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // RFC 8693 §2.1 REQUIRED: an empty subject_token_type is rejected locally.
    #[test]
    fn validate_rejects_empty_subject_token_type() {
        let err = TokenExchangeRequest::new("subject.tok", "")
            .validate()
            .expect_err("empty subject_token_type must be rejected");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // RFC 8693 §2.1: actor_token_type is REQUIRED whenever actor_token is
    // present, and an empty type is as unusable as a missing one.
    #[test]
    fn validate_rejects_actor_token_without_type() {
        let err = TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN)
            .actor_token("actor.tok", "")
            .validate()
            .expect_err("actor_token without a type must be rejected");
        assert!(matches!(err, IdentityError::Validation(_)), "{err:?}");
    }

    // RFC 8693 §1.1: a present-but-empty actor token is rejected, not dropped.
    // Dropping it would send a subject-only request, silently turning the
    // delegation the caller asked for into an impersonation.
    #[test]
    fn validate_rejects_empty_actor_token() {
        for (token, token_type) in [("", ""), ("", TOKEN_TYPE_JWT)] {
            let err = TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN)
                .actor_token(token, token_type)
                .validate()
                .expect_err("an empty actor token must be rejected");
            match err {
                IdentityError::Validation(message) => {
                    assert!(message.contains("actor_token"), "{message}");
                }
                other => panic!("expected Validation, got {other:?}"),
            }
        }
    }

    // #24: Debug never prints the subject or actor token, but still reveals
    // whether a delegation actor is present.
    #[test]
    fn debug_redacts_subject_and_actor_tokens() {
        let request = TokenExchangeRequest::new("SUBJECT-SECRET", TOKEN_TYPE_ACCESS_TOKEN)
            .actor_token("ACTOR-SECRET", TOKEN_TYPE_JWT);
        let dbg = format!("{request:?}");
        assert!(!dbg.contains("SUBJECT-SECRET"), "subject leaked: {dbg}");
        assert!(!dbg.contains("ACTOR-SECRET"), "actor leaked: {dbg}");
        assert!(dbg.contains(REDACTED), "no redaction marker: {dbg}");
        assert!(dbg.contains("actor_token: Some"), "{dbg}");
        // The type URIs are not secret and stay legible for diagnostics.
        assert!(dbg.contains(TOKEN_TYPE_ACCESS_TOKEN), "{dbg}");
    }

    // An impersonation request shows the absent actor as None, not a redaction
    // marker.
    #[test]
    fn debug_shows_absent_actor_as_none() {
        let request = TokenExchangeRequest::new("s", TOKEN_TYPE_ACCESS_TOKEN);
        assert!(format!("{request:?}").contains("actor_token: None"));
    }
}
