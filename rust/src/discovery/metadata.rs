//! Parsed OpenID Connect provider metadata (OIDC Discovery 1.0 §3).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The parsed OpenID Connect provider metadata document (OIDC Discovery 1.0 §3).
///
/// The seven fields the conformance contract marks required
/// (`spec/conformance/discovery.json`) are modelled as plain owned values and
/// default to empty when absent, so a document that omits one parses
/// successfully and is then reported by presence validation (DISC-008) rather
/// than failing to deserialize. Optional endpoints are `Option`, and any field
/// not modelled here is preserved in [`ProviderMetadata::extra`] so unknown
/// metadata is ignored, not rejected (DISC-009).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Issuer identifier. MUST match the requested issuer (DISC-003).
    #[serde(default)]
    pub issuer: String,
    /// Authorization endpoint URL.
    #[serde(default)]
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    #[serde(default)]
    pub token_endpoint: String,
    /// JWKS document URL.
    #[serde(default)]
    pub jwks_uri: String,
    /// OAuth 2.0 `response_type` values supported.
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Subject identifier types supported.
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    /// JWS `alg` values supported for the ID Token.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// UserInfo endpoint URL, if advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// Dynamic client registration endpoint URL, if advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Token introspection endpoint URL (RFC 7662), if advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// Token revocation endpoint URL (RFC 7009), if advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// RP-initiated logout endpoint URL, if advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    /// Scope values supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Claim names supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    /// Grant types supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// Token endpoint authentication methods supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// PKCE code challenge methods supported (RFC 7636).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// Provider metadata fields not modelled above. Unknown fields are ignored
    /// (not rejected) per OIDC Discovery 1.0 §3 (DISC-009).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ProviderMetadata {
    /// Returns the JSON names of any required fields the parsed document left
    /// empty, in spec order (DISC-002 / DISC-008). An empty result means every
    /// required field is present.
    pub(crate) fn missing_required_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.issuer.is_empty() {
            missing.push("issuer");
        }
        if self.authorization_endpoint.is_empty() {
            missing.push("authorization_endpoint");
        }
        if self.token_endpoint.is_empty() {
            missing.push("token_endpoint");
        }
        if self.jwks_uri.is_empty() {
            missing.push("jwks_uri");
        }
        if self.response_types_supported.is_empty() {
            missing.push("response_types_supported");
        }
        if self.subject_types_supported.is_empty() {
            missing.push("subject_types_supported");
        }
        if self.id_token_signing_alg_values_supported.is_empty() {
            missing.push("id_token_signing_alg_values_supported");
        }
        missing
    }
}
