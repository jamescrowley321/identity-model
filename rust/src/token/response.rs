//! Typed OAuth 2.0 token endpoint response (RFC 6749 §5.1).

use std::collections::HashMap;

use serde::{Deserialize, Deserializer};

/// A successful OAuth 2.0 token endpoint response (RFC 6749 §5.1).
///
/// Standard parameters are modelled as typed fields; any additional
/// provider-specific parameters are preserved in [`TokenResponse::extra`] so
/// unknown fields are ignored, not rejected. `expires_in` is tolerated as a
/// JSON number, a numeric string, or `null`, since some providers deviate from
/// the RFC's number type (CC-001).
#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    /// The issued access token (required).
    pub access_token: String,
    /// The token type, typically `Bearer` (required).
    #[serde(default)]
    pub token_type: String,
    /// The access token lifetime in seconds, if provided. Absent, `null`, or an
    /// empty value is reported as `0`.
    #[serde(default, deserialize_with = "deserialize_flexible_expires_in")]
    pub expires_in: i64,
    /// The granted scope, if it differs from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The issued refresh token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The OIDC ID token, present for the authorization code grant when the
    /// `openid` scope was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Any non-standard parameters returned by the provider.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Deserializes `expires_in` from a JSON number, numeric string, or `null`.
///
/// `expires_in` is an optional parameter (RFC 6749 §5.1), so `null`, an empty
/// string, or a missing value is treated as absent (`0`) rather than an error:
/// a valid token must not be discarded over a missing-but-present lifetime. A
/// fractional value (e.g. `3600.0`, sent by some providers) is truncated toward
/// zero; a value outside the `i64` range is rejected.
fn deserialize_flexible_expires_in<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(0),
        serde_json::Value::Number(n) => number_to_seconds::<D>(&n),
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(0);
            }
            if let Ok(i) = s.parse::<i64>() {
                return Ok(i);
            }
            match s.parse::<f64>() {
                Ok(f) => float_to_seconds::<D>(f),
                Err(_) => Err(D::Error::custom(format!(
                    "expires_in: expected numeric string, got {s:?}"
                ))),
            }
        }
        other => Err(D::Error::custom(format!(
            "expires_in: expected number, numeric string, or null, got {other}"
        ))),
    }
}

/// Converts a JSON number to whole seconds, preferring an exact integer and
/// falling back to a truncated float.
fn number_to_seconds<'de, D>(n: &serde_json::Number) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    if let Some(i) = n.as_i64() {
        return Ok(i);
    }
    match n.as_f64() {
        Some(f) => float_to_seconds::<D>(f),
        None => Err(D::Error::custom(format!(
            "expires_in: expected integer seconds, got {n}"
        ))),
    }
}

/// Truncates a fractional lifetime to whole seconds, rejecting values that
/// cannot be represented as an `i64` (overflow, Inf, NaN) so a crafted or
/// malformed `expires_in` cannot silently wrap to a garbage value.
fn float_to_seconds<'de, D>(f: f64) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    if !f.is_finite() || f >= i64::MAX as f64 || f < i64::MIN as f64 {
        return Err(D::Error::custom(format!("expires_in out of range: {f}")));
    }
    Ok(f as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CC-001: a standard success body deserializes into typed fields.
    #[test]
    fn parses_standard_response() {
        let json = r#"{
            "access_token": "at-123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile",
            "refresh_token": "rt-456",
            "id_token": "id-789"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(resp.access_token, "at-123");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert_eq!(resp.scope.as_deref(), Some("openid profile"));
        assert_eq!(resp.refresh_token.as_deref(), Some("rt-456"));
        assert_eq!(resp.id_token.as_deref(), Some("id-789"));
        assert!(resp.extra.is_empty());
    }

    // CC-001: unknown provider-specific fields are preserved in `extra`.
    #[test]
    fn preserves_extra_fields() {
        let json = r#"{
            "access_token": "at",
            "token_type": "Bearer",
            "custom_field": "keep-me",
            "resource": "urn:test:api"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(
            resp.extra.get("custom_field").and_then(|v| v.as_str()),
            Some("keep-me")
        );
        assert_eq!(
            resp.extra.get("resource").and_then(|v| v.as_str()),
            Some("urn:test:api")
        );
    }

    // expires_in as a numeric string (provider deviation) is accepted.
    #[test]
    fn parses_expires_in_numeric_string() {
        let resp: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":"7200"}"#).expect("parse");
        assert_eq!(resp.expires_in, 7200);
    }

    // A fractional expires_in is truncated to whole seconds.
    #[test]
    fn parses_expires_in_fractional() {
        let resp: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":3600.9}"#).expect("parse");
        assert_eq!(resp.expires_in, 3600);
    }

    // A null or missing expires_in is treated as absent (0), not an error.
    #[test]
    fn tolerates_null_and_missing_expires_in() {
        let null_resp: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":null}"#).expect("parse null");
        assert_eq!(null_resp.expires_in, 0);

        let missing_resp: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a"}"#).expect("parse missing");
        assert_eq!(missing_resp.expires_in, 0);
    }

    // An empty numeric string is treated as absent (0).
    #[test]
    fn tolerates_empty_expires_in_string() {
        let resp: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":""}"#).expect("parse");
        assert_eq!(resp.expires_in, 0);
    }

    // A non-numeric expires_in is a hard error.
    #[test]
    fn rejects_non_numeric_expires_in() {
        let err =
            serde_json::from_str::<TokenResponse>(r#"{"access_token":"a","expires_in":"soon"}"#);
        assert!(err.is_err());
    }
}
