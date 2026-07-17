//! Typed OIDC UserInfo response (OpenID Connect Core 1.0 §5.1).

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

/// The OIDC `address` claim: a structured postal address (OIDC Core 1.0
/// §5.1.1). Every component is optional.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Address {
    /// The full mailing address, formatted for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// The street address component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// The city or locality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// The state, province, prefecture, or region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// The country name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// The set of claims returned by the UserInfo endpoint (OIDC Core 1.0 §5.1).
///
/// The standard §5.1 claims are modelled as typed fields; any additional
/// provider-specific or custom claims are preserved in
/// [`UserInfoResponse::extra`] (reachable via [`UserInfoResponse::claims`]) so
/// unknown fields are ignored, not rejected (UI-007). `updated_at` is tolerated
/// as a JSON number, a numeric string, or `null`, since providers deviate from
/// the RFC's number type.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserInfoResponse {
    /// The subject identifier — always present (§5.3.2). An absent or empty
    /// `sub` is rejected by the client before this value is returned.
    #[serde(default)]
    pub sub: String,
    /// The end-user's full name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The given (first) name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// The family (last) name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// The middle name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// The casual name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// The shorthand name the end-user prefers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// The URL of the end-user's profile page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The URL of the end-user's profile picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// The URL of the end-user's web page or blog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// The preferred e-mail address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the e-mail has been verified. `None` when the claim is absent,
    /// distinguishing it from an explicit `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// The end-user's gender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// The birthday, `"YYYY-MM-DD"` or `"YYYY"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// The time-zone, e.g. `"Europe/Paris"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// The locale, e.g. `"en-US"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// The preferred telephone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether the phone number has been verified. `None` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// The preferred postal address (§5.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// The time the information was last updated, as seconds since the Unix
    /// epoch. `None` when absent; a fractional or numeric-string value is
    /// tolerated and truncated to whole seconds.
    #[serde(
        default,
        deserialize_with = "deserialize_flexible_updated_at",
        skip_serializing_if = "Option::is_none"
    )]
    pub updated_at: Option<i64>,
    /// Every non-standard, provider-specific claim, preserved verbatim so
    /// callers can reach custom claims via [`UserInfoResponse::claims`]
    /// (UI-007).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl UserInfoResponse {
    /// Returns the additional (non-standard) claims returned by the endpoint —
    /// any claim not modelled as a typed field. Standard §5.1 claims are read
    /// from their typed fields (UI-007).
    pub fn claims(&self) -> &HashMap<String, serde_json::Value> {
        &self.extra
    }
}

/// Deserializes the optional `updated_at` claim from a JSON number, numeric
/// string, or `null` (OIDC Core 1.0 §5.1 defines it as a number of seconds
/// since the epoch).
///
/// `updated_at` is optional, so `null`, an empty string, or a missing value is
/// treated as absent (`None`) rather than an error: a bad-but-present value
/// must not sink the whole response decode and drop every claim. A fractional
/// or exponent number is truncated toward zero; a value outside the `i64`
/// range (overflow, Inf, NaN) is rejected so a crafted number cannot silently
/// wrap to a garbage time.
fn deserialize_flexible_updated_at<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(n) => number_to_seconds::<D>(&n).map(Some),
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            if let Ok(i) = s.parse::<i64>() {
                return Ok(Some(i));
            }
            match s.parse::<f64>() {
                Ok(f) => float_to_seconds::<D>(f).map(Some),
                Err(_) => Err(D::Error::custom(format!(
                    "updated_at: expected numeric string, got {s:?}"
                ))),
            }
        }
        other => Err(D::Error::custom(format!(
            "updated_at: expected number, numeric string, or null, got {other}"
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
            "updated_at: expected integer seconds, got {n}"
        ))),
    }
}

/// Truncates a fractional value to whole seconds, rejecting values that cannot
/// be represented as an `i64` (overflow, Inf, NaN).
fn float_to_seconds<'de, D>(f: f64) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    if !f.is_finite() || f >= i64::MAX as f64 || f < i64::MIN as f64 {
        return Err(D::Error::custom(format!("updated_at out of range: {f}")));
    }
    Ok(f as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared cross-language fixture (spec/test-fixtures/userinfo).
    const STANDARD_CLAIMS: &str =
        include_str!("../../../spec/test-fixtures/userinfo/standard-claims.json");

    // UI-001 / UI-007: every standard §5.1 claim decodes into its typed field,
    // and the custom "department" claim is preserved in the overflow map.
    #[test]
    fn parses_standard_and_custom_claims() {
        let resp: UserInfoResponse = serde_json::from_str(STANDARD_CLAIMS).expect("parse fixture");

        assert_eq!(resp.sub, "248289761001");
        assert_eq!(resp.name.as_deref(), Some("Jane Doe"));
        assert_eq!(resp.given_name.as_deref(), Some("Jane"));
        assert_eq!(resp.family_name.as_deref(), Some("Doe"));
        assert_eq!(resp.middle_name.as_deref(), Some("Quinn"));
        assert_eq!(resp.nickname.as_deref(), Some("Janie"));
        assert_eq!(resp.preferred_username.as_deref(), Some("j.doe"));
        assert_eq!(resp.email.as_deref(), Some("janedoe@example.com"));
        assert_eq!(resp.email_verified, Some(true));
        assert_eq!(resp.phone_number.as_deref(), Some("+1 (425) 555-1212"));
        assert_eq!(resp.phone_number_verified, Some(false));
        assert_eq!(resp.locale.as_deref(), Some("en-US"));
        assert_eq!(resp.updated_at, Some(1_700_000_000));

        let address = resp.address.as_ref().expect("address present");
        assert_eq!(address.locality.as_deref(), Some("Los Angeles"));
        assert_eq!(address.postal_code.as_deref(), Some("90210"));
        assert_eq!(address.country.as_deref(), Some("USA"));

        // UI-007: the non-standard claim is reachable via claims(); standard
        // claims are NOT duplicated into the overflow map.
        assert_eq!(
            resp.claims().get("department").and_then(|v| v.as_str()),
            Some("Engineering")
        );
        assert!(
            !resp.claims().contains_key("sub"),
            "standard claims stay in typed fields"
        );
        assert!(!resp.claims().contains_key("email"));
    }

    // AC-6: absent optional claims deserialize to None rather than erroring.
    #[test]
    fn tolerates_missing_optional_claims() {
        let resp: UserInfoResponse =
            serde_json::from_str(r#"{"sub":"abc"}"#).expect("parse minimal");
        assert_eq!(resp.sub, "abc");
        assert!(resp.name.is_none());
        assert!(resp.email_verified.is_none());
        assert!(resp.address.is_none());
        assert!(resp.updated_at.is_none());
        assert!(resp.claims().is_empty());
    }

    // updated_at as a numeric string (provider deviation) is accepted.
    #[test]
    fn parses_updated_at_numeric_string() {
        let resp: UserInfoResponse =
            serde_json::from_str(r#"{"sub":"a","updated_at":"1700000000"}"#).expect("parse");
        assert_eq!(resp.updated_at, Some(1_700_000_000));
    }

    // A fractional updated_at is truncated to whole seconds.
    #[test]
    fn parses_updated_at_fractional() {
        let resp: UserInfoResponse =
            serde_json::from_str(r#"{"sub":"a","updated_at":1700000000.9}"#).expect("parse");
        assert_eq!(resp.updated_at, Some(1_700_000_000));
    }

    // A null updated_at is treated as absent (None), not an error, and does not
    // drop the other claims.
    #[test]
    fn tolerates_null_updated_at() {
        let resp: UserInfoResponse =
            serde_json::from_str(r#"{"sub":"a","name":"N","updated_at":null}"#).expect("parse");
        assert!(resp.updated_at.is_none());
        assert_eq!(resp.name.as_deref(), Some("N"));
    }

    // A non-numeric updated_at is a hard error.
    #[test]
    fn rejects_non_numeric_updated_at() {
        let err = serde_json::from_str::<UserInfoResponse>(r#"{"sub":"a","updated_at":"soon"}"#);
        assert!(err.is_err());
    }

    // The response serializes with omit-empty semantics (parity with the Go
    // `omitempty` tags): absent optional claims are dropped, custom claims in
    // the overflow map are flattened back out, and a round-trip is lossless.
    #[test]
    fn serializes_with_omit_empty_and_round_trips() {
        let resp: UserInfoResponse = serde_json::from_str(
            r#"{"sub":"abc","email":"a@b.co","email_verified":true,"department":"eng"}"#,
        )
        .expect("parse");

        let value = serde_json::to_value(&resp).expect("serialize");
        let obj = value.as_object().expect("object");
        // Present claims are emitted, absent ones are skipped (omit-empty).
        assert_eq!(obj.get("sub").and_then(|v| v.as_str()), Some("abc"));
        assert_eq!(obj.get("email").and_then(|v| v.as_str()), Some("a@b.co"));
        assert_eq!(
            obj.get("email_verified").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(!obj.contains_key("name"), "absent name must be omitted");
        assert!(
            !obj.contains_key("address"),
            "absent address must be omitted"
        );
        // The custom claim flattens back out at the top level.
        assert_eq!(obj.get("department").and_then(|v| v.as_str()), Some("eng"));

        // Round-trip is lossless.
        let again: UserInfoResponse = serde_json::from_value(value).expect("re-parse");
        assert_eq!(again.sub, "abc");
        assert_eq!(again.email.as_deref(), Some("a@b.co"));
        assert_eq!(
            again.claims().get("department").and_then(|v| v.as_str()),
            Some("eng")
        );
    }
}
