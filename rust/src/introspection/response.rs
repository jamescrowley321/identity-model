//! Typed token introspection response (RFC 7662 §2.2).

use std::collections::HashMap;

use serde::de::{Deserialize, Deserializer, Error as DeError};
use serde_json::{Map, Value};

use crate::{IdentityError, Result};

/// The introspection `aud` member, which per RFC 7662 §2.2 (via RFC 7519 §4.1.3)
/// MAY be a single string or an array of strings. It always resolves to a list
/// of audiences.
///
/// Local to introspection rather than reusing [`crate::jwt::Audience`], which is
/// decoded from validated JWT claims and carries no `Deserialize` impl of its
/// own; keeping this type here bounds the change to the introspection surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntrospectionAudience(pub Vec<String>);

impl IntrospectionAudience {
    /// Parses an `aud` value that is either a JSON string or an array of
    /// strings. A JSON `null` yields an empty audience rather than a slice
    /// holding one empty string; a non-string array element is rejected.
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Null => Ok(Self(Vec::new())),
            Value::String(s) => Ok(Self(vec![s.clone()])),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::String(s) => out.push(s.clone()),
                        _ => {
                            return Err(IdentityError::Deserialization(
                                "introspection \"aud\" invalid: array must contain only strings"
                                    .to_string(),
                            ));
                        }
                    }
                }
                Ok(Self(out))
            }
            _ => Err(IdentityError::Deserialization(
                "introspection \"aud\" invalid: must be a string or array of strings".to_string(),
            )),
        }
    }

    /// Reports whether the audience includes `s`.
    pub fn contains(&self, s: &str) -> bool {
        self.0.iter().any(|v| v == s)
    }

    /// Returns the audience values.
    pub fn values(&self) -> &[String] {
        &self.0
    }
}

/// The response from an OAuth 2.0 token introspection request (RFC 7662 §2.2).
///
/// Only [`active`](Introspection::active) is guaranteed present; the standard
/// metadata members are populated when `active == true` and applicable, and any
/// additional provider-specific members are preserved in
/// [`extra`](Introspection::extra) so unknown members remain reachable rather
/// than being dropped (INTR-001).
#[derive(Clone, Debug, PartialEq)]
pub struct Introspection {
    /// Whether the token is currently active — issued and neither expired nor
    /// revoked (REQUIRED).
    pub active: bool,
    /// The space-delimited list of scopes associated with the token.
    pub scope: Option<String>,
    /// The client identifier the token was issued to.
    pub client_id: Option<String>,
    /// A human-readable identifier for the resource owner.
    pub username: Option<String>,
    /// The type of the token, e.g. `Bearer`.
    pub token_type: Option<String>,
    /// The token expiration time (seconds since the Unix epoch).
    pub exp: Option<i64>,
    /// The token issuance time (seconds since the Unix epoch).
    pub iat: Option<i64>,
    /// The not-before time (seconds since the Unix epoch).
    pub nbf: Option<i64>,
    /// The subject of the token.
    pub sub: Option<String>,
    /// The intended audience; a single string or an array of strings.
    pub aud: IntrospectionAudience,
    /// The issuer of the token.
    pub iss: Option<String>,
    /// The string identifier of the token (the JWT ID).
    pub jti: Option<String>,
    /// Any non-standard members returned by the provider (INTR-001).
    pub extra: HashMap<String, Value>,
}

/// The §2.2 members routed to typed fields; anything else falls through to
/// [`Introspection::extra`].
const STANDARD_MEMBERS: &[&str] = &[
    "active",
    "scope",
    "client_id",
    "username",
    "token_type",
    "exp",
    "iat",
    "nbf",
    "sub",
    "aud",
    "iss",
    "jti",
];

impl Introspection {
    /// Builds a typed response from a decoded JSON object, routing the standard
    /// §2.2 members to their typed fields and preserving the rest in `extra`.
    fn from_value(value: Value) -> Result<Self> {
        let Value::Object(map) = value else {
            return Err(IdentityError::Deserialization(
                "introspection response is not a JSON object".to_string(),
            ));
        };
        Self::from_map(map)
    }

    fn from_map(map: Map<String, Value>) -> Result<Self> {
        // `active` is REQUIRED (RFC 7662 §2.2). A 2xx body that omits it (e.g.
        // `{}`) or sets it to JSON null would otherwise decode to `false`,
        // indistinguishable from a legitimately inactive token; reject it as
        // malformed instead. A wrong-typed `active` (e.g. a string) is likewise
        // rejected rather than silently coerced.
        let active = match map.get("active") {
            Some(Value::Bool(b)) => *b,
            None | Some(Value::Null) => {
                return Err(IdentityError::Deserialization(
                    "introspection response missing required \"active\" member (RFC 7662 §2.2)"
                        .to_string(),
                ));
            }
            Some(_) => {
                return Err(IdentityError::Deserialization(
                    "introspection \"active\" member must be a boolean (RFC 7662 §2.2)".to_string(),
                ));
            }
        };

        let scope = string_member(&map, "scope")?;
        let client_id = string_member(&map, "client_id")?;
        let username = string_member(&map, "username")?;
        let token_type = string_member(&map, "token_type")?;
        let sub = string_member(&map, "sub")?;
        let iss = string_member(&map, "iss")?;
        let jti = string_member(&map, "jti")?;
        let exp = int_member(&map, "exp")?;
        let iat = int_member(&map, "iat")?;
        let nbf = int_member(&map, "nbf")?;
        let aud = match map.get("aud") {
            Some(v) => IntrospectionAudience::from_value(v)?,
            None => IntrospectionAudience::default(),
        };

        let extra: HashMap<String, Value> = map
            .into_iter()
            .filter(|(k, _)| !STANDARD_MEMBERS.contains(&k.as_str()))
            .collect();

        Ok(Introspection {
            active,
            scope,
            client_id,
            username,
            token_type,
            exp,
            iat,
            nbf,
            sub,
            aud,
            iss,
            jti,
            extra,
        })
    }
}

/// A custom decode (rather than `#[derive(Deserialize)]` with
/// `#[serde(flatten)]`) so the required-`active` check and the overflow map are
/// enforced explicitly, matching the Go reference's `UnmarshalJSON`.
impl<'de> Deserialize<'de> for Introspection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Introspection::from_value(value).map_err(D::Error::custom)
    }
}

/// Reads an optional string member, treating a missing member or JSON `null` as
/// absent and rejecting a non-string value.
fn string_member(map: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    match map.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(IdentityError::Deserialization(format!(
            "introspection \"{name}\" invalid: must be a string"
        ))),
    }
}

/// Reads an optional integer member (a numeric date), treating a missing member
/// or JSON `null` as absent and rejecting a non-integer value.
fn int_member(map: &Map<String, Value>, name: &str) -> Result<Option<i64>> {
    match map.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(|| {
            IdentityError::Deserialization(format!(
                "introspection \"{name}\" invalid: must be an integer number of seconds"
            ))
        }),
        Some(_) => Err(IdentityError::Deserialization(format!(
            "introspection \"{name}\" invalid: must be a number"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // INTR-001: `spec/test-fixtures/introspection/active-response.json` — an
    // active token decodes to active=true with the standard metadata populated,
    // and an unknown member remains reachable via `extra`.
    #[test]
    fn parses_active_response_with_extra() {
        let json = r#"{
            "active": true,
            "scope": "read write dolphin",
            "client_id": "l238j323ds-23ij4",
            "username": "jdoe",
            "token_type": "Bearer",
            "exp": 1419356238,
            "iat": 1419350238,
            "nbf": 1419350238,
            "sub": "Z5O3upPC88QrAjx00dis",
            "aud": "https://protected.example.net/resource",
            "iss": "https://server.example.com/",
            "jti": "d3f5c9a1-2b7e-4c1a-9e8f-0a1b2c3d4e5f",
            "extension_field": "twenty-seven"
        }"#;
        let ir: Introspection = serde_json::from_str(json).expect("parse");
        assert!(ir.active);
        assert_eq!(ir.scope.as_deref(), Some("read write dolphin"));
        assert_eq!(ir.client_id.as_deref(), Some("l238j323ds-23ij4"));
        assert_eq!(ir.username.as_deref(), Some("jdoe"));
        assert_eq!(ir.token_type.as_deref(), Some("Bearer"));
        assert_eq!(ir.exp, Some(1419356238));
        assert_eq!(ir.iat, Some(1419350238));
        assert_eq!(ir.nbf, Some(1419350238));
        assert_eq!(ir.sub.as_deref(), Some("Z5O3upPC88QrAjx00dis"));
        assert!(ir.aud.contains("https://protected.example.net/resource"));
        assert_eq!(ir.iss.as_deref(), Some("https://server.example.com/"));
        assert_eq!(
            ir.jti.as_deref(),
            Some("d3f5c9a1-2b7e-4c1a-9e8f-0a1b2c3d4e5f")
        );
        // Unknown member preserved (INTR-001).
        assert_eq!(
            ir.extra.get("extension_field").and_then(Value::as_str),
            Some("twenty-seven")
        );
        // Standard members are NOT duplicated into `extra`.
        assert!(!ir.extra.contains_key("active"));
        assert!(!ir.extra.contains_key("scope"));
    }

    // INTR-001: `active-minimal.json` — active=true with no other member.
    #[test]
    fn parses_active_minimal() {
        let ir: Introspection = serde_json::from_str(r#"{"active": true}"#).expect("parse");
        assert!(ir.active);
        assert_eq!(ir.scope, None);
        assert_eq!(ir.client_id, None);
        assert!(ir.aud.values().is_empty());
        assert!(ir.extra.is_empty());
    }

    // INTR-002: `inactive-response.json` — active=false, no other member
    // required to be present.
    #[test]
    fn parses_inactive_response() {
        let ir: Introspection = serde_json::from_str(r#"{"active": false}"#).expect("parse");
        assert!(!ir.active);
        assert_eq!(ir.username, None);
        assert!(ir.extra.is_empty());
    }

    // INTR-002 / RFC 7662 §2.2: `active` is REQUIRED — a body that omits it is
    // malformed, not a silently-inactive token.
    #[test]
    fn rejects_missing_active() {
        let err = serde_json::from_str::<Introspection>(r#"{"scope":"read"}"#)
            .expect_err("missing active must fail");
        assert!(err.to_string().contains("active"), "{err}");
    }

    // A JSON-null `active` is likewise rejected (would coerce to false).
    #[test]
    fn rejects_null_active() {
        let err = serde_json::from_str::<Introspection>(r#"{"active":null}"#)
            .expect_err("null active must fail");
        assert!(err.to_string().contains("active"), "{err}");
    }

    // A wrong-typed `active` is rejected rather than coerced.
    #[test]
    fn rejects_non_boolean_active() {
        let err = serde_json::from_str::<Introspection>(r#"{"active":"true"}"#)
            .expect_err("string active must fail");
        assert!(err.to_string().contains("active"), "{err}");
    }

    // RFC 7662 §2.2 (via RFC 7519 §4.1.3): `aud` may be an array of strings.
    #[test]
    fn parses_audience_array() {
        let ir: Introspection =
            serde_json::from_str(r#"{"active":true,"aud":["a","b"]}"#).expect("parse");
        assert_eq!(ir.aud.values(), ["a".to_string(), "b".to_string()]);
        assert!(ir.aud.contains("b"));
    }

    // A non-string audience element is rejected.
    #[test]
    fn rejects_non_string_audience_element() {
        let err = serde_json::from_str::<Introspection>(r#"{"active":true,"aud":["a",1]}"#)
            .expect_err("numeric aud element must fail");
        assert!(err.to_string().contains("aud"), "{err}");
    }

    // A fractional numeric date (e.g. `exp`) is rejected, exactly as the Go
    // reference does: `go/pkg/introspection` decodes exp/iat/nbf into `int64`
    // fields, and Go's `encoding/json` rejects any number carrying a decimal
    // point (including `1419356238.0`) into an integer, failing the whole
    // response. `as_i64()` returns `None` for a serde_json float, so this path
    // mirrors that behavior — keeping strict Go parity rather than silently
    // truncating (which would diverge from the reference).
    #[test]
    fn rejects_fractional_numeric_date() {
        let err = serde_json::from_str::<Introspection>(r#"{"active":true,"exp":1419356238.5}"#)
            .expect_err("fractional exp must fail, matching Go's int64 decode");
        assert!(err.to_string().contains("exp"), "{err}");
    }
}
