//! JSON Web Key and JWK Set data model (RFC 7517 §4, §5).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{IdentityError, Result};

/// A single JSON Web Key (RFC 7517 §4).
///
/// The common signing-key parameters are modelled as fields; key-type-specific
/// material is exposed as base64url-encoded strings (RFC 7518) for a later
/// verifier to decode into public-key material (JWKS-002). Per RFC 7517 §4 the
/// only universally required member is `kty`; `kid`/`use`/`alg` are optional and
/// omitted by some providers. Parameters not modelled here are preserved in
/// [`JsonWebKey::extra`] so unknown members are ignored, not rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type, e.g. `RSA` or `EC` (RFC 7517 §4.1, required).
    #[serde(default, deserialize_with = "null_as_empty")]
    pub kty: String,
    /// Key ID used to select a key by the `kid` JOSE header (§4.5).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        rename = "kid",
        skip_serializing_if = "String::is_empty"
    )]
    pub kid: String,
    /// Public key use, e.g. `sig` (§4.2).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        rename = "use",
        skip_serializing_if = "String::is_empty"
    )]
    pub use_: String,
    /// Algorithm the key is intended for, e.g. `RS256` (§4.4).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub alg: String,

    /// RSA modulus (RFC 7518 §6.3.1).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub n: String,
    /// RSA exponent (RFC 7518 §6.3.1).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub e: String,

    /// EC curve, e.g. `P-256` (RFC 7518 §6.2.1).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub crv: String,
    /// EC x coordinate (RFC 7518 §6.2.1).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub x: String,
    /// EC y coordinate (RFC 7518 §6.2.1).
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "String::is_empty"
    )]
    pub y: String,

    /// Key parameters not modelled above (e.g. `x5c`, `x5t`). Preserved so
    /// unknown members are ignored rather than rejected (RFC 7517 §4).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl JsonWebKey {
    /// Enforces the required parameters for a key (JWKS-002, RFC 7517 §4).
    ///
    /// `kty` is the only universally required member; key-type-specific material
    /// must be present so a later verifier can construct a public key: RSA needs
    /// `n` and `e`, EC needs `crv`, `x`, and `y`. Other key types (e.g. `oct`,
    /// `OKP`) are accepted without parameter checks; their material is preserved
    /// in [`JsonWebKey::extra`].
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] when a required parameter is missing.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.kty.is_empty() {
            return Err(IdentityError::Validation(
                "JWK is missing required parameter \"kty\"".to_string(),
            ));
        }
        match self.kty.as_str() {
            "RSA" if self.n.is_empty() || self.e.is_empty() => {
                Err(IdentityError::Validation(format!(
                    "RSA key {:?} is missing modulus \"n\" or exponent \"e\"",
                    self.kid
                )))
            }
            "EC" if self.crv.is_empty() || self.x.is_empty() || self.y.is_empty() => {
                Err(IdentityError::Validation(format!(
                    "EC key {:?} is missing curve \"crv\", \"x\", or \"y\"",
                    self.kid
                )))
            }
            _ => Ok(()),
        }
    }
}

/// Deserializes an optional string, treating an explicit JSON `null` as absent
/// (JWKS-008), the same as a missing member.
fn null_as_empty<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// A parsed JWK Set (RFC 7517 §5). `keys` holds the keys in document order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    /// The keys in the set, in document order.
    #[serde(default)]
    pub keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    /// Parses and validates a JWK Set document body (JWKS-001/002/007).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Deserialization`] — the body is not a valid JWK Set
    ///   document (JWKS-007).
    /// - [`IdentityError::Validation`] — no key in the set is usable: every key is
    ///   missing required parameters, or the set is empty (JWKS-007). Individual
    ///   unusable keys are skipped (JWKS-008).
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        // JWKS-007: a non-JSON body, or one whose "keys" member is not an array,
        // is a deserialization error.
        #[derive(Deserialize)]
        struct RawSet {
            #[serde(default)]
            keys: Vec<serde_json::Value>,
        }
        let raw: RawSet = serde_json::from_slice(body)
            .map_err(|e| IdentityError::Deserialization(format!("parse JWK Set: {e}")))?;

        // JWKS-002: a key must carry the parameters its type requires.
        // JWKS-008 (RFC 7517 §5): one that doesn't, or that has a mistyped
        // parameter, is skipped rather than failing the set, so an unusable key
        // cannot block a usable one. A member that is not a JSON object still
        // leaves the document malformed (JWKS-007).
        let mut set = JsonWebKeySet { keys: Vec::new() };
        let mut first_invalid = None;
        for member in raw.keys {
            if !member.is_object() {
                return Err(IdentityError::Deserialization(format!(
                    "parse JWK Set: member is not an object: {member}"
                )));
            }
            let checked = serde_json::from_value::<JsonWebKey>(member)
                .map_err(|e| {
                    IdentityError::Validation(format!("JWK has a mistyped parameter: {e}"))
                })
                .and_then(|key| key.validate().map(|()| key));
            match checked {
                Ok(key) => set.keys.push(key),
                Err(e) => {
                    first_invalid.get_or_insert(e);
                }
            }
        }

        // No usable key: report why the keys were rejected, else JWKS-007's
        // empty-set error.
        if let Some(e) = first_invalid.filter(|_| set.keys.is_empty()) {
            return Err(e);
        }
        if set.keys.is_empty() {
            return Err(IdentityError::Validation(
                "JWK Set contains no keys".to_string(),
            ));
        }
        Ok(set)
    }

    /// Returns the keys in the set, in document order.
    pub fn keys(&self) -> &[JsonWebKey] {
        &self.keys
    }

    /// Returns the key whose `kid` matches, scanning the in-memory set only
    /// (RFC 7517 §4.5). Makes no network request.
    pub fn find(&self, kid: &str) -> Option<&JsonWebKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Resolves the key whose `kid` matches (JWKS-003, RFC 7517 §4.5).
    ///
    /// # Errors
    ///
    /// [`IdentityError::KeyNotFound`] when no key in the set has the given `kid`.
    pub fn resolve_key(&self, kid: &str) -> Result<&JsonWebKey> {
        self.find(kid)
            .ok_or_else(|| IdentityError::KeyNotFound(kid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SET: &str = r#"{
        "keys": [
            {"kty":"RSA","kid":"rsa-sig-key","use":"sig","alg":"RS256",
             "n":"0vx7ag","e":"AQAB","x5t":"ignored-extra"},
            {"kty":"EC","kid":"ec-sig-key","use":"sig","alg":"ES256",
             "crv":"P-256","x":"f83OJ3","y":"x_FEzR"}
        ]
    }"#;

    // JWKS-001 / JWKS-002: a valid set parses; each key exposes kty/kid/use/alg,
    // RSA exposes n/e, EC exposes crv/x/y, and unmodelled members land in extra.
    #[test]
    fn parses_rsa_and_ec_keys() {
        let set = JsonWebKeySet::parse(VALID_SET.as_bytes()).expect("valid set parses");
        assert_eq!(set.keys().len(), 2);

        let rsa = set.resolve_key("rsa-sig-key").expect("rsa key present");
        assert_eq!(rsa.kty, "RSA");
        assert_eq!(rsa.use_, "sig");
        assert_eq!(rsa.alg, "RS256");
        assert!(!rsa.n.is_empty() && !rsa.e.is_empty());
        assert!(rsa.extra.contains_key("x5t"), "unmodelled param preserved");

        let ec = set.resolve_key("ec-sig-key").expect("ec key present");
        assert_eq!(ec.kty, "EC");
        assert_eq!(ec.crv, "P-256");
        assert!(!ec.x.is_empty() && !ec.y.is_empty());
    }

    // JWKS-003: resolving an absent kid is a KeyNotFound error.
    #[test]
    fn resolve_missing_kid_errors() {
        let set = JsonWebKeySet::parse(VALID_SET.as_bytes()).expect("valid set parses");
        let err = set.resolve_key("absent").expect_err("missing kid errors");
        match err {
            IdentityError::KeyNotFound(kid) => assert_eq!(kid, "absent"),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    // JWKS-007: an empty key set is a validation error.
    #[test]
    fn rejects_empty_key_set() {
        let err = JsonWebKeySet::parse(br#"{ "keys": [] }"#).expect_err("empty set errors");
        assert!(
            matches!(err, IdentityError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    // JWKS-007: a non-JSON body is a deserialization error.
    #[test]
    fn rejects_malformed_json() {
        let err = JsonWebKeySet::parse(b"not-json").expect_err("malformed body errors");
        assert!(
            matches!(err, IdentityError::Deserialization(_)),
            "expected Deserialization, got {err:?}"
        );
    }

    // JWKS-002 negative: an RSA key missing its exponent is rejected.
    #[test]
    fn rejects_invalid_key_missing_params() {
        let body = br#"{ "keys": [ {"kty":"RSA","kid":"bad","n":"abc"} ] }"#;
        let err = JsonWebKeySet::parse(body).expect_err("incomplete RSA key errors");
        match err {
            IdentityError::Validation(msg) => assert!(msg.contains('e'), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    // JWKS-008: keys the client cannot use are skipped, not fatal. The fixture
    // carries the OpenID conformance suite's unusable keys plus an RSA key
    // missing its modulus beside the real signing key.
    #[test]
    fn skips_unusable_keys() {
        let body = include_str!("../../../spec/test-fixtures/jwks/unusable-keys.json");
        let set = JsonWebKeySet::parse(body.as_bytes()).expect("usable key survives");

        assert!(set.find("rsa-sig-key").is_some(), "signing key resolves");
        assert!(
            set.find("usable-rsa-null-alg").is_some(),
            "null counts as absent"
        );
        for kid in [
            "unusable-rsa-missing-n",
            "unusable-rsa-mistyped-use",
            "unusable-rsa-mistyped-n",
        ] {
            assert!(set.find(kid).is_none(), "{kid} is skipped");
        }
    }

    // JWKS-007: a member that is not a JSON object leaves the document
    // malformed; unlike an unusable key (JWKS-008) it is not skipped.
    #[test]
    fn non_object_member_is_deserialization_error() {
        for member in ["null", r#""key""#] {
            let body = format!(
                r#"{{ "keys": [ {member}, {{"kty":"RSA","kid":"good","n":"a","e":"AQAB"}} ] }}"#
            );
            let err = JsonWebKeySet::parse(body.as_bytes()).expect_err("non-object errors");
            assert!(
                matches!(err, IdentityError::Deserialization(_)),
                "{member}: expected Deserialization, got {err:?}"
            );
        }
    }

    // A key missing kty is rejected (RFC 7517 §4.1).
    #[test]
    fn rejects_key_missing_kty() {
        let body = br#"{ "keys": [ {"kid":"no-kty","alg":"RS256"} ] }"#;
        let err = JsonWebKeySet::parse(body).expect_err("missing kty errors");
        match err {
            IdentityError::Validation(msg) => assert!(msg.contains("kty"), "{msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
