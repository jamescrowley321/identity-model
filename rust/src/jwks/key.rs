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
    #[serde(default)]
    pub kty: String,
    /// Key ID used to select a key by the `kid` JOSE header (§4.5).
    #[serde(default, rename = "kid", skip_serializing_if = "String::is_empty")]
    pub kid: String,
    /// Public key use, e.g. `sig` (§4.2).
    #[serde(default, rename = "use", skip_serializing_if = "String::is_empty")]
    pub use_: String,
    /// Algorithm the key is intended for, e.g. `RS256` (§4.4).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alg: String,

    /// RSA modulus (RFC 7518 §6.3.1).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub n: String,
    /// RSA exponent (RFC 7518 §6.3.1).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub e: String,

    /// EC curve, e.g. `P-256` (RFC 7518 §6.2.1).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub crv: String,
    /// EC x coordinate (RFC 7518 §6.2.1).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String,
    /// EC y coordinate (RFC 7518 §6.2.1).
    #[serde(default, skip_serializing_if = "String::is_empty")]
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
    /// - [`IdentityError::Validation`] — a key is missing required parameters, or
    ///   the set contains no keys (JWKS-007).
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        // JWKS-007: a non-JSON body, or one whose "keys" member is not an array,
        // is a deserialization error.
        let set: JsonWebKeySet = serde_json::from_slice(body)
            .map_err(|e| IdentityError::Deserialization(format!("parse JWK Set: {e}")))?;

        // JWKS-002: every key must carry the parameters its type requires.
        for key in &set.keys {
            key.validate()?;
        }

        // JWKS-007: an empty (or absent) key set yields no usable keys.
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
