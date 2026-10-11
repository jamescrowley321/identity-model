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

    /// Resolves the key that verifies a token whose JOSE header carries `kid`
    /// and `alg`, scanning the in-memory set only.
    ///
    /// With a `kid` it is [`JsonWebKeySet::resolve_key`]. With no `kid` (an OP
    /// may omit it when its set holds a single key, OIDC Core 1.0 §10.1) the
    /// set is narrowed to signing keys (`use` absent or `sig`, RFC 7517 §4.2;
    /// if none, every key), then, while more than one remains, to keys whose
    /// `alg` is absent or equals `alg` (§4.4) and to keys whose `kty` matches
    /// `alg`, each step applied only when it leaves a key. The one remaining
    /// key is returned (JWKS-009). Callers must reject `alg` `none` first.
    ///
    /// Either way, a key that declares an `alg` other than a non-empty `alg`
    /// is not returned (JWKS-010, RFC 7517 §4.4).
    ///
    /// The fallback to every key when none is a signing key matches the
    /// Python implementation, where a `kid` naming a `use` `enc` key is also
    /// used; enforcing `use` on both paths in every language is tracked in
    /// #888.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::AmbiguousKey`] when no `kid` is given and more than
    ///   one key remains.
    /// - [`IdentityError::KeyNotFound`] when `kid` matches no key.
    /// - [`IdentityError::KeyAlgorithmMismatch`] when the resolved key
    ///   declares another `alg`.
    pub fn resolve_signing_key(&self, kid: &str, alg: &str) -> Result<&JsonWebKey> {
        let key = if kid.is_empty() {
            self.resolve_kidless(alg)?
        } else {
            self.resolve_key(kid)?
        };
        check_declared_alg(key, alg)?;
        Ok(key)
    }

    /// Selects the key for a token with no `kid`, as described on
    /// [`JsonWebKeySet::resolve_signing_key`].
    fn resolve_kidless(&self, alg: &str) -> Result<&JsonWebKey> {
        let all: Vec<&JsonWebKey> = self.keys.iter().collect();
        let mut candidates = narrow(all, |k| k.use_.is_empty() || k.use_ == "sig");
        if candidates.len() > 1 && !alg.is_empty() {
            candidates = narrow(candidates, |k| k.alg.is_empty() || k.alg == alg);
            if let Some(kty) = alg_kty(alg) {
                candidates = narrow(candidates, |k| k.kty == kty);
            }
        }
        match candidates.as_slice() {
            [] => Err(IdentityError::KeyNotFound(String::new())),
            [key] => Ok(key),
            many => Err(IdentityError::AmbiguousKey {
                alg: alg.to_string(),
                kids: many
                    .iter()
                    .filter(|k| !k.kid.is_empty())
                    .map(|k| k.kid.clone())
                    .collect(),
                count: many.len(),
            }),
        }
    }
}

/// Rejects `key` when it declares an `alg` other than a non-empty token `alg`
/// (JWKS-010, RFC 7517 §4.4).
pub(crate) fn check_declared_alg(key: &JsonWebKey, alg: &str) -> Result<()> {
    if alg.is_empty() || key.alg.is_empty() || key.alg == alg {
        return Ok(());
    }
    Err(IdentityError::KeyAlgorithmMismatch {
        kid: key.kid.clone(),
        key_alg: key.alg.clone(),
        alg: alg.to_string(),
    })
}

/// Returns the keys that satisfy `keep`, or `keys` unchanged when none does.
fn narrow(keys: Vec<&JsonWebKey>, keep: impl Fn(&JsonWebKey) -> bool) -> Vec<&JsonWebKey> {
    let kept: Vec<&JsonWebKey> = keys.iter().copied().filter(|k| keep(k)).collect();
    if kept.is_empty() { keys } else { kept }
}

/// The JWK `kty` that can verify a JWS `alg` (RFC 7518 §3.1).
fn alg_kty(alg: &str) -> Option<&'static str> {
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Some("RSA"),
        "ES256" | "ES384" | "ES512" | "ES256K" => Some("EC"),
        "EdDSA" | "Ed25519" | "Ed448" => Some("OKP"),
        "HS256" | "HS384" | "HS512" => Some("oct"),
        _ => None,
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

    /// Fixture JWK Sets shared with the spec vectors (JWKS-009).
    fn kidless_fixture(name: &str) -> JsonWebKeySet {
        let path = format!(
            "{}/../spec/test-fixtures/jwks/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let body = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        JsonWebKeySet::parse(&body).expect("fixture parses")
    }

    // JWKS-009: with no kid, the single key left after narrowing by use, alg
    // and kty is selected.
    #[test]
    fn resolve_signing_key_without_kid_narrows_to_one_key() {
        let cases = [
            ("kidless-single.json", "RS256", "rsa-sig-key"),
            ("kidless-sig-enc.json", "RS256", "rsa-sig-key"),
            ("kidless-rsa-ec.json", "RS256", "rsa-sig-key"),
            ("kidless-rsa-ec.json", "ES256", "ec-sig-key"),
        ];
        for (fixture, alg, want) in cases {
            let set = kidless_fixture(fixture);
            let key = set
                .resolve_signing_key("", alg)
                .unwrap_or_else(|e| panic!("{fixture} {alg}: {e}"));
            assert_eq!(key.kid, want, "{fixture} {alg}");
        }
    }

    // JWKS-009: a key declaring a different alg does not make the choice
    // ambiguous (RFC 7517 §4.4), and a set with no signing key falls back to
    // every key.
    #[test]
    fn resolve_signing_key_without_kid_alg_filter_and_fallback() {
        let by_alg = JsonWebKeySet::parse(
            br#"{ "keys": [
                {"kty":"RSA","kid":"rs256","use":"sig","alg":"RS256","n":"a","e":"AQAB"},
                {"kty":"RSA","kid":"rs384","use":"sig","alg":"RS384","n":"a","e":"AQAB"}
            ] }"#,
        )
        .expect("parses");
        assert_eq!(
            by_alg.resolve_signing_key("", "RS384").expect("rs384").kid,
            "rs384"
        );

        let enc_only = JsonWebKeySet::parse(
            br#"{ "keys": [ {"kty":"RSA","kid":"enc-only","use":"enc","n":"a","e":"AQAB"} ] }"#,
        )
        .expect("parses");
        assert_eq!(
            enc_only
                .resolve_signing_key("", "RS256")
                .expect("fallback")
                .kid,
            "enc-only"
        );
    }

    // JWKS-009: two keys that could verify a kid-less token are ambiguous, a
    // typed error distinct from KeyNotFound.
    #[test]
    fn resolve_signing_key_without_kid_ambiguous() {
        let set = kidless_fixture("kidless-two-rsa.json");
        let err = set
            .resolve_signing_key("", "RS256")
            .expect_err("two RSA signing keys are ambiguous");
        match err {
            IdentityError::AmbiguousKey { alg, kids, count } => {
                assert_eq!(alg, "RS256");
                assert_eq!(
                    kids,
                    vec!["rsa-sig-key-1".to_string(), "rsa-sig-key-2".to_string()]
                );
                assert_eq!(count, 2);
            }
            other => panic!("expected AmbiguousKey, got {other:?}"),
        }
    }

    // JWKS-010: a key declaring an alg other than the token's is not used,
    // whether found by kid or selected without one; one declaring the token's
    // alg is.
    #[test]
    fn resolve_signing_key_rejects_key_declaring_other_alg() {
        let set = kidless_fixture("single-rs384.json");
        for kid in ["rsa-rs384-key", ""] {
            let err = set
                .resolve_signing_key(kid, "RS256")
                .expect_err("key declares RS384");
            match err {
                IdentityError::KeyAlgorithmMismatch {
                    kid: got,
                    key_alg,
                    alg,
                } => {
                    assert_eq!(
                        (got.as_str(), key_alg.as_str(), alg.as_str()),
                        ("rsa-rs384-key", "RS384", "RS256"),
                        "kid {kid:?}"
                    );
                }
                other => panic!("kid {kid:?}: expected KeyAlgorithmMismatch, got {other:?}"),
            }
            assert_eq!(
                set.resolve_signing_key(kid, "RS384")
                    .unwrap_or_else(|e| panic!("kid {kid:?} RS384: {e}"))
                    .kid,
                "rsa-rs384-key"
            );
        }
    }

    // A token with a kid keeps the kid lookup.
    #[test]
    fn resolve_signing_key_with_kid_looks_up_kid() {
        let set = kidless_fixture("kidless-two-rsa.json");
        assert_eq!(
            set.resolve_signing_key("rsa-sig-key-2", "RS256")
                .expect("by kid")
                .kid,
            "rsa-sig-key-2"
        );
        let err = set
            .resolve_signing_key("ghost", "RS256")
            .expect_err("unknown kid");
        assert!(
            matches!(&err, IdentityError::KeyNotFound(kid) if kid == "ghost"),
            "{err:?}"
        );
    }
}
