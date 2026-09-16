//! DPoP key pairs (RFC 9449 §4.1) and their RFC 7638 JWK thumbprints.

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_PAD, URL_SAFE_NO_PAD};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use p256::pkcs8::EncodePrivateKey;
use serde::Deserialize;

use crate::jwks::JsonWebKey;
use crate::{IdentityError, Result};

/// How many times [`DpopAlgorithm::Es256`] generation re-draws from the CSPRNG
/// before giving up. A uniform 32-byte draw lands outside the valid P-256 scalar
/// range `[1, n-1]` with probability below 2^-32, so a single retry is already
/// beyond reach; the loop exists so the failure is an error rather than a panic.
const EC_SCALAR_DRAWS: usize = 8;

/// The PEM label PKCS#8 private keys carry (RFC 7468 §10).
const PKCS8_PEM_LABEL: &str = "PRIVATE KEY";

/// A DPoP proof signing algorithm.
///
/// DPoP requires an **asymmetric** algorithm (RFC 9449 §4.2); a symmetric one
/// such as `HS256` would let anyone holding the shared secret mint proofs, which
/// defeats the whole point of sender-constraining a token. These are the two
/// RFC 9449 §4.1 expects every implementation to provide.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DpopAlgorithm {
    /// ECDSA using P-256 and SHA-256 (RFC 7518 §3.4). Keys are EC P-256.
    Es256,
    /// RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3). Keys are RSA of at least
    /// 2048 bits.
    Rs256,
}

impl DpopAlgorithm {
    /// Returns the JWA algorithm name (RFC 7518 §3.1), the value that appears in
    /// a proof's `alg` header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }

    /// The `jsonwebtoken` algorithm this maps to. Internal: the crate keeps
    /// `jsonwebtoken` types out of its public surface.
    pub(crate) const fn jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
        }
    }
}

impl fmt::Display for DpopAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DpopAlgorithm {
    type Err = IdentityError;

    /// Parses a JWA algorithm name into a DPoP algorithm (DPOP-007).
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] for anything other than `ES256` or
    /// `RS256` — including the symmetric algorithms and `none`, which
    /// RFC 9449 §4.2 forbids for proofs.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ES256" => Ok(Self::Es256),
            "RS256" => Ok(Self::Rs256),
            other => Err(IdentityError::Configuration(format!(
                "unsupported DPoP algorithm {other:?}: DPoP proofs require an \
                 asymmetric algorithm, either \"ES256\" or \"RS256\" \
                 (RFC 9449 §4.1)"
            ))),
        }
    }
}

/// The private-key JWK members [`DpopKey::from_private_jwk`] reads (RFC 7517 §4,
/// RFC 7518 §6.2.2 / §6.3.2). Kept private: it exists to carry key material in,
/// not to be part of the public surface.
#[derive(Deserialize)]
struct PrivateJwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: String,
    #[serde(default)]
    crv: String,
    // EC private key (RFC 7518 §6.2.2).
    #[serde(default)]
    d: String,
    // RSA public half (RFC 7518 §6.3.1).
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    // RSA private half, including the CRT members (RFC 7518 §6.3.2).
    #[serde(default)]
    p: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    dp: String,
    #[serde(default)]
    dq: String,
    #[serde(default)]
    qi: String,
}

/// A DPoP key pair: the private key that signs proof JWTs, plus its algorithm.
///
/// The public half is embedded in every proof's `jwk` header (RFC 9449 §4.2) and
/// its RFC 7638 thumbprint ([`DpopKey::thumbprint`]) is the value an
/// authorization server binds a token to via `cnf.jkt` (RFC 9449 §6).
///
/// Create one with [`DpopKey::generate`], or load a persisted one with
/// [`DpopKey::from_pkcs8_pem`], [`DpopKey::from_pkcs8_der`], or
/// [`DpopKey::from_private_jwk`]. Persist one with [`DpopKey::to_pkcs8_pem`] so
/// it survives a restart: a key that outlives the process can be rotated without
/// invalidating already-issued bound tokens.
#[derive(Clone)]
pub struct DpopKey {
    algorithm: DpopAlgorithm,
    /// The signing key handed to `jsonwebtoken`.
    encoding: EncodingKey,
    /// The public half, derived once at construction.
    public: Jwk,
    /// The PKCS#8 DER form, retained so the key can be re-serialized.
    pkcs8: Vec<u8>,
}

/// Prints only the algorithm and the public thumbprint. Private key material is
/// deliberately absent so a `{:?}` of a key — or of any struct holding one —
/// cannot leak it into a log.
impl fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopKey")
            .field("algorithm", &self.algorithm.as_str())
            .field(
                "thumbprint",
                &self.thumbprint().unwrap_or_else(|_| "<unavailable>".into()),
            )
            .finish_non_exhaustive()
    }
}

impl DpopKey {
    /// Generates a fresh DPoP key pair (RFC 9449 §4.1, DPOP-007).
    ///
    /// [`DpopAlgorithm::Es256`] produces an EC P-256 key and
    /// [`DpopAlgorithm::Rs256`] a 2048-bit RSA key. Entropy comes from the
    /// operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if the system random source is
    /// unavailable or key generation fails.
    pub fn generate(algorithm: DpopAlgorithm) -> Result<Self> {
        let pkcs8 = match algorithm {
            DpopAlgorithm::Es256 => generate_p256_pkcs8()?,
            DpopAlgorithm::Rs256 => generate_rsa_pkcs8()?,
        };
        Self::from_pkcs8_der(&pkcs8, algorithm)
    }

    /// Loads a key pair from a PKCS#8 DER private key, tagging it `algorithm`.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] if the DER is not a private key of the type
    /// `algorithm` requires, or if an RSA modulus is shorter than
    /// 2048 bits (RFC 7518 §3.3).
    pub fn from_pkcs8_der(der: &[u8], algorithm: DpopAlgorithm) -> Result<Self> {
        // The two families want different byte formats. EC takes the PKCS#8 DER
        // as-is; RSA signing goes through `signature::RsaKeyPair::from_der`,
        // which wants the *inner* PKCS#1 `RSAPrivateKey`. Rather than unwrap the
        // PKCS#8 here, hand jsonwebtoken the PEM form — its PEM decoder already
        // extracts that inner structure.
        let encoding = match algorithm {
            DpopAlgorithm::Es256 => EncodingKey::from_ec_der(der),
            DpopAlgorithm::Rs256 => EncodingKey::from_rsa_pem(
                pem_encode(PKCS8_PEM_LABEL, der).as_bytes(),
            )
            .map_err(|e| {
                IdentityError::Validation(format!(
                    "load DPoP RS256 key: not a valid PKCS#8 RSA private key: {e}"
                ))
            })?,
        };

        // Deriving the public half is also what enforces that the DER holds a key
        // of the right shape, so there is no separate strength check below. The
        // backend has to read the private components to compute the public ones,
        // and it rejects what DPoP would have to reject anyway: an RSA modulus
        // under 2048 bits comes back `TooSmall` (RFC 7518 §3.3) and an EC key on
        // any curve but P-256 comes back `InvalidEcdsaKey`, as does an RSA key
        // labelled ES256 or vice versa. `key_strength_is_enforced_by_the_backend`
        // in this module's tests pins each of those, so a backend that relaxes one
        // fails the suite rather than silently widening what DPoP accepts.
        let public = Jwk::from_encoding_key(&encoding, algorithm.jwt()).map_err(|e| {
            IdentityError::Validation(format!(
                "load DPoP {algorithm} key: cannot derive the public key: {e}"
            ))
        })?;

        Ok(Self {
            algorithm,
            encoding,
            public,
            pkcs8: der.to_vec(),
        })
    }

    /// Loads a key pair from a PKCS#8 PEM private key, tagging it `algorithm`.
    ///
    /// Pair it with [`DpopKey::to_pkcs8_pem`] to round-trip a persisted key.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] if `pem` is not a single PKCS#8
    /// `PRIVATE KEY` block holding a key of the type `algorithm` requires.
    pub fn from_pkcs8_pem(pem: &str, algorithm: DpopAlgorithm) -> Result<Self> {
        let der = pem_decode(pem, PKCS8_PEM_LABEL)?;
        Self::from_pkcs8_der(&der, algorithm)
    }

    /// Loads a key pair from a **private** JWK document (RFC 7517 §4,
    /// RFC 7518 §6.2.2 / §6.3.2).
    ///
    /// The JWK's `alg` member selects the algorithm when present; otherwise it is
    /// inferred from `kty` (`EC` → ES256, `RSA` → RS256). An RSA JWK must carry
    /// the full Chinese-Remainder set — `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`
    /// — because the backend validates the components against each other rather
    /// than recomputing them.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Deserialization`] — `jwk` is not valid JSON.
    /// - [`IdentityError::Validation`] — a required member is missing, a member
    ///   is not valid base64url, or the components do not form a usable key.
    /// - [`IdentityError::Configuration`] — the `alg` member names an algorithm
    ///   DPoP does not allow.
    pub fn from_private_jwk(jwk: &str) -> Result<Self> {
        let parsed: PrivateJwk = serde_json::from_str(jwk)
            .map_err(|e| IdentityError::Deserialization(format!("parse DPoP private JWK: {e}")))?;

        let algorithm = if parsed.alg.is_empty() {
            match parsed.kty.as_str() {
                "EC" => DpopAlgorithm::Es256,
                "RSA" => DpopAlgorithm::Rs256,
                other => {
                    return Err(IdentityError::Validation(format!(
                        "DPoP private JWK has key type {other:?}: expected \"EC\" or \"RSA\""
                    )));
                }
            }
        } else {
            parsed.alg.parse()?
        };

        let pkcs8 = match algorithm {
            DpopAlgorithm::Es256 => ec_jwk_to_pkcs8(&parsed)?,
            DpopAlgorithm::Rs256 => rsa_jwk_to_pkcs8(&parsed)?,
        };
        Self::from_pkcs8_der(&pkcs8, algorithm)
    }

    /// Returns the key's DPoP signing algorithm.
    pub const fn algorithm(&self) -> DpopAlgorithm {
        self.algorithm
    }

    /// Returns the public half as a JWK — the form embedded in a proof's `jwk`
    /// header (RFC 9449 §4.2). It carries no private material.
    pub fn public_jwk(&self) -> JsonWebKey {
        let mut key = JsonWebKey {
            kty: String::new(),
            kid: String::new(),
            use_: "sig".to_string(),
            alg: self.algorithm.as_str().to_string(),
            n: String::new(),
            e: String::new(),
            crv: String::new(),
            x: String::new(),
            y: String::new(),
            extra: std::collections::HashMap::new(),
        };
        match &self.public.algorithm {
            AlgorithmParameters::EllipticCurve(ec) => {
                key.kty = "EC".to_string();
                key.crv = curve_name(&ec.curve);
                key.x = ec.x.clone();
                key.y = ec.y.clone();
            }
            AlgorithmParameters::RSA(rsa) => {
                key.kty = "RSA".to_string();
                key.n = rsa.n.clone();
                key.e = rsa.e.clone();
            }
            // Unreachable: the constructors only admit EC P-256 and RSA keys.
            // Leaving `kty` empty rather than panicking keeps a library
            // invariant violation from taking the caller's process down.
            _ => {}
        }
        key
    }

    /// Returns the RFC 7638 SHA-256 JWK thumbprint of the public key,
    /// base64url-encoded without padding.
    ///
    /// This is the value an authorization server places in a DPoP-bound token's
    /// `cnf.jkt` (RFC 9449 §6, DPOP-005); compare it against that claim to
    /// confirm a token is bound to this key.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] if the thumbprint cannot be computed.
    pub fn thumbprint(&self) -> Result<String> {
        self.public
            .thumbprint(ThumbprintHash::SHA256)
            .map_err(|e| IdentityError::Validation(format!("compute DPoP key thumbprint: {e}")))
    }

    /// Returns the private key in PKCS#8 DER form, for persistence.
    pub fn to_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Returns the private key as a PKCS#8 `PRIVATE KEY` PEM block, for
    /// persistence. Pair it with [`DpopKey::from_pkcs8_pem`] to reload.
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PKCS8_PEM_LABEL, &self.pkcs8)
    }

    /// The signing key, for [`crate::dpop`]'s proof builder.
    pub(crate) const fn encoding_key(&self) -> &EncodingKey {
        &self.encoding
    }

    /// The public JWK in `jsonwebtoken`'s representation, for embedding in a
    /// proof header.
    pub(crate) const fn embedded_jwk(&self) -> &Jwk {
        &self.public
    }
}

/// Computes the RFC 7638 SHA-256 JWK thumbprint of a **public** JWK,
/// base64url-encoded without padding (DPOP-005).
///
/// Use this to check a DPoP-bound token's `cnf.jkt` against a public key you
/// hold as a JWK rather than as a [`DpopKey`] — a resource server verifying a
/// proof it just accepted, for instance, against
/// [`crate::DpopProof::public_jwk`]. For a key you hold the private half of,
/// [`DpopKey::thumbprint`] is the direct route.
///
/// The thumbprint covers only the required members in lexicographic order
/// (RFC 7638 §3.2), so `kid`, `use`, and `alg` do not affect it: two JWKs
/// describing the same key produce the same thumbprint whatever their metadata.
///
/// # Errors
///
/// [`IdentityError::Validation`] if `key` is not a JWK whose thumbprint is
/// defined — an unsupported `kty`, or a key missing the members its type
/// requires.
///
/// # Examples
///
/// ```
/// use rs_identity_model::{JsonWebKey, jwk_thumbprint};
///
/// # fn main() -> rs_identity_model::Result<()> {
/// // The RFC 7638 §3.1 canonical example key.
/// let key: JsonWebKey = serde_json::from_str(
///     r#"{"kty":"RSA","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#,
/// )
/// .expect("the RFC 7638 example key parses");
/// assert_eq!(jwk_thumbprint(&key)?, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
/// # Ok(())
/// # }
/// ```
pub fn jwk_thumbprint(key: &JsonWebKey) -> Result<String> {
    // Go via JSON rather than matching on `kty` by hand: the JWK member names are
    // identical on both sides, so serde does the mapping and a key type added to
    // either representation later needs no change here.
    let value = serde_json::to_value(key)
        .map_err(|e| IdentityError::Validation(format!("serialize JWK for thumbprint: {e}")))?;
    let jwk: Jwk = serde_json::from_value(value).map_err(|e| {
        IdentityError::Validation(format!(
            "JWK thumbprint is not defined for this key: {e} (RFC 7638 §3.2)"
        ))
    })?;
    jwk.thumbprint(ThumbprintHash::SHA256)
        .map_err(|e| IdentityError::Validation(format!("compute JWK thumbprint: {e}")))
}

/// Returns the RFC 7518 §6.2.1.1 `crv` name for a curve.
///
/// `EllipticCurve` is `#[non_exhaustive]`, so a curve `jsonwebtoken` adds later
/// falls back to its own serde name rather than silently becoming the wrong
/// curve or panicking.
pub(crate) fn curve_name(curve: &EllipticCurve) -> String {
    match curve {
        EllipticCurve::P256 => "P-256".to_string(),
        EllipticCurve::P384 => "P-384".to_string(),
        EllipticCurve::P521 => "P-521".to_string(),
        EllipticCurve::Ed25519 => "Ed25519".to_string(),
        other => serde_json::to_value(other)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
    }
}

/// Generates an EC P-256 private key in PKCS#8 DER form.
fn generate_p256_pkcs8() -> Result<Vec<u8>> {
    // p256 exposes no CSPRNG-free constructor, and pulling `rand` in for one
    // scalar is not worth it: draw 32 uniform bytes from the OS CSPRNG the way
    // `PkceChallenge::generate` does and let `from_slice` enforce the valid
    // scalar range, re-drawing on the (vanishingly rare) rejection.
    let mut seed = [0u8; 32];
    for _ in 0..EC_SCALAR_DRAWS {
        getrandom::fill(&mut seed)
            .map_err(|e| IdentityError::Configuration(format!("generate DPoP ES256 key: {e}")))?;
        let secret = p256::SecretKey::from_slice(&seed);
        seed.fill(0);
        if let Ok(secret) = secret {
            return secret
                .to_pkcs8_der()
                .map(|der| der.as_bytes().to_vec())
                .map_err(|e| {
                    IdentityError::Configuration(format!(
                        "generate DPoP ES256 key: encode PKCS#8: {e}"
                    ))
                });
        }
    }
    Err(IdentityError::Configuration(format!(
        "generate DPoP ES256 key: {EC_SCALAR_DRAWS} draws from the system CSPRNG all fell \
         outside the valid P-256 scalar range, which suggests the random source is broken"
    )))
}

/// Generates a 2048-bit RSA private key in PKCS#8 DER form. 2048 is the
/// RFC 7518 §3.3 minimum for RS256 and the minimum DPOP-007 asserts; it is also
/// the smallest size `aws_lc_rs::rsa::KeySize` offers, so there is no way to
/// generate a key this crate would then refuse to load.
fn generate_rsa_pkcs8() -> Result<Vec<u8>> {
    let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .map_err(|e| IdentityError::Configuration(format!("generate DPoP RS256 key: {e}")))?;
    let der: Pkcs8V1Der<'static> = pair.as_der().map_err(|e| {
        IdentityError::Configuration(format!("generate DPoP RS256 key: encode PKCS#8: {e}"))
    })?;
    Ok(der.as_ref().to_vec())
}

/// Converts an EC private JWK to PKCS#8 DER via its `d` scalar.
fn ec_jwk_to_pkcs8(jwk: &PrivateJwk) -> Result<Vec<u8>> {
    if !jwk.crv.is_empty() && jwk.crv != "P-256" {
        return Err(IdentityError::Validation(format!(
            "DPoP ES256 requires curve P-256, got {:?}",
            jwk.crv
        )));
    }
    let d = decode_b64url(&jwk.d, "d")?;
    let secret = p256::SecretKey::from_slice(&d).map_err(|e| {
        IdentityError::Validation(format!(
            "DPoP private JWK member \"d\" is not a valid P-256 scalar: {e}"
        ))
    })?;
    secret
        .to_pkcs8_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|e| IdentityError::Validation(format!("encode DPoP ES256 key as PKCS#8: {e}")))
}

/// Converts an RSA private JWK to PKCS#8 DER via its CRT components.
fn rsa_jwk_to_pkcs8(jwk: &PrivateJwk) -> Result<Vec<u8>> {
    let components = aws_lc_rs::rsa::KeyPairComponents {
        public_key: aws_lc_rs::rsa::PublicKeyComponents {
            n: decode_b64url(&jwk.n, "n")?,
            e: decode_b64url(&jwk.e, "e")?,
        },
        d: decode_b64url(&jwk.d, "d")?,
        p: decode_b64url(&jwk.p, "p")?,
        q: decode_b64url(&jwk.q, "q")?,
        dP: decode_b64url(&jwk.dp, "dp")?,
        dQ: decode_b64url(&jwk.dq, "dq")?,
        qInv: decode_b64url(&jwk.qi, "qi")?,
    };
    let pair = aws_lc_rs::rsa::KeyPair::from_components(&components).map_err(|e| {
        IdentityError::Validation(format!(
            "DPoP private JWK does not form a valid RSA key: {e}. An RSA JWK must carry \
             \"n\", \"e\", \"d\", \"p\", \"q\", \"dp\", \"dq\", and \"qi\" \
             (RFC 7518 §6.3.2), and the components must be consistent"
        ))
    })?;
    let der: Pkcs8V1Der<'static> = pair
        .as_der()
        .map_err(|e| IdentityError::Validation(format!("encode DPoP RS256 key as PKCS#8: {e}")))?;
    Ok(der.as_ref().to_vec())
}

/// Decodes a base64url JWK member, naming it in the error.
fn decode_b64url(value: &str, member: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Err(IdentityError::Validation(format!(
            "DPoP private JWK is missing required member {member:?}"
        )));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|e| {
        IdentityError::Validation(format!(
            "DPoP private JWK member {member:?} is not valid base64url: {e}"
        ))
    })
}

/// Wraps DER in a PEM block with `label` (RFC 7468 §2): 64-character base64
/// lines between the BEGIN/END markers.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = BASE64_PAD.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / 64 + 2 * label.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in body.as_bytes().chunks(64) {
        // `chunks` of a base64 string always split on character boundaries.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Extracts the DER from a PEM block, requiring it to carry `label`.
fn pem_decode(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| IdentityError::Validation(format!("PEM input has no {begin:?} block")))?;
    let body_start = start + begin.len();
    let body_end = pem[body_start..]
        .find(&end)
        .map(|i| body_start + i)
        .ok_or_else(|| IdentityError::Validation(format!("PEM block is missing {end:?}")))?;
    let body: String = pem[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    BASE64_PAD
        .decode(body)
        .map_err(|e| IdentityError::Validation(format!("PEM body is not valid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PEM encoding round-trips, wraps at 64 characters (RFC 7468 §2), and rejects
    /// a block carrying the wrong label.
    #[test]
    fn pem_round_trips_and_checks_the_label() {
        let der: Vec<u8> = (0u8..=255).collect();
        let pem = pem_encode(PKCS8_PEM_LABEL, &der);
        assert_eq!(pem_decode(&pem, PKCS8_PEM_LABEL).expect("decode"), der);

        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "PEM body line too long: {line}");
        }
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));

        // A different label is not silently accepted.
        assert!(pem_decode(&pem, "EC PRIVATE KEY").is_err());
        // Neither is a truncated block or plain garbage.
        assert!(pem_decode("-----BEGIN PRIVATE KEY-----\nAAAA\n", PKCS8_PEM_LABEL).is_err());
        assert!(pem_decode("not a pem at all", PKCS8_PEM_LABEL).is_err());
        assert!(
            pem_decode(
                "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
                PKCS8_PEM_LABEL
            )
            .is_err(),
            "a non-base64 body must be rejected"
        );
    }

    /// An empty PEM body decodes to empty rather than erroring; the key parser
    /// downstream is what rejects it. Pinned so the behaviour is deliberate.
    #[test]
    fn pem_decode_accepts_an_empty_body() {
        let pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            pem_decode(pem, PKCS8_PEM_LABEL).expect("decode"),
            Vec::<u8>::new()
        );
        assert!(DpopKey::from_pkcs8_pem(pem, DpopAlgorithm::Es256).is_err());
    }

    /// A deliberately weak 1024-bit RSA private key, and a P-384 EC key. Both are
    /// throwaway test material generated for this test and used nowhere else; they
    /// exist to prove the loader rejects them.
    const RSA_1024_PEM: &str = include_str!("testdata/rsa-1024-too-small.pem");
    const EC_P384_PEM: &str = include_str!("testdata/ec-p384-wrong-curve.pem");

    /// DPOP-007: the key-strength rules RFC 9449 §4.1 and RFC 7518 §3.3 impose are
    /// enforced — an RSA modulus below 2048 bits and an EC key on a curve other
    /// than P-256 are both refused, as is either key type labelled with the other's
    /// algorithm.
    ///
    /// The enforcement lives in the crypto backend rather than in a check of our
    /// own (see [`DpopKey::from_pkcs8_der`]), which is why it is pinned here: a
    /// backend release that started accepting one of these would otherwise widen
    /// what this crate accepts with nothing failing.
    #[test]
    fn key_strength_is_enforced_by_the_backend() {
        let too_small = DpopKey::from_pkcs8_pem(RSA_1024_PEM, DpopAlgorithm::Rs256)
            .expect_err("a 1024-bit RSA key is below the RFC 7518 §3.3 minimum");
        assert!(
            matches!(too_small, IdentityError::Validation(_)),
            "got {too_small:?}"
        );

        let wrong_curve = DpopKey::from_pkcs8_pem(EC_P384_PEM, DpopAlgorithm::Es256)
            .expect_err("ES256 requires curve P-256");
        assert!(
            matches!(wrong_curve, IdentityError::Validation(_)),
            "got {wrong_curve:?}"
        );

        // And the cross-labelled combinations, which would produce proofs whose
        // `alg` header does not describe the signature.
        let ec = DpopKey::generate(DpopAlgorithm::Es256).expect("generate ES256");
        let rsa = DpopKey::generate(DpopAlgorithm::Rs256).expect("generate RS256");
        assert!(DpopKey::from_pkcs8_der(ec.to_pkcs8_der(), DpopAlgorithm::Rs256).is_err());
        assert!(DpopKey::from_pkcs8_der(rsa.to_pkcs8_der(), DpopAlgorithm::Es256).is_err());
        // The correct labelling still loads, so the test is not simply rejecting
        // everything.
        assert!(DpopKey::from_pkcs8_der(ec.to_pkcs8_der(), DpopAlgorithm::Es256).is_ok());
        assert!(DpopKey::from_pkcs8_der(rsa.to_pkcs8_der(), DpopAlgorithm::Rs256).is_ok());
    }

    /// Algorithm names round-trip through their JWA string form.
    #[test]
    fn algorithm_round_trips_through_its_jwa_name() {
        for algorithm in [DpopAlgorithm::Es256, DpopAlgorithm::Rs256] {
            assert_eq!(
                algorithm.as_str().parse::<DpopAlgorithm>().expect("parses"),
                algorithm
            );
            assert_eq!(algorithm.to_string(), algorithm.as_str());
        }
        assert_eq!(DpopAlgorithm::Es256.as_str(), "ES256");
        assert_eq!(DpopAlgorithm::Rs256.as_str(), "RS256");
    }

    /// A curve name is returned for every variant, including a future one.
    #[test]
    fn curve_names_follow_rfc_7518() {
        assert_eq!(curve_name(&EllipticCurve::P256), "P-256");
        assert_eq!(curve_name(&EllipticCurve::P384), "P-384");
        assert_eq!(curve_name(&EllipticCurve::P521), "P-521");
    }

    /// A base64url JWK member is decoded, and a missing or malformed one is
    /// reported by name so a caller can fix the right member.
    #[test]
    fn jwk_members_are_decoded_and_named_in_errors() {
        assert_eq!(decode_b64url("AQAB", "e").expect("decode"), vec![1, 0, 1]);

        let missing = decode_b64url("", "d").expect_err("missing member");
        assert!(
            missing.to_string().contains("\"d\""),
            "error must name the member: {missing}"
        );
        let malformed = decode_b64url("not base64url!!", "n").expect_err("malformed");
        assert!(
            malformed.to_string().contains("\"n\""),
            "error must name the member: {malformed}"
        );
        // Standard base64 padding is not base64url and is rejected.
        assert!(decode_b64url("AQAB==", "e").is_err());
    }

    /// The derived public JWK carries the public members and nothing else — no
    /// place for private material to hide.
    #[test]
    fn public_jwk_carries_only_public_members() {
        let ec = DpopKey::generate(DpopAlgorithm::Es256).expect("generate ES256");
        let jwk = ec.public_jwk();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.alg, "ES256");
        assert!(!jwk.x.is_empty() && !jwk.y.is_empty());
        assert!(jwk.n.is_empty() && jwk.e.is_empty());
        assert!(jwk.extra.is_empty(), "no stray members: {:?}", jwk.extra);

        // Serialized, it must contain no private member.
        let json = serde_json::to_string(&jwk).expect("serialize");
        for private in [
            "\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\"", "\"k\"",
        ] {
            assert!(
                !json.contains(private),
                "public JWK leaks {private}: {json}"
            );
        }

        let rsa = DpopKey::generate(DpopAlgorithm::Rs256).expect("generate RS256");
        let jwk = rsa.public_jwk();
        assert_eq!(jwk.kty, "RSA");
        assert!(!jwk.n.is_empty() && !jwk.e.is_empty());
        assert!(jwk.crv.is_empty() && jwk.x.is_empty() && jwk.y.is_empty());
    }

    /// `jwk_thumbprint` ignores the members RFC 7638 §3.2 excludes, so two JWKs
    /// describing one key agree however they are labelled.
    #[test]
    fn jwk_thumbprint_ignores_non_required_members() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let plain = key.public_jwk();
        let expected = key.thumbprint().expect("thumbprint");
        assert_eq!(jwk_thumbprint(&plain).expect("thumbprint"), expected);

        let mut labelled = plain.clone();
        labelled.kid = "rotated-2026".to_string();
        labelled.use_ = String::new();
        labelled.alg = String::new();
        assert_eq!(
            jwk_thumbprint(&labelled).expect("thumbprint"),
            expected,
            "kid/use/alg must not affect the thumbprint"
        );
    }

    /// A JWK whose thumbprint is undefined is an error, not a panic or a bogus
    /// value that would silently fail a `cnf.jkt` comparison.
    #[test]
    fn jwk_thumbprint_rejects_keys_it_cannot_hash() {
        for json in [
            r#"{"kty":"RSA"}"#,
            r#"{"kty":"EC","crv":"P-256"}"#,
            r#"{"kty":"unknown-kty"}"#,
            r#"{}"#,
        ] {
            let key: JsonWebKey = serde_json::from_str(json).expect("parse");
            assert!(
                jwk_thumbprint(&key).is_err(),
                "{json} has no defined thumbprint"
            );
        }
    }

    /// Generation draws fresh entropy per call: repeated ES256 keys differ. A
    /// generator that returned a constant would sender-constrain every client to
    /// the same key.
    #[test]
    fn generated_keys_are_distinct() {
        let a = DpopKey::generate(DpopAlgorithm::Es256).expect("generate");
        let b = DpopKey::generate(DpopAlgorithm::Es256).expect("generate");
        assert_ne!(
            a.thumbprint().expect("thumbprint"),
            b.thumbprint().expect("thumbprint")
        );
        assert_ne!(a.to_pkcs8_der(), b.to_pkcs8_der());
    }

    /// A private JWK with no `alg` member infers the algorithm from `kty`, matching
    /// `go/pkg/dpop`'s `algForJWK`.
    #[test]
    fn private_jwk_infers_the_algorithm_from_kty() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate");
        // Rebuild the fixture-style JWK from the generated key's own scalar. The
        // PKCS#8 holds it; round-trip through p256 to read it back out.
        use p256::pkcs8::DecodePrivateKey;
        let secret =
            p256::SecretKey::from_pkcs8_der(key.to_pkcs8_der()).expect("parse generated PKCS#8");
        let d = URL_SAFE_NO_PAD.encode(secret.to_bytes());
        let public = key.public_jwk();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": public.x, "y": public.y, "d": d,
        });
        let loaded = DpopKey::from_private_jwk(&jwk.to_string()).expect("load without alg");
        assert_eq!(loaded.algorithm(), DpopAlgorithm::Es256);
        assert_eq!(
            loaded.thumbprint().expect("thumbprint"),
            key.thumbprint().expect("thumbprint")
        );
    }
}
