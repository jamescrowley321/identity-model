//! Resource-server side DPoP proof verification (RFC 9449 §4.3).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use subtle::ConstantTimeEq;

use super::key::curve_name;
use super::proof::{DPOP_PROOF_TYP, ath, normalize_htu};
use crate::jwks::JsonWebKey;
use crate::{IdentityError, Result};

/// How far a proof's `iat` may sit from the current time before it is rejected
/// (RFC 9449 §4.3 requires `iat` within an acceptable window). Matches
/// `go/pkg/dpop`'s `defaultMaxIATAge`.
const DEFAULT_MAX_IAT_AGE: Duration = Duration::from_secs(60);

/// The JWS algorithms a DPoP proof may be signed with.
///
/// Only asymmetric algorithms appear: RFC 9449 §4.2 forbids symmetric ones,
/// because a shared secret lets anyone holding it mint proofs and the token stops
/// being sender-constrained at all. `none` cannot appear here either — a proof
/// claiming it fails to parse before this list is consulted.
///
/// Two deliberate omissions, both matching `go/pkg/dpop`'s allowlist or the
/// crate's existing [`crate::DEFAULT_ALLOWED_ALGORITHMS`]:
///
/// - `ES512`, because the underlying `jsonwebtoken` verifier has no P-521
///   support, so allowing it here would only turn a clear rejection into a
///   confusing signature failure.
/// - `EdDSA`, which `go/pkg/dpop` also omits. Widening both languages is
///   tracked by [#579](https://github.com/jamescrowley321/identity-model/issues/579).
const PROOF_ALGORITHMS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// JWK members that carry private key material (RFC 7518 §6.2.2, §6.3.2, §6.4).
/// A proof's embedded `jwk` must be the public key alone (RFC 9449 §4.2), so any
/// of these appearing is a rejection.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k"];

/// A DPoP proof whose signature and claims have been verified (RFC 9449 §4.2).
///
/// Compare [`DpopProof::thumbprint`] against the presented access token's
/// `cnf.jkt` claim to confirm the token is bound to the key that signed this
/// proof (RFC 9449 §6, DPOP-005). That comparison is the actual
/// sender-constraint check and [`verify_proof`] does not perform it: it has no
/// access token to inspect.
#[derive(Clone, Debug)]
pub struct DpopProof {
    /// The `typ` header, always [`DPOP_PROOF_TYP`].
    pub typ: String,
    /// The JWA name of the algorithm the proof was signed with.
    pub algorithm: String,
    /// The public key embedded in the proof header.
    pub public_jwk: JsonWebKey,
    /// The RFC 7638 SHA-256 thumbprint of [`DpopProof::public_jwk`], the value to
    /// compare against a bound token's `cnf.jkt`.
    pub thumbprint: String,
    /// The proof's unique identifier, for replay detection.
    pub jti: String,
    /// The HTTP method the proof was issued for.
    pub htm: String,
    /// The normalized request URI the proof was issued for.
    pub htu: String,
    /// When the proof was created, in seconds since the Unix epoch.
    pub iat: i64,
    /// The access-token hash, on a resource-request proof (RFC 9449 §7).
    pub ath: Option<String>,
    /// The server-supplied nonce, when the proof answers a challenge (§8).
    pub nonce: Option<String>,
}

/// Settings for [`verify_proof`].
///
/// The defaults check everything RFC 9449 §4.3 makes mandatory — signature,
/// algorithm, `typ`, the embedded public `jwk`, `jti` presence, `htm`/`htu`
/// match, and an `iat` within 60 seconds. The `ath` and `nonce` checks are opt-in
/// because only the caller knows which token was presented and which nonce was
/// issued.
#[derive(Clone, Debug)]
pub struct DpopVerifyOptions {
    max_iat_age: Duration,
    expected_ath: Option<String>,
    expected_nonce: Option<String>,
    /// Overrides the verification clock. Internal test seam.
    pub(crate) now: Option<i64>,
}

impl Default for DpopVerifyOptions {
    fn default() -> Self {
        Self {
            max_iat_age: DEFAULT_MAX_IAT_AGE,
            expected_ath: None,
            expected_nonce: None,
            now: None,
        }
    }
}

impl DpopVerifyOptions {
    /// Returns the default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how far the proof's `iat` may sit from now, in either direction. The
    /// default is 60 seconds.
    #[must_use]
    pub const fn max_iat_age(mut self, max_iat_age: Duration) -> Self {
        self.max_iat_age = max_iat_age;
        self
    }

    /// Requires the proof's `ath` to be the hash of `access_token`, binding the
    /// proof to the token presented alongside it (RFC 9449 §7).
    ///
    /// Set this on every protected-resource request. Without it a proof minted
    /// for one token is accepted alongside another.
    #[must_use]
    pub fn access_token(mut self, access_token: &str) -> Self {
        self.expected_ath = Some(ath(access_token));
        self
    }

    /// Requires the proof's `nonce` to equal `nonce` (RFC 9449 §8).
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.expected_nonce = Some(nonce.into());
        self
    }
}

/// The proof payload, with every member optional so a missing one is reported by
/// name rather than as a blanket deserialization failure.
#[derive(Deserialize)]
struct RawProofClaims {
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    htm: Option<String>,
    #[serde(default)]
    htu: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// Verifies a DPoP proof JWT for a request with method `expected_htm` and URI
/// `expected_htu` (RFC 9449 §4.3, DPOP-006).
///
/// Rejects a proof that: is signed with a symmetric algorithm, `none`, or
/// anything outside the asymmetric allowlist; omits the embedded `jwk`, or embeds
/// private key material, or embeds a non-asymmetric key; is not
/// `typ=dpop+jwt`; fails signature verification against its own embedded key;
/// omits a required claim; or whose `htm`, `htu`, `iat`, `ath`, or `nonce` does
/// not match. Every rejection is an [`IdentityError::DpopVerification`] naming
/// the offending member.
///
/// # Replay detection is the caller's job
///
/// RFC 9449 §4.3 also expects a server to reject a proof whose `jti` it has
/// already seen inside the `iat` window. That needs state this function does not
/// have: dedupe [`DpopProof::jti`] against a short-lived store — one that only
/// needs to retain entries for [`DpopVerifyOptions::max_iat_age`], since an older
/// proof is rejected on `iat` anyway.
///
/// # Errors
///
/// [`IdentityError::DpopVerification`] for every rejection listed above.
///
/// # Examples
///
/// ```
/// use rs_identity_model::{
///     DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, verify_proof,
/// };
///
/// # fn main() -> rs_identity_model::Result<()> {
/// let key = DpopKey::generate(DpopAlgorithm::Es256)?;
/// let token = "the-access-token";
/// let proof = key.proof(
///     "GET",
///     "https://resource.example.com/userinfo",
///     &DpopProofOptions::new().access_token(token),
/// )?;
///
/// let verified = verify_proof(
///     &proof,
///     "GET",
///     "https://resource.example.com/userinfo",
///     &DpopVerifyOptions::new().access_token(token),
/// )?;
/// // The sender-constraint check: does the bound token name this key?
/// assert_eq!(verified.thumbprint, key.thumbprint()?);
/// # Ok(())
/// # }
/// ```
pub fn verify_proof(
    proof: &str,
    expected_htm: &str,
    expected_htu: &str,
    options: &DpopVerifyOptions,
) -> Result<DpopProof> {
    // An `alg` outside jsonwebtoken's vocabulary — `none` above all — dies here,
    // before any key is touched.
    let header = decode_header(proof).map_err(|e| {
        reject(
            "alg",
            format!("not a DPoP proof signed with a supported asymmetric algorithm: {e}"),
        )
    })?;

    // Check the algorithm BEFORE building a key from the embedded jwk. An
    // attacker who picks HS256 and embeds an `oct` key would otherwise get their
    // own HMAC verified as a valid proof.
    if !PROOF_ALGORITHMS.contains(&header.alg) {
        return Err(reject(
            "alg",
            format!(
                "algorithm {:?} is not allowed for DPoP proofs: RFC 9449 §4.2 requires an \
                 asymmetric algorithm",
                format!("{:?}", header.alg)
            ),
        ));
    }

    if header.typ.as_deref() != Some(DPOP_PROOF_TYP) {
        return Err(reject(
            "typ",
            format!("header typ must be {DPOP_PROOF_TYP:?}"),
        ));
    }

    let jwk = header.jwk.as_ref().ok_or_else(|| {
        reject(
            "jwk",
            "proof header is missing the embedded jwk".to_string(),
        )
    })?;

    // jsonwebtoken's Jwk type cannot represent private members, so it drops them
    // silently on parse and there is nothing left here to inspect. Read the raw
    // protected header to catch a proof that tried to hand over its private key.
    reject_private_jwk_members(proof)?;

    // The embedded key must be asymmetric. A symmetric `oct` key would pair with
    // an HS* alg the allowlist above already refuses, but an explicit check keeps
    // the two from drifting apart.
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(_) | AlgorithmParameters::RSA(_) => {}
        _ => {
            return Err(reject(
                "jwk",
                "embedded jwk is not an asymmetric key".to_string(),
            ));
        }
    }

    let key = DecodingKey::from_jwk(jwk).map_err(|e| {
        reject(
            "jwk",
            format!("embedded jwk is not a usable public key: {e}"),
        )
    })?;

    // A proof carries none of the claims jsonwebtoken validates by default: no
    // exp, no aud, no sub. Turn all of that off and pin the algorithm to the one
    // the allowlist just approved, so the signature check is the only thing this
    // call performs.
    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let claims = decode::<RawProofClaims>(proof, &key, &validation)
        .map_err(|e| reject("signature", e.to_string()))?
        .claims;

    let jti = claims
        .jti
        .filter(|j| !j.is_empty())
        .ok_or_else(|| reject("jti", "missing required jti claim".to_string()))?;

    let htm = claims
        .htm
        .ok_or_else(|| reject("htm", "missing required htm claim".to_string()))?;
    if htm != expected_htm {
        return Err(reject(
            "htm",
            "proof htm does not match the request method".to_string(),
        ));
    }

    let htu = claims
        .htu
        .ok_or_else(|| reject("htu", "missing required htu claim".to_string()))?;
    let want_htu = normalize_htu(expected_htu)
        .map_err(|e| reject("htu", format!("invalid expected request URI: {e}")))?;
    if htu != want_htu {
        return Err(reject(
            "htu",
            "proof htu does not match the request URI".to_string(),
        ));
    }

    let iat = claims
        .iat
        .ok_or_else(|| reject("iat", "missing required iat claim".to_string()))?;
    let now = match options.now {
        Some(now) => now,
        None => now_unix()?,
    };
    // `iat` is attacker-controlled and unauthenticated at this point, so the
    // distance must be computed with arithmetic that is total over i64:
    // `now - iat` overflows for an `iat` near i64::MIN and panics under
    // overflow checks. `abs_diff` returns the distance as a u64 and cannot
    // trap, which also removes the `as i64` cast on the window.
    let max_age = options.max_iat_age.as_secs();
    if now.abs_diff(iat) > max_age {
        return Err(reject(
            "iat",
            format!("proof iat is outside the acceptable {max_age}s window"),
        ));
    }

    if let Some(expected) = &options.expected_ath {
        match &claims.ath {
            Some(actual) if ct_eq(actual, expected) => {}
            _ => {
                return Err(reject(
                    "ath",
                    "proof ath does not match the access token hash".to_string(),
                ));
            }
        }
    }

    if let Some(expected) = &options.expected_nonce {
        match &claims.nonce {
            Some(actual) if ct_eq(actual, expected) => {}
            _ => {
                return Err(reject(
                    "nonce",
                    "proof nonce does not match the expected nonce".to_string(),
                ));
            }
        }
    }

    let thumbprint = jwk
        .thumbprint(ThumbprintHash::SHA256)
        .map_err(|e| reject("jwk", format!("cannot compute thumbprint: {e}")))?;

    Ok(DpopProof {
        typ: DPOP_PROOF_TYP.to_string(),
        algorithm: format!("{:?}", header.alg),
        public_jwk: public_jwk_of(jwk),
        thumbprint,
        jti,
        htm,
        htu,
        iat,
        ath: claims.ath,
        nonce: claims.nonce,
    })
}

/// Builds the [`IdentityError::DpopVerification`] for a rejected member.
fn reject(field: &str, reason: String) -> IdentityError {
    IdentityError::DpopVerification {
        field: Some(field.to_string()),
        reason,
    }
}

/// Rejects a proof whose embedded `jwk` carries private key material
/// (RFC 9449 §4.2, DPOP-001).
///
/// Reads the raw protected header rather than the parsed [`Jwk`], which drops
/// unknown members. Cryptographically the private half is ignored either way —
/// verification uses `n`/`e` or `x`/`y` — but a client that leaks its private key
/// into a proof has a serious bug, and accepting the proof would hide it.
fn reject_private_jwk_members(proof: &str) -> Result<()> {
    let encoded = proof.split('.').next().unwrap_or_default();
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| reject("jwk", format!("proof header is not valid base64url: {e}")))?;
    let header: Value = serde_json::from_slice(&decoded)
        .map_err(|e| reject("jwk", format!("proof header is not valid JSON: {e}")))?;
    let Some(members) = header.get("jwk").and_then(Value::as_object) else {
        // A missing or non-object jwk is reported by the caller's own check.
        return Ok(());
    };
    for private in PRIVATE_JWK_MEMBERS {
        if members.contains_key(*private) {
            return Err(reject(
                "jwk",
                format!(
                    "embedded jwk must contain only the public key, but carries the private \
                     member {private:?}"
                ),
            ));
        }
    }
    Ok(())
}

/// Converts a verified proof's embedded key to the crate's public JWK type, so
/// `jsonwebtoken` types stay out of the public surface.
fn public_jwk_of(jwk: &Jwk) -> JsonWebKey {
    let mut key = JsonWebKey {
        kty: String::new(),
        kid: jwk.common.key_id.clone().unwrap_or_default(),
        use_: String::new(),
        alg: String::new(),
        n: String::new(),
        e: String::new(),
        crv: String::new(),
        x: String::new(),
        y: String::new(),
        extra: std::collections::HashMap::new(),
    };
    match &jwk.algorithm {
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
        // Unreachable: verify_proof rejects a non-asymmetric key before here.
        _ => {}
    }
    key
}

/// Constant-time equality of two ASCII claim strings, matching how the ID-Token
/// profile compares `nonce`/`at_hash`/`c_hash`.
fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Seconds since the Unix epoch, for the `iat` window check.
fn now_unix() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| IdentityError::DpopVerification {
            field: None,
            reason: format!("cannot read the system clock to check the proof iat: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::key::{DpopAlgorithm, DpopKey};
    use crate::dpop::proof::DpopProofOptions;

    /// A proof minted at `iat`, using the crate-internal clock seam.
    fn proof_at(key: &DpopKey, iat: i64) -> String {
        let mut options = DpopProofOptions::new();
        options.issued_at = Some(iat);
        key.proof("POST", "https://server.example.com/token", &options)
            .expect("build proof")
    }

    fn verify_at(proof: &str, now: i64, max_age: Duration) -> Result<DpopProof> {
        let mut options = DpopVerifyOptions::new().max_iat_age(max_age);
        options.now = Some(now);
        verify_proof(proof, "POST", "https://server.example.com/token", &options)
    }

    fn field_of(err: &IdentityError) -> Option<&str> {
        match err {
            IdentityError::DpopVerification { field, .. } => field.as_deref(),
            _ => None,
        }
    }

    /// DPOP-006: `iat` is rejected outside the window in **both** directions. A
    /// one-sided check would accept a proof minted far in the future, which lets a
    /// client pre-mint proofs and defeats the freshness requirement.
    #[test]
    fn iat_window_is_enforced_in_both_directions() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;
        let window = Duration::from_secs(60);
        let proof = proof_at(&key, now);

        // Inside the window: the boundary itself is accepted, matching go/pkg/dpop.
        for offset in [0, 59, 60, -59, -60] {
            verify_at(&proof, now + offset, window)
                .unwrap_or_else(|e| panic!("offset {offset}s should verify: {e}"));
        }

        // Outside it, on both sides.
        for offset in [61, 3600, -61, -3600] {
            let err = verify_at(&proof, now + offset, window)
                .expect_err(&format!("offset {offset}s must be rejected"));
            assert_eq!(field_of(&err), Some("iat"), "offset {offset}s");
        }
    }

    /// An `iat` at the extremes of `i64` is rejected, not trapped on.
    ///
    /// `iat` is attacker-controlled — it arrives in an unauthenticated proof —
    /// and the window check subtracts it from the current time. A plain
    /// `now - iat` overflows for `i64::MIN`, which panics in any
    /// overflow-checked build (the default `dev` profile, and any release
    /// profile setting `overflow-checks`). That is a pre-authentication denial
    /// of service reachable by anyone who can reach the resource server, so the
    /// arithmetic has to be total over the whole domain.
    #[test]
    fn an_extreme_iat_is_rejected_rather_than_overflowing() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;

        for iat in [i64::MIN, i64::MIN + 1, i64::MAX, i64::MAX - 1] {
            let proof = proof_at(&key, iat);
            let err = verify_at(&proof, now, DEFAULT_MAX_IAT_AGE)
                .expect_err("an iat at the i64 boundary is far outside any window");
            assert_eq!(field_of(&err), Some("iat"), "iat {iat}");
        }
    }

    /// A stale proof is rejected even when everything else about it is perfect —
    /// this is the replay window, so it must not depend on any other check.
    #[test]
    fn a_stale_proof_is_rejected_on_iat_alone() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;
        let proof = proof_at(&key, now - 86_400);
        let err = verify_at(&proof, now, DEFAULT_MAX_IAT_AGE).expect_err("a day-old proof");
        assert_eq!(field_of(&err), Some("iat"));
    }

    /// A proof missing a required claim is rejected by name, not as a blanket
    /// parse failure — a caller distinguishing `htu` from `jti` needs the name.
    #[test]
    fn missing_required_claims_are_reported_by_name() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;
        let proof = proof_at(&key, now);
        let parts: Vec<&str> = proof.split('.').collect();
        let header = parts[0];

        // Re-sign a payload with one claim dropped each time, so the signature
        // stays valid and the missing claim is the only fault.
        for (claim, field) in [
            ("jti", "jti"),
            ("htm", "htm"),
            ("htu", "htu"),
            ("iat", "iat"),
        ] {
            let mut payload: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url"),
            )
            .expect("payload JSON");
            payload.as_object_mut().expect("object").remove(claim);
            let resigned = jsonwebtoken::encode(
                &{
                    let mut h = jsonwebtoken::Header::new(Algorithm::ES256);
                    h.typ = Some(DPOP_PROOF_TYP.to_string());
                    h.jwk = Some(key.embedded_jwk().clone());
                    h
                },
                &payload,
                key.encoding_key(),
            )
            .expect("re-sign");
            let _ = header;

            let err = verify_at(&resigned, now, DEFAULT_MAX_IAT_AGE)
                .expect_err(&format!("a proof without {claim:?} must be rejected"));
            assert_eq!(field_of(&err), Some(field), "missing {claim:?}");
        }
    }

    /// An empty `jti` is as useless for replay detection as a missing one, so it is
    /// rejected the same way.
    #[test]
    fn an_empty_jti_is_rejected() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some(DPOP_PROOF_TYP.to_string());
        header.jwk = Some(key.embedded_jwk().clone());
        let payload = serde_json::json!({
            "jti": "",
            "htm": "POST",
            "htu": "https://server.example.com/token",
            "iat": now,
        });
        let proof =
            jsonwebtoken::encode(&header, &payload, key.encoding_key()).expect("sign proof");
        let err = verify_at(&proof, now, DEFAULT_MAX_IAT_AGE).expect_err("empty jti");
        assert_eq!(field_of(&err), Some("jti"));
    }

    /// The expected-URI argument is normalized before comparison, so a caller may
    /// pass the raw request URI — query string, fragment, and userinfo included —
    /// and still match a proof built from the same request.
    #[test]
    fn expected_htu_is_normalized_before_comparison() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let now = 1_700_000_000;
        let mut options = DpopProofOptions::new();
        options.issued_at = Some(now);
        let proof = key
            .proof("GET", "https://rs.example.com/resource", &options)
            .expect("build proof");

        for equivalent in [
            "https://rs.example.com/resource",
            "https://rs.example.com/resource?include=all",
            "https://rs.example.com/resource#section",
            "https://user:pass@rs.example.com/resource",
        ] {
            let mut verify = DpopVerifyOptions::new();
            verify.now = Some(now);
            verify_proof(&proof, "GET", equivalent, &verify)
                .unwrap_or_else(|e| panic!("{equivalent} should normalize to a match: {e}"));
        }

        // A non-absolute expected URI is a caller error reported against htu.
        let mut verify = DpopVerifyOptions::new();
        verify.now = Some(now);
        let err = verify_proof(&proof, "GET", "/resource", &verify).expect_err("relative URI");
        assert_eq!(field_of(&err), Some("htu"));
    }

    /// The allowlist must not contain a symmetric algorithm or `none`. A
    /// regression here silently un-sender-constrains every token in the system,
    /// so it is asserted directly rather than only through a forged proof.
    #[test]
    fn the_algorithm_allowlist_is_asymmetric_only() {
        for symmetric in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert!(
                !PROOF_ALGORITHMS.contains(&symmetric),
                "{symmetric:?} must never be allowed for a DPoP proof"
            );
        }
        assert!(!PROOF_ALGORITHMS.is_empty());
    }

    /// A header that is not valid base64url or not JSON is rejected rather than
    /// panicking — the private-member scan reads the raw header, so it is the one
    /// place that touches unparsed attacker input.
    #[test]
    fn a_malformed_header_is_rejected_not_panicked_on() {
        for malformed in ["", "!!!.x.y", "e30.x.y"] {
            let err = verify_proof(
                malformed,
                "POST",
                "https://server.example.com/token",
                &DpopVerifyOptions::new(),
            )
            .expect_err("malformed proof");
            assert!(
                matches!(err, IdentityError::DpopVerification { .. }),
                "{malformed:?} produced {err:?}"
            );
        }
    }
}
