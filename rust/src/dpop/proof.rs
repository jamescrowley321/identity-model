//! DPoP proof JWT construction (RFC 9449 §4.2) and the `ath` / `htu` helpers.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Header;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::key::DpopKey;
use crate::{IdentityError, Result};

/// The `typ` header every DPoP proof carries (RFC 9449 §4.2). A verifier that
/// checks it cannot be fooled into accepting a plain JWT — an access token, say —
/// replayed as a proof.
pub const DPOP_PROOF_TYP: &str = "dpop+jwt";

/// Entropy of a generated `jti`. 16 bytes is the 128 bits RFC 9449 §4.2 calls for.
const JTI_BYTES: usize = 16;

/// The payload of a DPoP proof JWT (RFC 9449 §4.2).
///
/// `ath` and `nonce` are omitted when absent: `ath` appears only on
/// resource-request proofs (§7) and `nonce` only after a server challenge (§8).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProofClaims {
    pub(crate) jti: String,
    pub(crate) htm: String,
    pub(crate) htu: String,
    pub(crate) iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ath: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
}

/// The optional claims of a generated DPoP proof.
///
/// Defaults to neither `ath` nor `nonce`, which is what a token-endpoint request
/// wants (RFC 9449 §5). Add [`access_token`] for a protected-resource request
/// (§7) and [`nonce`] when retrying after a `use_dpop_nonce` challenge (§8).
///
/// [`access_token`]: DpopProofOptions::access_token
/// [`nonce`]: DpopProofOptions::nonce
#[derive(Clone, Debug, Default)]
pub struct DpopProofOptions {
    ath: Option<String>,
    nonce: Option<String>,
    /// Overrides the `iat` clock. Internal: exists so the crate's own tests can
    /// mint a proof with a known or deliberately stale timestamp.
    pub(crate) issued_at: Option<i64>,
}

impl DpopProofOptions {
    /// Returns options with no optional claims — the token-request form
    /// (RFC 9449 §5, DPOP-002).
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds the proof to `access_token` by adding the `ath` claim,
    /// `BASE64URL(SHA-256(access_token))` (RFC 9449 §4.2, DPOP-003).
    ///
    /// Use this for protected-resource requests. Token-endpoint requests omit
    /// `ath`, since there is no access token to bind to yet (RFC 9449 §5).
    #[must_use]
    pub fn access_token(mut self, access_token: &str) -> Self {
        self.ath = Some(ath(access_token));
        self
    }

    /// Adds the server-supplied `nonce` claim, sent when retrying after a
    /// `use_dpop_nonce` challenge (RFC 9449 §8, DPOP-004).
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

impl DpopKey {
    /// Builds and signs a DPoP proof JWT for an HTTP request (RFC 9449 §4.2,
    /// DPOP-001).
    ///
    /// The protected header carries `typ=dpop+jwt`, the key's asymmetric `alg`,
    /// and the **public** `jwk`. The payload carries a fresh random `jti`,
    /// `htm=method`, `htu` — `uri` reduced to scheme, authority, and path — and
    /// `iat=now`, plus whatever `options` adds. The return value is the compact
    /// serialization to place in the `DPoP` request header.
    ///
    /// Each call mints a new `jti` and a new `iat`, so a proof is single-use:
    /// generate one per request rather than caching one.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::Validation`] — `uri` is not an absolute URI with a
    ///   scheme and host.
    /// - [`IdentityError::Configuration`] — the system random source is
    ///   unavailable, or the key cannot sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use rs_identity_model::{DpopAlgorithm, DpopKey, DpopProofOptions};
    ///
    /// # fn main() -> rs_identity_model::Result<()> {
    /// let key = DpopKey::generate(DpopAlgorithm::Es256)?;
    ///
    /// // Token request: no `ath` (RFC 9449 §5).
    /// let proof = key.proof("POST", "https://server.example.com/token", &DpopProofOptions::new())?;
    ///
    /// // Resource request: bound to the access token (RFC 9449 §7).
    /// let bound = key.proof(
    ///     "GET",
    ///     "https://resource.example.com/userinfo",
    ///     &DpopProofOptions::new().access_token("the-access-token"),
    /// )?;
    /// # let _ = (proof, bound);
    /// # Ok(())
    /// # }
    /// ```
    pub fn proof(&self, method: &str, uri: &str, options: &DpopProofOptions) -> Result<String> {
        let claims = ProofClaims {
            jti: new_jti()?,
            htm: method.to_string(),
            htu: normalize_htu(uri)?,
            iat: match options.issued_at {
                Some(iat) => iat,
                None => unix_now()?,
            },
            ath: options.ath.clone(),
            nonce: options.nonce.clone(),
        };

        let mut header = Header::new(self.algorithm().jwt());
        header.typ = Some(DPOP_PROOF_TYP.to_string());
        // The embedded JWK is the public half only — RFC 9449 §4.2 requires the
        // public key and private material would hand the key away.
        header.jwk = Some(self.embedded_jwk().clone());

        jsonwebtoken::encode(&header, &claims, self.encoding_key())
            .map_err(|e| IdentityError::Configuration(format!("sign DPoP proof: {e}")))
    }
}

/// Computes the DPoP access-token hash claim for `access_token`:
/// `BASE64URL(SHA-256(access_token))` without padding (RFC 9449 §4.2, DPOP-003).
///
/// This is the value carried in a resource-request proof's `ath` claim, binding
/// the proof to the token it accompanies.
///
/// # Examples
///
/// ```
/// // The RFC 9449 §4.2 example access token and its ath.
/// assert_eq!(
///     rs_identity_model::dpop_ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
///     "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
/// );
/// ```
pub fn ath(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// Reduces a request URI to the `htu` form RFC 9449 §4.2 requires: scheme,
/// authority, and path, with the query, fragment, and any userinfo removed.
///
/// # Divergence from the Go implementation
///
/// `Url` normalizes an empty path to `/` (the RFC 3986 §6.2.3 equivalent form),
/// so `https://example.com` yields `https://example.com/` where
/// `go/pkg/dpop` leaves it bare. Verification is unaffected — [`verify_proof`]
/// runs both the proof's `htu` and the expected URI through this same function —
/// but a Go client's proof for a bare-authority URI will not match a Rust
/// resource server's expectation, and vice versa. Every URI with a non-empty
/// path, which is every real token or resource endpoint, is identical in both.
///
/// [`verify_proof`]: super::verify_proof
///
/// # Errors
///
/// [`IdentityError::Validation`] if `uri` is not parsable, or is missing a scheme
/// or host.
pub fn normalize_htu(uri: &str) -> Result<String> {
    let mut url = Url::parse(uri).map_err(|e| {
        IdentityError::Validation(format!(
            "DPoP htu requires a valid absolute URI: {uri:?}: {e}"
        ))
    })?;
    if !url.has_host() {
        return Err(IdentityError::Validation(format!(
            "DPoP htu requires an absolute URI with a scheme and host, got {uri:?}"
        )));
    }
    url.set_query(None);
    url.set_fragment(None);
    // Userinfo is not part of htu and would leak a credential into the proof.
    // `set_username`/`set_password` only fail on a cannot-be-a-base URL, which
    // the has_host check above has already excluded.
    let _ = url.set_username("");
    let _ = url.set_password(None);
    Ok(url.into())
}

/// Returns a fresh 128-bit random `jti` for the proof's replay-prevention claim
/// (RFC 9449 §4.2), base64url-encoded without padding.
fn new_jti() -> Result<String> {
    let mut bytes = [0u8; JTI_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| IdentityError::Configuration(format!("generate DPoP proof jti: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Seconds since the Unix epoch, for the proof's `iat`.
fn unix_now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| {
            IdentityError::Configuration(format!(
                "read the system clock for the DPoP proof iat: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpop::key::{DpopAlgorithm, DpopKey};

    /// `htu` is scheme + authority + path: the query, fragment, and userinfo are
    /// stripped (RFC 9449 §4.2). Userinfo matters most — leaving it in would copy a
    /// credential into a signed, forwarded token.
    #[test]
    fn normalize_htu_strips_query_fragment_and_userinfo() {
        for (input, want) in [
            (
                "https://server.example.com/token",
                "https://server.example.com/token",
            ),
            (
                "https://server.example.com/token?x=1",
                "https://server.example.com/token",
            ),
            (
                "https://server.example.com/token#frag",
                "https://server.example.com/token",
            ),
            (
                "https://server.example.com/token?x=1#frag",
                "https://server.example.com/token",
            ),
            (
                "https://user:pw@server.example.com/token",
                "https://server.example.com/token",
            ),
            (
                "https://server.example.com:8443/token",
                "https://server.example.com:8443/token",
            ),
            // A default port is elided by URL normalization; both forms are the
            // same origin, and both sides of a comparison run through here.
            (
                "https://server.example.com:443/token",
                "https://server.example.com/token",
            ),
            (
                "http://localhost:8080/oauth/token",
                "http://localhost:8080/oauth/token",
            ),
            // Path case and percent-encoding are preserved: htu is compared exactly.
            (
                "https://server.example.com/Token",
                "https://server.example.com/Token",
            ),
            (
                "https://server.example.com/a%20b",
                "https://server.example.com/a%20b",
            ),
        ] {
            assert_eq!(normalize_htu(input).expect(input), want, "input {input}");
        }
    }

    /// An empty path normalizes to `/`. Documented as the one divergence from
    /// `go/pkg/dpop`, which leaves it bare — asserted so the divergence is a
    /// deliberate, visible fact rather than a surprise.
    #[test]
    fn normalize_htu_gives_an_empty_path_a_root_slash() {
        assert_eq!(
            normalize_htu("https://server.example.com").expect("bare authority"),
            "https://server.example.com/"
        );
        assert_eq!(
            normalize_htu("https://server.example.com/").expect("root path"),
            "https://server.example.com/"
        );
    }

    /// A URI without a scheme or host cannot be an `htu`.
    #[test]
    fn normalize_htu_rejects_non_absolute_uris() {
        for input in ["/token", "token", "", "example.com/token", "https://"] {
            assert!(
                normalize_htu(input).is_err(),
                "{input:?} is not an absolute http(s) URI and must be rejected"
            );
        }
    }

    /// `ath` is unpadded base64url of the SHA-256 of the token (RFC 9449 §4.2),
    /// including for the RFC's own example value.
    #[test]
    fn ath_is_unpadded_base64url_sha256() {
        assert_eq!(
            ath("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
        let hash = ath("");
        assert!(!hash.contains('='), "no base64 padding");
        // SHA-256 is 32 bytes, which is 43 unpadded base64url characters.
        assert_eq!(hash.len(), 43);
        assert_ne!(ath("a"), ath("b"));
    }

    /// The `jti` is fresh per call and 128 bits wide (RFC 9449 §4.2).
    #[test]
    fn jti_is_fresh_and_128_bits() {
        let a = new_jti().expect("jti");
        let b = new_jti().expect("jti");
        assert_ne!(a, b);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&a).expect("base64url jti").len(),
            JTI_BYTES
        );
    }

    /// The optional claims are absent by default and present only when asked for,
    /// so a token-request proof cannot accidentally carry `ath` (RFC 9449 §5).
    #[test]
    fn proof_options_default_to_no_optional_claims() {
        let bare = DpopProofOptions::new();
        assert!(bare.ath.is_none());
        assert!(bare.nonce.is_none());

        let bound = DpopProofOptions::new().access_token("tok").nonce("n-1");
        assert_eq!(bound.ath.as_deref(), Some(ath("tok").as_str()));
        assert_eq!(bound.nonce.as_deref(), Some("n-1"));
    }

    /// The `htu` in a built proof is the normalized form, not the raw URI handed
    /// in — otherwise a request with a query string would produce a proof no
    /// verifier accepts.
    #[test]
    fn proof_normalizes_the_htu_it_signs() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        let proof = key
            .proof(
                "POST",
                "https://server.example.com/token?scope=openid",
                &DpopProofOptions::new(),
            )
            .expect("build proof");
        let payload = proof.split('.').nth(1).expect("payload");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
        let claims: ProofClaims = serde_json::from_slice(&decoded).expect("claims");
        assert_eq!(claims.htu, "https://server.example.com/token");
    }

    /// A proof for a URI that cannot be an `htu` fails rather than signing a
    /// malformed claim.
    #[test]
    fn proof_rejects_a_non_absolute_uri() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        assert!(
            key.proof("POST", "/token", &DpopProofOptions::new())
                .is_err(),
            "a relative URI has no htu"
        );
    }

    /// The method is signed verbatim, uppercase or not: RFC 9449 §4.3 compares
    /// `htm` to the request method, and HTTP methods are case-sensitive.
    #[test]
    fn proof_signs_the_method_verbatim() {
        let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
        for method in ["GET", "POST", "PATCH", "DELETE"] {
            let proof = key
                .proof(method, "https://rs.example.com/r", &DpopProofOptions::new())
                .expect("build proof");
            let decoded = URL_SAFE_NO_PAD
                .decode(proof.split('.').nth(1).expect("payload"))
                .expect("base64url");
            let claims: ProofClaims = serde_json::from_slice(&decoded).expect("claims");
            assert_eq!(claims.htm, method);
        }
    }
}
