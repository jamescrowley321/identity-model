//! PKCE code verifier / challenge (RFC 7636) and the authorization URL builder.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::discovery::ProviderMetadata;
use crate::{IdentityError, Result};

/// The SHA-256 PKCE transform, which all capable clients MUST use
/// (RFC 7636 §4.2).
pub const CHALLENGE_METHOD_S256: &str = "S256";

/// Entropy of a generated verifier. 32 bytes encode to 43 base64url characters
/// with no padding — the RFC 7636 §4.1 minimum.
const CODE_VERIFIER_BYTES: usize = 32;
/// Minimum length of a valid code verifier (RFC 7636 §4.1).
const MIN_CODE_VERIFIER_LEN: usize = 43;
/// Maximum length of a valid code verifier (RFC 7636 §4.1).
const MAX_CODE_VERIFIER_LEN: usize = 128;

/// A PKCE code verifier and its derived S256 challenge (RFC 7636 §4.1–§4.3).
///
/// Construct one with [`PkceChallenge::generate`]. Send the [`code_challenge`]
/// and [`code_challenge_method`] on the authorization request (see
/// [`authorization_url`]), retain the [`code_verifier`], and present it on the
/// token exchange via [`crate::TokenClient::exchange_code`].
///
/// [`code_challenge`]: PkceChallenge::code_challenge
/// [`code_challenge_method`]: PkceChallenge::code_challenge_method
/// [`code_verifier`]: PkceChallenge::code_verifier
#[derive(Clone, Debug)]
pub struct PkceChallenge {
    /// The cryptographically random code verifier (RFC 7636 §4.1).
    pub code_verifier: String,
    /// The S256 code challenge, `BASE64URL(SHA256(code_verifier))`
    /// (RFC 7636 §4.2).
    pub code_challenge: String,
    /// The challenge method, always `S256`.
    pub code_challenge_method: String,
}

impl PkceChallenge {
    /// Generates a fresh PKCE verifier and its S256 challenge (ACG-002/ACG-003).
    ///
    /// The verifier is 43 characters drawn from the base64url alphabet
    /// (`[A-Za-z0-9-_]`), a subset of the RFC 7636 §4.1 unreserved set, so it is
    /// always valid. Entropy comes from the operating system CSPRNG via
    /// `getrandom`.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Configuration`] if the system random source is
    /// unavailable.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; CODE_VERIFIER_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|e| IdentityError::Configuration(format!("generate code verifier: {e}")))?;
        let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
        let code_challenge = s256_challenge(&code_verifier);
        Ok(Self {
            code_verifier,
            code_challenge,
            code_challenge_method: CHALLENGE_METHOD_S256.to_string(),
        })
    }
}

/// Computes the PKCE S256 code challenge for `verifier` as
/// `BASE64URL(SHA256(ASCII(verifier)))` (RFC 7636 §4.2, ACG-003).
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Reports whether `verifier` satisfies the RFC 7636 §4.1 length and charset
/// rules: 43–128 characters, each from the unreserved set `[A-Za-z0-9-._~]`.
pub fn valid_code_verifier(verifier: &str) -> bool {
    if verifier.len() < MIN_CODE_VERIFIER_LEN || verifier.len() > MAX_CODE_VERIFIER_LEN {
        return false;
    }
    verifier
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

/// Builds an OAuth 2.0 authorization request URL for the authorization code
/// grant with PKCE (RFC 6749 §4.1.1, RFC 7636 §4.3, AC-4).
///
/// The URL targets `metadata.authorization_endpoint` and carries
/// `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, and the
/// PKCE `code_challenge` / `code_challenge_method`. All values are
/// percent-encoded by [`reqwest::Url`].
///
/// # Errors
///
/// [`IdentityError::Configuration`] if `metadata.authorization_endpoint` is
/// empty or not a valid URL.
pub fn authorization_url(
    metadata: &ProviderMetadata,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    pkce: &PkceChallenge,
) -> Result<String> {
    if metadata.authorization_endpoint.is_empty() {
        return Err(IdentityError::Configuration(
            "authorization_endpoint is empty".to_string(),
        ));
    }
    let mut url = Url::parse(&metadata.authorization_endpoint).map_err(|e| {
        IdentityError::Configuration(format!(
            "invalid authorization_endpoint {:?}: {e}",
            metadata.authorization_endpoint
        ))
    })?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", &pkce.code_challenge_method);
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ACG-003: S256Challenge must match the RFC 7636 Appendix B worked example
    // exactly. See spec/test-fixtures/token/pkce-appendix-b.json.
    #[test]
    fn s256_challenge_matches_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), challenge);
    }

    // ACG-002: a generated verifier is 43-128 chars of unreserved characters
    // and its challenge is the S256 transform.
    #[test]
    fn generate_produces_valid_verifier_and_challenge() {
        for _ in 0..100 {
            let pkce = PkceChallenge::generate().expect("generate");
            assert!(
                (MIN_CODE_VERIFIER_LEN..=MAX_CODE_VERIFIER_LEN).contains(&pkce.code_verifier.len()),
                "length {} out of range",
                pkce.code_verifier.len()
            );
            assert!(
                valid_code_verifier(&pkce.code_verifier),
                "verifier {:?} not valid",
                pkce.code_verifier
            );
            assert_eq!(pkce.code_challenge_method, "S256");
            assert_eq!(pkce.code_challenge, s256_challenge(&pkce.code_verifier));
        }
    }

    // ACG-002: successive verifiers must differ (cryptographic randomness).
    #[test]
    fn generate_produces_unique_verifiers() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let pkce = PkceChallenge::generate().expect("generate");
            assert!(
                seen.insert(pkce.code_verifier),
                "duplicate verifier generated"
            );
        }
    }

    // ACG-002: length and charset boundary conditions.
    #[test]
    fn valid_code_verifier_bounds() {
        assert!(valid_code_verifier(&"a".repeat(43)), "min-43");
        assert!(valid_code_verifier(&"a".repeat(128)), "max-128");
        assert!(!valid_code_verifier(&"a".repeat(42)), "too-short-42");
        assert!(!valid_code_verifier(&"a".repeat(129)), "too-long-129");
        assert!(
            !valid_code_verifier(&(format!("{}/", "a".repeat(42)))),
            "illegal-char"
        );
        assert!(
            valid_code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "appendix-b"
        );
        assert!(
            valid_code_verifier(&format!("ABCabc012{}", "-._~".repeat(9))),
            "all-unreserved"
        );
    }

    // AC-4: authorization_url carries all required query parameters.
    #[test]
    fn authorization_url_has_required_params() {
        let metadata: ProviderMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/authorize",
        }))
        .expect("metadata");
        let pkce = PkceChallenge::generate().expect("generate");
        let url = authorization_url(
            &metadata,
            "client-1",
            "https://app.example.com/cb",
            "openid profile",
            "xyz-state",
            &pkce,
        )
        .expect("build url");

        let parsed = Url::parse(&url).expect("parse url");
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.path(), "/authorize");
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("client-1")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://app.example.com/cb")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(params.get("state").map(String::as_str), Some("xyz-state"));
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some(pkce.code_challenge.as_str())
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
    }

    // AC-4: an empty authorization_endpoint is a configuration error.
    #[test]
    fn authorization_url_rejects_empty_endpoint() {
        let metadata: ProviderMetadata =
            serde_json::from_value(serde_json::json!({})).expect("metadata");
        let pkce = PkceChallenge::generate().expect("generate");
        let err = authorization_url(&metadata, "c", "r", "s", "st", &pkce)
            .expect_err("empty endpoint must error");
        assert!(matches!(err, IdentityError::Configuration(_)), "{err:?}");
    }
}
