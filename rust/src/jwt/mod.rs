//! JWT validation: verify JWS signatures and registered claims.
//!
//! [`validate_token`] verifies a compact-serialized JWT against an
//! already-resolved [`JsonWebKey`]; [`validate_token_with_jwks`] resolves the
//! signing key from a [`JwksClient`] by the token's `kid` — forcing one JWKS
//! refresh on a miss (JWT-010) — before delegating to it. Both reject the
//! unsecured `none` algorithm before any cryptographic work (JWT-003) and
//! restrict acceptance to an asymmetric algorithm allowlist to defeat
//! algorithm-confusion attacks. Behaviour is proven against the cross-language
//! conformance IDs `JWT-001`..`JWT-013` in `spec/conformance/validation.json`.
//!
//! RFC / spec references: RFC 7519 (JWT), RFC 7515 (JWS), OIDC Core 1.0
//! §3.1.3.7.
//!
//! ```no_run
//! # async fn run() -> identity_model::Result<()> {
//! use identity_model::{JwksClient, ValidationOptions, validate_token_with_jwks};
//!
//! let jwks = JwksClient::new();
//! let opts = ValidationOptions::builder()
//!     .issuer("https://accounts.example.com")
//!     .audience("my-client-id")
//!     .build();
//! let claims = validate_token_with_jwks(
//!     "eyJ...",
//!     &jwks,
//!     "https://accounts.example.com/jwks",
//!     &opts,
//! )
//! .await?;
//! println!("subject = {:?}", claims.subject);
//! # Ok(())
//! # }
//! ```

mod claims;
mod options;

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::Value;

use crate::jwks::{JsonWebKey, JwksClient};
use crate::{IdentityError, Result};

pub use claims::{Audience, Claims};
pub use options::{DEFAULT_ALLOWED_ALGORITHMS, ValidationOptions, ValidationOptionsBuilder};

/// The subset of the JWS protected header inspected before any cryptographic
/// work (RFC 7515 §4.1).
#[derive(Debug, Deserialize)]
struct JoseHeader {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    kid: String,
}

/// Validates a compact-serialized JWT against an already-resolved signing key
/// and returns its typed [`Claims`].
///
/// Use this when the verification key is already in hand (e.g. resolved from a
/// [`crate::JsonWebKeySet`]). To resolve the key from a [`JwksClient`] by the
/// token's `kid` — with a forced JWKS refresh on a miss — use
/// [`validate_token_with_jwks`].
///
/// The flow is: parse the protected header, reject the `none` algorithm before
/// any crypto (JWT-003), confirm the header `alg` is in the allowlist (defeating
/// algorithm confusion), verify the signature against `key` (JWT-001/009), then
/// validate the registered and configured claims
/// (JWT-002/004/005/006/007/008/011/012/013).
///
/// # Errors
///
/// [`IdentityError::Validation`] for a malformed token, a rejected/unsupported
/// algorithm, a signature that does not verify, or a claim that fails its rule;
/// [`IdentityError::Deserialization`] for a payload that is not a JSON object.
pub fn validate_token(
    token: &str,
    key: &JsonWebKey,
    options: &ValidationOptions,
) -> Result<Claims> {
    let token = token.trim();
    let header = parse_header(token)?;
    let alg = check_algorithm(&header, options)?;

    let decoding_key = decoding_key_for(key)?;

    // Disable jsonwebtoken's built-in claim checks: we verify only the signature
    // here and enforce every claim rule ourselves in `Claims::validate`, for
    // full control over required claims, clock skew, nonce, and error messages
    // (message parity with `go/pkg/jwt`).
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.algorithms = vec![alg];

    let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(map_verify_err)?;

    let claims = Claims::from_value(token_data.claims)?;
    claims.validate(options, now_unix())?;
    Ok(claims)
}

/// Validates a compact-serialized JWT, resolving its signing key from `jwks` by
/// the token's `kid`, and returns its typed [`Claims`].
///
/// The `none` algorithm is rejected and the header `alg` is checked against the
/// allowlist before the key is resolved, so a `none`/disallowed token never
/// triggers a JWKS fetch. Key resolution forces one JWKS refresh and retries if
/// the `kid` is not cached (JWT-010), supporting key rotation, before delegating
/// to [`validate_token`].
///
/// # Errors
///
/// [`IdentityError::KeyNotFound`] when no key matches the token's `kid` even
/// after a refresh; otherwise the errors of [`validate_token`] and
/// [`JwksClient::resolve_key`].
pub async fn validate_token_with_jwks(
    token: &str,
    jwks: &JwksClient,
    jwks_uri: &str,
    options: &ValidationOptions,
) -> Result<Claims> {
    let token = token.trim();
    let header = parse_header(token)?;
    // JWT-003 and the allowlist are enforced before any network work so an
    // untrusted `none`/disallowed token cannot drive an outbound JWKS fetch.
    check_algorithm(&header, options)?;

    // JWT-001/010: resolve the verification key by kid, forcing one JWKS refresh
    // and retry if the kid is not cached (RFC 7517 §4.5).
    let key = jwks.resolve_key(jwks_uri, &header.kid).await?;
    validate_token(token, &key, options)
}

/// Decodes the protected header of a compact JWS without verifying it, so the
/// algorithm and `kid` can be inspected first (JWT-003).
///
/// A manual base64url decode is used rather than [`jsonwebtoken::decode_header`]
/// because the latter cannot distinguish the `none` algorithm from any other
/// unsupported one.
fn parse_header(token: &str) -> Result<JoseHeader> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IdentityError::Validation(format!(
            "malformed token: compact JWS must have 3 segments, got {}",
            parts.len()
        )));
    }
    if parts[0].is_empty() {
        return Err(IdentityError::Validation(
            "malformed token: empty header segment".to_string(),
        ));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| IdentityError::Validation(format!("malformed token: decode header: {e}")))?;
    serde_json::from_slice(&raw)
        .map_err(|e| IdentityError::Validation(format!("malformed token: parse header JSON: {e}")))
}

/// Rejects the `none` algorithm and any header `alg` outside the configured
/// allowlist, returning the mapped [`Algorithm`] for signature verification.
fn check_algorithm(header: &JoseHeader, options: &ValidationOptions) -> Result<Algorithm> {
    // JWT-003: reject the unsecured "none" algorithm unconditionally, before any
    // key resolution or signature work (RFC 7519 §7.2).
    if header.alg.eq_ignore_ascii_case("none") {
        return Err(IdentityError::Validation(
            "unsecured token with algorithm \"none\" is rejected".to_string(),
        ));
    }
    if header.alg.is_empty() {
        return Err(IdentityError::Validation(
            "malformed token: header is missing the \"alg\" parameter".to_string(),
        ));
    }
    if !options.allowed_algorithms.iter().any(|a| a == &header.alg) {
        return Err(IdentityError::Validation(format!(
            "unsupported or disallowed algorithm {:?}",
            header.alg
        )));
    }
    algorithm_from_str(&header.alg)
}

/// Maps an asymmetric JWS algorithm name to a [`jsonwebtoken::Algorithm`]. The
/// symmetric `HS*` family and `none` are not mapped (they are excluded by the
/// default allowlist and would be verified against a public key).
fn algorithm_from_str(alg: &str) -> Result<Algorithm> {
    let mapped = match alg {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        _ => {
            return Err(IdentityError::Validation(format!(
                "unsupported or disallowed algorithm {alg:?}"
            )));
        }
    };
    Ok(mapped)
}

/// Builds a [`DecodingKey`] from a resolved [`JsonWebKey`], selecting only the
/// key material that belongs to the declared key type so a malformed entry
/// carrying both RSA and EC parameters cannot present an ambiguous key.
fn decoding_key_for(key: &JsonWebKey) -> Result<DecodingKey> {
    match key.kty.as_str() {
        "RSA" => DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|e| IdentityError::Validation(format!("convert RSA key {:?}: {e}", key.kid))),
        "EC" => DecodingKey::from_ec_components(&key.x, &key.y)
            .map_err(|e| IdentityError::Validation(format!("convert EC key {:?}: {e}", key.kid))),
        other => Err(IdentityError::Validation(format!(
            "unsupported key type {other:?}"
        ))),
    }
}

/// Maps a jsonwebtoken verification error to an [`IdentityError`]. Only the
/// signature is checked here (all claim validation is disabled), so any failure
/// is a signature or structural problem (JWT-009).
fn map_verify_err(err: jsonwebtoken::errors::Error) -> IdentityError {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::InvalidSignature => {
            IdentityError::Validation("signature verification failed".to_string())
        }
        _ => IdentityError::Validation(format!("signature verification failed: {err}")),
    }
}

/// Current wall-clock time in whole seconds since the Unix epoch.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::JsonWebKeySet;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::{BigUint, RsaPrivateKey};
    use serde_json::json;
    use std::time::Duration;

    const FIXTURE_DIR: &str = "../spec/test-fixtures/validation";
    const TEST_KID: &str = "test-key-1";
    const TEST_ISSUER: &str = "https://issuer.example.com";
    const TEST_AUDIENCE: &str = "test-client";

    fn read_fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURE_DIR}/{name}"))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
    }

    fn b64u(s: &str) -> BigUint {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .unwrap_or_else(|e| panic!("decode base64url component: {e}"));
        BigUint::from_bytes_be(&bytes)
    }

    /// Builds an RS256 [`EncodingKey`] from the shared private JWK fixture so
    /// unit tests sign tokens with the same key material as the other languages.
    fn signing_key() -> EncodingKey {
        let jwk: Value =
            serde_json::from_slice(&read_fixture("signing-key.jwk.json")).expect("parse jwk");
        let field = |name: &str| b64u(jwk[name].as_str().unwrap_or_else(|| panic!("jwk.{name}")));
        let private = RsaPrivateKey::from_components(
            field("n"),
            field("e"),
            field("d"),
            vec![field("p"), field("q")],
        )
        .expect("build RSA private key");
        let pem = private
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode PKCS#1 PEM");
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key")
    }

    /// The public verification key resolved from the JWKS fixture (JWT-001).
    fn public_key() -> JsonWebKey {
        let set = JsonWebKeySet::parse(&read_fixture("jwks.json")).expect("parse jwks fixture");
        set.resolve_key(TEST_KID).expect("fixture key").clone()
    }

    /// Mints an RS256 token with `kid=test-key-1` carrying `claims`.
    fn mint(claims: Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
    }

    fn now() -> i64 {
        now_unix()
    }

    // JWT-001 / JWT-002: a valid RS256 token whose kid resolves the fixture key
    // verifies and returns a typed claim set.
    #[test]
    fn accepts_valid_rsa_token() {
        let n = now();
        let token = mint(json!({
            "iss": TEST_ISSUER,
            "sub": "user-1",
            "aud": TEST_AUDIENCE,
            "exp": n + 3600,
            "iat": n - 5,
        }));
        let opts = ValidationOptions::builder()
            .issuer(TEST_ISSUER)
            .audience(TEST_AUDIENCE)
            .build();
        let claims = validate_token(&token, &public_key(), &opts).expect("valid token");
        assert_eq!(claims.subject.as_deref(), Some("user-1"));
        assert_eq!(claims.issuer.as_deref(), Some(TEST_ISSUER));
        assert!(claims.audience.contains(TEST_AUDIENCE));
    }

    // JWT-003: the static alg:none fixture is rejected before any signature work.
    #[test]
    fn rejects_alg_none_fixture() {
        let token = String::from_utf8(read_fixture("alg-none-token.txt")).expect("utf8 token");
        let err = validate_token(token.trim(), &public_key(), &ValidationOptions::new())
            .expect_err("alg none rejected");
        assert!(err.to_string().contains("none"), "{err}");
    }

    // JWT-009: a token whose signature is tampered fails signature verification.
    #[test]
    fn rejects_tampered_signature() {
        let n = now();
        let token = mint(json!({ "iss": TEST_ISSUER, "exp": n + 3600, "iat": n }));
        // Flip the last character of the signature segment.
        let (head, sig) = token.rsplit_once('.').expect("three segments");
        let last = sig.chars().last().expect("non-empty signature");
        let swapped = if last == 'A' { 'B' } else { 'A' };
        let tampered = format!("{head}.{}{swapped}", &sig[..sig.len() - 1]);
        let err = validate_token(&tampered, &public_key(), &ValidationOptions::new())
            .expect_err("tampered signature rejected");
        assert!(err.to_string().contains("signature"), "{err}");
    }

    // A correctly signed token whose header alg is not in the allowlist is
    // rejected before verification (algorithm-confusion defence).
    #[test]
    fn rejects_disallowed_algorithm() {
        let n = now();
        let token = mint(json!({ "iss": TEST_ISSUER, "exp": n + 3600, "iat": n }));
        let opts = ValidationOptions::builder()
            .allowed_algorithms(["ES256"])
            .build();
        let err = validate_token(&token, &public_key(), &opts).expect_err("RS256 disallowed");
        assert!(err.to_string().contains("disallowed"), "{err}");
    }

    // A token with the wrong number of segments is malformed.
    #[test]
    fn rejects_malformed_token() {
        let err = validate_token("not.a", &public_key(), &ValidationOptions::new())
            .expect_err("two-segment token rejected");
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    // JWT-005: end-to-end, an expired token minted with the fixture key is
    // rejected on the claim check after a successful signature verification.
    #[test]
    fn rejects_expired_token_end_to_end() {
        let n = now();
        let token = mint(json!({ "iss": TEST_ISSUER, "exp": n - 10, "iat": n - 3600 }));
        let err = validate_token(&token, &public_key(), &ValidationOptions::new())
            .expect_err("expired rejected");
        assert!(err.to_string().contains("expired"), "{err}");
    }

    // JWT-011: an expired-within-skew token passes once the skew tolerance is
    // configured, proving signature + claim validation compose.
    #[test]
    fn tolerates_skew_end_to_end() {
        let n = now();
        let token = mint(json!({ "iss": TEST_ISSUER, "exp": n - 30, "iat": n - 3600 }));
        let opts = ValidationOptions::builder()
            .clock_skew(Duration::from_secs(120))
            .build();
        validate_token(&token, &public_key(), &opts).expect("within skew passes");
    }
}
