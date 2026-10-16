//! JWT validation: verify JWS signatures and registered claims.
//!
//! [`validate_token`] verifies a compact-serialized JWT against an
//! already-resolved [`JsonWebKey`]; [`validate_token_with_jwks`] resolves the
//! signing key from a [`JwksClient`] by the token's `kid` — forcing one JWKS
//! refresh on a miss (JWKS-004), or narrowing the set to a single key when
//! there is no `kid` (JWKS-009) — before delegating to it. Both reject the
//! unsecured `none` algorithm before any cryptographic work (JWT-003) and
//! restrict acceptance to an asymmetric algorithm allowlist to defeat
//! algorithm-confusion attacks. Behaviour is proven against the cross-language
//! conformance IDs `JWT-001`..`JWT-013` in `spec/vectors/validation.json`.
//!
//! RFC / spec references: RFC 7519 (JWT), RFC 7515 (JWS), OIDC Core 1.0
//! §3.1.3.7.
//!
//! ```no_run
//! # async fn run() -> rs_identity_model::Result<()> {
//! use rs_identity_model::{JwksClient, ValidationOptions, validate_token_with_jwks};
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
mod claims_validation;
mod id_token;
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
pub use claims_validation::{
    BoxedClaimsValidator, ClaimsValidationError, ClaimsValidator, CombineMode, CombinedValidator,
    boxed, combine_claims_validators, from_fn, require_claim_value, require_claims, require_scopes,
};
pub use id_token::{
    IdTokenValidationOptions, IdTokenValidationOptionsBuilder, validate_id_token,
    validate_id_token_claims,
};
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

    // Injectable, composable claims validator (#603): the application-policy
    // hook runs only after the signature, algorithm allowlist, and
    // registered/configured claim checks pass — parity with the Python
    // pipeline's `validate_claims`, which runs after `decode_with_config`. A
    // clean rejection surfaces as `IdentityError::ClaimsValidation` carrying the
    // structured reason/claim; any other error the validator returns propagates
    // unchanged. (The Python layer additionally logs the rejection server-side;
    // this crate has no logging facility, so the structured error is the
    // observability channel — the caller decides how to record it.)
    if let Some(validator) = &options.claims_validator {
        validator.validate(&claims)?;
    }

    Ok(claims)
}

/// Validates a compact-serialized JWT, resolving its signing key from `jwks` by
/// the token's `kid`, and returns its typed [`Claims`].
///
/// The `none` algorithm is rejected and the header `alg` is checked against the
/// allowlist before the key is resolved, so a `none`/disallowed token never
/// triggers a JWKS fetch. Key resolution forces one JWKS refresh and retries if
/// the `kid` is not cached (JWKS-004), supporting key rotation, before delegating
/// to [`validate_token`]. A token with no `kid` is verified by the single key
/// left after narrowing the set by `use`, `alg` and `kty`, with no refresh
/// (JWKS-009, see [`JwksClient::resolve_signing_key`]).
///
/// # Errors
///
/// [`IdentityError::KeyNotFound`] when no key matches the token's `kid` even
/// after a refresh; [`IdentityError::AmbiguousKey`] when the token has no `kid`
/// and more than one key could verify it; [`IdentityError::KeyAlgorithmMismatch`]
/// when the resolved key declares an `alg` other than the token's (JWKS-010);
/// otherwise the errors of
/// [`validate_token`] and [`JwksClient::resolve_signing_key`].
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
    // and retry if the kid is not cached (RFC 7517 §4.5). With no kid, the
    // single key left after narrowing by use, alg and kty is used, with no
    // refresh; more than one is `AmbiguousKey` (JWKS-009).
    let key = jwks
        .resolve_signing_key(jwks_uri, &header.kid, &header.alg)
        .await?;
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

/// Returns the `alg` from a compact JWS protected header, or `None` when the
/// header carries no (or an empty) `alg`.
///
/// Used by the ID-Token profile after base validation to select the
/// `at_hash`/`c_hash` hash: because [`validate_token`] verifies the signature
/// under exactly this header `alg` (and rejects any `alg` outside the
/// allowlist), the value returned here for an already-validated token is the
/// *signature-verified* algorithm, not an unauthenticated header read.
///
/// # Errors
///
/// [`IdentityError::Validation`] when the token is not a well-formed compact
/// JWS (the same parse errors as [`validate_token`]).
pub(super) fn parse_header_alg(token: &str) -> Result<Option<String>> {
    let header = parse_header(token.trim())?;
    Ok((!header.alg.is_empty()).then_some(header.alg))
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
pub(super) fn now_unix() -> i64 {
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

    /// Builds an RS256 [`EncodingKey`] from the shared private-key fixture
    /// (`signing-key.pkcs1.der`, the PKCS#1 DER form of `signing-key.jwk.json`)
    /// so unit tests sign tokens with the same key material as the other
    /// languages — without depending on the `rsa` crate (RUSTSEC-2023-0071).
    fn signing_key() -> EncodingKey {
        EncodingKey::from_rsa_der(&read_fixture("signing-key.pkcs1.der"))
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

    // JWT-001 / AC-1: an ES256 token verifies through the EC key path
    // (`DecodingKey::from_ec_components`), exercising the asymmetric algorithm
    // family that the RSA-only fixtures cannot reach.
    #[test]
    fn accepts_valid_ec_token() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::pkcs8::{EncodePrivateKey, LineEnding as P256LineEnding};

        // A fixed non-zero P-256 secret scalar keeps the test deterministic.
        let secret = p256::SecretKey::from_slice(&[1u8; 32]).expect("valid P-256 scalar");
        let pkcs8 = secret.to_pkcs8_pem(P256LineEnding::LF).expect("pkcs8 pem");
        let encoding = EncodingKey::from_ec_pem(pkcs8.as_bytes()).expect("EC encoding key");

        let point = secret.public_key().to_sec1_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("y coordinate"));
        let jwk: JsonWebKey = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": "ec-test",
            "alg": "ES256",
        }))
        .expect("EC jwk");

        let n = now();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("ec-test".to_string());
        let claims = json!({ "iss": TEST_ISSUER, "sub": "ec-user", "exp": n + 3600, "iat": n });
        let token = jsonwebtoken::encode(&header, &claims, &encoding).expect("sign ES256");

        let opts = ValidationOptions::builder().issuer(TEST_ISSUER).build();
        let validated = validate_token(&token, &jwk, &opts).expect("valid ES256 token");
        assert_eq!(validated.subject.as_deref(), Some("ec-user"));
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

    // End-to-end through signature verification: base `validate_token` checks
    // the expected audience and ignores azp, so an access token issued to a
    // resource server on behalf of a SPA validates. azp is enforced only by the
    // ID-token profile (OIDC Core 1.0 §3.1.3.7 steps 4-6), matching Python and Go.
    #[test]
    fn validate_token_ignores_azp_on_access_token() {
        let n = now();
        let opts = ValidationOptions::builder()
            .issuer(TEST_ISSUER)
            .audience("api")
            .build();

        let token = mint(json!({
            "iss": TEST_ISSUER,
            "sub": "user-1",
            "aud": ["api", "https://idp.example/userinfo"],
            "azp": "spa-client",
            "exp": n + 3600,
            "iat": n - 5,
        }));
        let validated = validate_token(&token, &public_key(), &opts)
            .expect("access token with foreign azp validates");
        assert_eq!(validated.authorized_party.as_deref(), Some("spa-client"));
        assert_eq!(validated.subject.as_deref(), Some("user-1"));
    }

    /// Mints an RS256 token with no `kid` header carrying `claims`.
    fn mint_without_kid(claims: Value) -> String {
        let header = Header::new(Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
    }

    /// Serves `keys` (merged into a JWK Set) at `/jwks` and returns the server
    /// and its `jwks_uri`.
    async fn serve_jwks(keys: Vec<Value>) -> (wiremock::MockServer, String) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
            .mount(&server)
            .await;
        let uri = format!("{}/jwks", server.uri());
        (server, uri)
    }

    fn fixture_jwk() -> Value {
        let set: Value = serde_json::from_slice(&read_fixture("jwks.json")).expect("jwks fixture");
        set["keys"][0].clone()
    }

    fn kidless_claims() -> Value {
        let n = now();
        json!({ "iss": TEST_ISSUER, "sub": "user-1", "aud": TEST_AUDIENCE, "exp": n + 3600, "iat": n - 5 })
    }

    // JWKS-009: a token with no kid verifies against the single key in the set,
    // which has a kid of its own, with no forced refresh.
    #[tokio::test]
    async fn validate_with_jwks_without_kid_uses_single_key() {
        let (server, uri) = serve_jwks(vec![fixture_jwk()]).await;
        let client = JwksClient::builder().allow_http(true).build();
        let opts = ValidationOptions::builder().issuer(TEST_ISSUER).build();

        let claims =
            validate_token_with_jwks(&mint_without_kid(kidless_claims()), &client, &uri, &opts)
                .await
                .expect("kid-less token verifies");

        assert_eq!(claims.subject.as_deref(), Some("user-1"));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "no forced refresh"
        );
    }

    // JWKS-009: with no kid, an RS256 token is verified by the RSA key of an
    // {EC, RSA} set rather than the first key.
    #[tokio::test]
    async fn validate_with_jwks_without_kid_narrows_by_kty() {
        let ec = json!({"kty":"EC","kid":"ec-sig-key","use":"sig","crv":"P-256",
            "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"});
        let (_server, uri) = serve_jwks(vec![ec, fixture_jwk()]).await;
        let client = JwksClient::builder().allow_http(true).build();
        let opts = ValidationOptions::builder().issuer(TEST_ISSUER).build();

        validate_token_with_jwks(&mint_without_kid(kidless_claims()), &client, &uri, &opts)
            .await
            .expect("RSA key selected");
    }

    // JWKS-009: with no kid and two RSA signing keys the key is ambiguous, a
    // typed error distinct from KeyNotFound, with no forced refresh.
    #[tokio::test]
    async fn validate_with_jwks_without_kid_ambiguous() {
        let mut other = fixture_jwk();
        other["kid"] = json!("other-key");
        let (server, uri) = serve_jwks(vec![fixture_jwk(), other]).await;
        let client = JwksClient::builder().allow_http(true).build();
        let opts = ValidationOptions::builder().issuer(TEST_ISSUER).build();

        let err =
            validate_token_with_jwks(&mint_without_kid(kidless_claims()), &client, &uri, &opts)
                .await
                .expect_err("ambiguous");

        assert!(
            matches!(&err, IdentityError::AmbiguousKey { count: 2, .. }),
            "expected AmbiguousKey, got {err:?}"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "no forced refresh"
        );
    }

    // JWKS-010: a correctly signed RS256 token is rejected when the key that
    // verifies it declares RS384, whether the token names it by kid or not.
    #[tokio::test]
    async fn validate_with_jwks_rejects_key_declaring_other_alg() {
        let mut rs384 = fixture_jwk();
        rs384["alg"] = json!("RS384");
        let (_server, uri) = serve_jwks(vec![rs384]).await;
        let client = JwksClient::builder().allow_http(true).build();
        let opts = ValidationOptions::builder().issuer(TEST_ISSUER).build();

        for token in [mint(kidless_claims()), mint_without_kid(kidless_claims())] {
            let err = validate_token_with_jwks(&token, &client, &uri, &opts)
                .await
                .expect_err("key declares RS384");
            assert!(
                matches!(&err, IdentityError::KeyAlgorithmMismatch { key_alg, alg, .. }
                    if key_alg == "RS384" && alg == "RS256"),
                "expected KeyAlgorithmMismatch, got {err:?}"
            );
        }
    }
}
