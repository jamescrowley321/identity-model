//! OpenID Connect ID Token profile validation (OIDC Core 1.0 §3.1.3.7 / §3.3.2.11).
//!
//! Standard JWT validation — signature (via JWKS), `iss`, `aud`, `iat` and
//! `exp` — is performed by the base [`validate_token`](crate::validate_token)
//! path. [`validate_id_token_claims`] enforces only the additional rules that
//! make an ID Token an ID Token, on an already-decoded [`Claims`] set:
//!
//! * `sub` is REQUIRED and must be non-empty (§2 / §3.1.3.7).
//! * `azp` authorized-party rules when the token carries multiple audiences
//!   (§3.1.3.7 steps 4-6).
//! * `nonce` binding, when the caller supplies the `nonce` it sent on the
//!   authorization request (§3.1.3.7 step 11).
//! * `auth_time` freshness against `max_age` (§3.1.3.7 step 12).
//! * `at_hash` / `c_hash` token/code binding for the hybrid and
//!   authorization-code flows (§3.3.2.11).
//!
//! The `at_hash`/`c_hash` hash is chosen from the ID Token header `alg` — the
//! *signature-verified* algorithm ([`super::parse_header_alg`]), never an
//! unauthenticated header read — and the profile fails **closed**: an unknown
//! or missing `alg` on a hash check is an error, not a skipped check. Claim
//! comparisons (`nonce`/`at_hash`/`c_hash`) are constant-time
//! ([`subtle::ConstantTimeEq`]).
//!
//! Behaviour is proven against the cross-language conformance IDs
//! `IDT-001`..`IDT-011` in `spec/vectors/id-token.json`
//! (`rust/tests/spec_conformance_id_token.rs`) — the same language-neutral
//! vector set the Python (`core/id_token_logic.py`) and Go runners execute.
//!
//! This module positively validates the ID-Token profile; it deliberately does
//! not reject "access-token-looking" claim sets — that ID-token-vs-access-token
//! discrimination belongs in the relying-party middleware layer, not here.
//!
//! ```no_run
//! # async fn run() -> rs_identity_model::Result<()> {
//! use rs_identity_model::{
//!     IdTokenValidationOptions, JwksClient, ValidationOptions, validate_id_token,
//! };
//!
//! let jwks = JwksClient::new();
//! // Base rules: signature + issuer + audience(client_id) + exp.
//! let base = ValidationOptions::builder()
//!     .issuer("https://op.example.com")
//!     .audience("s6BhdRkqt3")
//!     .build();
//! // ID-Token profile: bind to the nonce sent on the authorization request.
//! let profile = IdTokenValidationOptions::builder()
//!     .client_id("s6BhdRkqt3")
//!     .nonce("n-0S6_WzA2Mj")
//!     .build();
//! let claims = validate_id_token(
//!     "eyJ...",
//!     &jwks,
//!     "https://op.example.com/jwks",
//!     &base,
//!     &profile,
//! )
//! .await?;
//! println!("subject = {:?}", claims.subject);
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::jwks::JwksClient;
use crate::{IdentityError, Result};

use super::claims::Claims;
use super::options::ValidationOptions;
use super::{now_unix, parse_header_alg, validate_token_with_jwks};

/// The signing algorithms whose `at_hash`/`c_hash` digest is SHA-512 regardless
/// of a numeric suffix (the EdDSA family). Every other supported `alg` is
/// resolved from its trailing SHA-2 size (`*256`/`*384`/`*512`).
const EDDSA_ALGS: &[&str] = &["EdDSA", "Ed25519"];

/// Opt-in inputs for the ID-Token profile checks (OIDC Core §3.1.3.7 /
/// §3.3.2.11).
///
/// Construct one with [`IdTokenValidationOptions::builder`]. Every field is
/// optional: an empty options set enforces only the always-on rules (a
/// non-empty `sub` and the `azp` authorized-party rules). Each remaining check
/// runs only when its input is supplied — a `nonce`, an `access_token` (for
/// `at_hash`), a `code` (for `c_hash`), or a `max_age` (for `auth_time`).
#[derive(Clone, Debug, Default)]
pub struct IdTokenValidationOptions {
    pub(crate) client_id: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) max_age: Option<i64>,
    pub(crate) leeway: Duration,
    pub(crate) now: Option<i64>,
}

impl IdTokenValidationOptions {
    /// Returns an options set with every check disabled (only the always-on
    /// `sub` and `azp` rules apply).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a builder for customising the ID-Token profile inputs.
    pub fn builder() -> IdTokenValidationOptionsBuilder {
        IdTokenValidationOptionsBuilder::new()
    }
}

/// Builder for [`IdTokenValidationOptions`]. Obtain one via
/// [`IdTokenValidationOptions::builder`].
#[derive(Clone, Debug, Default)]
pub struct IdTokenValidationOptionsBuilder {
    inner: IdTokenValidationOptions,
}

impl IdTokenValidationOptionsBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Sets the relying party's `client_id`. When a present `azp` is validated
    /// it MUST equal this value (§3.1.3.7 step 6). [`validate_id_token`]
    /// defaults it to the base audience when unset.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.inner.client_id = Some(client_id.into());
        self
    }

    /// Requires the token's `nonce` to be present and equal `nonce` — the value
    /// the RP sent on the authorization request (§3.1.3.7 step 11).
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.inner.nonce = Some(nonce.into());
        self
    }

    /// Requires the token's `at_hash` to be present and bind to `access_token`
    /// (§3.3.2.11).
    pub fn access_token(mut self, access_token: impl Into<String>) -> Self {
        self.inner.access_token = Some(access_token.into());
        self
    }

    /// Requires the token's `c_hash` to be present and bind to `code`, the
    /// authorization code (§3.3.2.11).
    pub fn code(mut self, code: impl Into<String>) -> Self {
        self.inner.code = Some(code.into());
        self
    }

    /// Requires `auth_time` to be present and satisfy
    /// `now - auth_time <= max_age + leeway` (§3.1.3.7 step 12).
    pub fn max_age(mut self, max_age: i64) -> Self {
        self.inner.max_age = Some(max_age);
        self
    }

    /// Tolerates up to `leeway` of clock drift on the `max_age`/`auth_time`
    /// freshness check. The default is zero.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.inner.leeway = leeway;
        self
    }

    /// Overrides the reference clock (seconds since the Unix epoch) used by the
    /// `max_age`/`auth_time` check. Injected for deterministic tests; defaults
    /// to the real clock when unset.
    pub fn now(mut self, now: i64) -> Self {
        self.inner.now = Some(now);
        self
    }

    /// Builds the [`IdTokenValidationOptions`].
    pub fn build(self) -> IdTokenValidationOptions {
        self.inner
    }
}

/// Resolves the SHA-2 hash constructor implied by an ID Token `alg` and returns
/// the digest of `bytes` under it (§3.3.2.11).
///
/// `RS256`/`ES256`/`PS256`/`HS256` → SHA-256, `*384` → SHA-384, `*512` →
/// SHA-512; `EdDSA`/`Ed25519` → SHA-512.
///
/// # Errors
///
/// [`IdentityError::IdTokenValidation`] when `alg` is missing (`alg_required`)
/// or cannot be mapped to a hash (`unsupported_alg`). Fails **closed** — an
/// unknown `alg` for a hash check is an error, never a silently skipped check.
fn digest_for_alg(bytes: &[u8], alg: Option<&str>) -> Result<Vec<u8>> {
    let alg = alg.map(str::trim).unwrap_or_default();
    if alg.is_empty() {
        return Err(IdentityError::IdTokenValidation(
            "ID token header 'alg' is required to validate at_hash/c_hash".to_string(),
        ));
    }
    if EDDSA_ALGS.contains(&alg) {
        // Assumes Ed25519 (SHA-512). Ed448 also carries alg "EdDSA" but hashes
        // with SHAKE256; it is intentionally unsupported here and fails closed
        // on the resulting at_hash/c_hash mismatch.
        return Ok(Sha512::digest(bytes).to_vec());
    }
    if alg.ends_with("256") {
        Ok(Sha256::digest(bytes).to_vec())
    } else if alg.ends_with("384") {
        Ok(Sha384::digest(bytes).to_vec())
    } else if alg.ends_with("512") {
        Ok(Sha512::digest(bytes).to_vec())
    } else {
        Err(IdentityError::IdTokenValidation(format!(
            "Unsupported ID token 'alg' {alg:?} for at_hash/c_hash validation"
        )))
    }
}

/// Computes the OIDC left-half hash of `value` under the ID Token `alg`
/// (§3.3.2.11): base64url-no-pad of the left-most half of `H(value.ascii)`.
fn left_half_hash(value: &str, alg: Option<&str>) -> Result<String> {
    let digest = digest_for_alg(value.as_bytes(), alg)?;
    let half = digest.len() / 2;
    Ok(URL_SAFE_NO_PAD.encode(&digest[..half]))
}

/// Constant-time equality of two ASCII claim strings (`nonce`/`at_hash`/
/// `c_hash`). Unequal lengths compare unequal without leaking the length via a
/// per-byte timing difference.
fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Reads a claim as an integer number of seconds, rejecting JSON booleans
/// (which `serde_json` would otherwise not coerce anyway) and non-numeric
/// values. Fractional NumericDates are truncated toward zero.
fn numeric_seconds(value: &Value) -> Option<i64> {
    if value.is_boolean() {
        return None;
    }
    if let Some(i) = value.as_i64() {
        return Some(i);
    }
    value.as_f64().map(|f| f.trunc() as i64)
}

/// Validates the ID-Token-specific claim rules on an already-decoded claim set
/// (OIDC Core §3.1.3.7 / §3.3.2.11).
///
/// Assumes the JWT signature, `iss`, `aud`, `iat` and (when present) `exp` have
/// ALREADY been verified by the base [`validate_token`](crate::validate_token)
/// path, and that the caller's `client_id` has been enforced as an `aud` member
/// there. This function enforces only the rules unique to ID Tokens.
///
/// `header_alg` is the ID Token's JOSE-header `alg` (the signature-verified
/// algorithm), used to select the `at_hash`/`c_hash` hash. Pass it as the
/// already-decoded [`Claims`] plus `header_alg` plus [`IdTokenValidationOptions`]
/// so the check is fully offline (no network, no signature step) — this is the
/// entry point the cross-language conformance vectors drive.
///
/// # Errors
///
/// [`IdentityError::IdTokenValidation`] when any ID-Token profile rule is
/// violated. Fails **closed**: a hash check whose `header_alg` is missing or
/// unmappable is an error, not a skipped check.
pub fn validate_id_token_claims(
    claims: &Claims,
    header_alg: Option<&str>,
    options: &IdTokenValidationOptions,
) -> Result<()> {
    // §2 / §3.1.3.7 — `sub` is REQUIRED and must be non-empty.
    if claims.subject.as_deref().unwrap_or_default().is_empty() {
        return Err(IdentityError::IdTokenValidation(
            "ID token missing required 'sub' claim".to_string(),
        ));
    }

    // §3.1.3.7 steps 4-6 — authorized-party (`azp`) rules.
    //
    // The trusted Python oracle (`core/id_token_logic.py`) gates the
    // multi-audience "azp REQUIRED" rule on `not azp`, whose truthiness treats
    // an EMPTY-STRING `azp` identically to an absent one — so a multi-aud token
    // carrying `azp: ""` must be rejected, not accepted. Mirror that here (the
    // previous `azp.is_none()` accepted `azp: ""`, a narrow fail-open). The
    // subsequent mismatch check keeps the oracle's `azp is not None` guard, so a
    // present-but-empty `azp` is still compared against `client_id`.
    let audiences = claims.audience.values();
    let azp = claims.authorized_party.as_deref();
    let azp_present = azp.is_some_and(|value| !value.is_empty());
    if audiences.len() > 1 && !azp_present {
        // Step 4: with multiple audiences an `azp` claim MUST be present — an
        // empty-string `azp` counts as absent, matching the oracle's `not azp`.
        return Err(IdentityError::IdTokenValidation(
            "ID token with multiple audiences must contain an 'azp' claim".to_string(),
        ));
    }
    if let (Some(azp), Some(client_id)) = (azp, options.client_id.as_deref())
        && azp != client_id
    {
        // Step 6: a present `azp` (including an empty string, matching the
        // oracle's `azp is not None`) MUST identify this client.
        return Err(IdentityError::IdTokenValidation(
            "ID token 'azp' claim does not match the configured client_id".to_string(),
        ));
    }

    // §3.1.3.7 step 11 — `nonce` binding (only when the caller passed one).
    if let Some(expected) = options.nonce.as_deref() {
        let matches = claims
            .nonce
            .as_deref()
            .is_some_and(|actual| ct_eq(actual, expected));
        if !matches {
            return Err(IdentityError::IdTokenValidation(
                "ID token 'nonce' claim does not match the expected value".to_string(),
            ));
        }
    }

    // §3.1.3.7 step 12 — `auth_time` freshness (only when `max_age` passed).
    if let Some(max_age) = options.max_age {
        let auth_time = claims.get("auth_time").and_then(numeric_seconds);
        let Some(auth_time) = auth_time else {
            return Err(IdentityError::IdTokenValidation(
                "ID token missing required numeric 'auth_time' claim for max_age check".to_string(),
            ));
        };
        let now = options.now.unwrap_or_else(now_unix);
        let leeway = i64::try_from(options.leeway.as_secs()).unwrap_or(i64::MAX);
        if now.saturating_sub(auth_time) > max_age.saturating_add(leeway) {
            return Err(IdentityError::IdTokenValidation(
                "ID token 'auth_time' is older than the permitted max_age".to_string(),
            ));
        }
    }

    // §3.3.2.11 — `at_hash` binding (only when an access token was passed).
    if let Some(access_token) = options.access_token.as_deref() {
        let expected = left_half_hash(access_token, header_alg)?;
        let matches = claims
            .get_str("at_hash")
            .is_some_and(|actual| ct_eq(actual, &expected));
        if !matches {
            return Err(IdentityError::IdTokenValidation(
                "ID token 'at_hash' claim does not match the access token".to_string(),
            ));
        }
    }

    // §3.3.2.11 — `c_hash` binding (only when an authorization code was passed).
    if let Some(code) = options.code.as_deref() {
        let expected = left_half_hash(code, header_alg)?;
        let matches = claims
            .get_str("c_hash")
            .is_some_and(|actual| ct_eq(actual, &expected));
        if !matches {
            return Err(IdentityError::IdTokenValidation(
                "ID token 'c_hash' claim does not match the authorization code".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validates an OpenID Connect ID Token end-to-end (OIDC Core §3.1.3.7 /
/// §3.3.2.11).
///
/// Runs the standard JWT validation via
/// [`validate_token_with_jwks`](crate::validate_token_with_jwks) (signature
/// resolved from `jwks`/`jwks_uri`, plus `iss`/`aud`/`iat`/`exp` per `base` —
/// set `base` audience to the RP's `client_id` so the `aud` check is enforced),
/// then applies the ID-Token profile from `profile`: required `sub`, the `azp`
/// authorized-party rules, and the opt-in `nonce`/`max_age`/`at_hash`/`c_hash`
/// bindings that are checked only when the corresponding option is supplied.
///
/// When `profile.client_id` is unset it defaults to the `base` audience, so a
/// caller that already set the audience need not repeat the `client_id`.
///
/// # Errors
///
/// - [`IdentityError::Validation`] — standard JWT validation failed (bad
///   signature, wrong issuer/audience, expired token).
/// - [`IdentityError::KeyNotFound`] — no JWKS key matched the token's `kid`.
/// - [`IdentityError::IdTokenValidation`] — an ID-Token-profile rule failed.
/// - the transport/parse errors of
///   [`validate_token_with_jwks`](crate::validate_token_with_jwks).
pub async fn validate_id_token(
    id_token: &str,
    jwks: &JwksClient,
    jwks_uri: &str,
    base: &ValidationOptions,
    profile: &IdTokenValidationOptions,
) -> Result<Claims> {
    let claims = validate_token_with_jwks(id_token, jwks, jwks_uri, base).await?;
    // The signature was verified under exactly this header `alg`, so reading it
    // back is the *verified* algorithm, not an unauthenticated header read.
    let header_alg = parse_header_alg(id_token)?;

    let mut effective = profile.clone();
    if effective.client_id.is_none() {
        effective.client_id = base.expected_audience.clone();
    }
    validate_id_token_claims(&claims, header_alg.as_deref(), &effective)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a [`Claims`] set from a JSON object literal for the profile tests.
    fn claims(value: Value) -> Claims {
        Claims::from_json(value).expect("valid claims object")
    }

    /// Asserts a rejection is an [`IdentityError::IdTokenValidation`] whose
    /// message contains `needle` (the stable per-reason marker).
    fn assert_id_token_reject(err: &IdentityError, needle: &str) {
        match err {
            IdentityError::IdTokenValidation(msg) => {
                assert!(msg.contains(needle), "message {msg:?} lacks {needle:?}");
            }
            other => panic!("expected IdTokenValidation, got {other:?}"),
        }
    }

    // IDT-001 / IDT-003: a non-empty sub with a single audience equal to the
    // client_id and no optional bindings requested validates.
    #[test]
    fn accepts_baseline_single_audience() {
        let c = claims(
            json!({"iss": "https://op.example.com", "sub": "248289761001", "aud": "s6BhdRkqt3"}),
        );
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        validate_id_token_claims(&c, Some("RS256"), &opts).expect("baseline validates");
    }

    // IDT-002: sub is REQUIRED and must be non-empty.
    #[test]
    fn rejects_missing_or_empty_sub() {
        let opts = IdTokenValidationOptions::new();
        let absent = claims(json!({"aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &opts).unwrap_err(),
            "required 'sub'",
        );
        let empty = claims(json!({"sub": "", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&empty, Some("RS256"), &opts).unwrap_err(),
            "required 'sub'",
        );
    }

    // IDT-003: multiple audiences REQUIRE an azp that identifies this client.
    #[test]
    fn enforces_azp_for_multiple_audiences() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();

        let single_list = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3"]}));
        validate_id_token_claims(&single_list, Some("RS256"), &cid)
            .expect("single-element aud list needs no azp");

        let no_azp = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"]}));
        assert_id_token_reject(
            &validate_id_token_claims(&no_azp, Some("RS256"), &cid).unwrap_err(),
            "multiple audiences must contain an 'azp'",
        );

        let wrong_azp = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "other-client-9x"}),
        );
        assert_id_token_reject(
            &validate_id_token_claims(&wrong_azp, Some("RS256"), &cid).unwrap_err(),
            "'azp' claim does not match",
        );

        let right_azp = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "s6BhdRkqt3"}),
        );
        validate_id_token_claims(&right_azp, Some("RS256"), &cid)
            .expect("multi-aud with matching azp validates");
    }

    // An empty-string `azp` must behave exactly like the Python oracle's
    // `not azp` / `azp is not None` truthiness (F-1 parity), NOT like Rust's
    // former `azp.is_none()`:
    //   * multi-aud + azp=""            -> azp_required_multi_aud (was fail-open
    //     accept when no client_id was configured);
    //   * multi-aud + azp="" + client_id -> still azp_required_multi_aud, since
    //     the required-multi-aud check precedes the mismatch check;
    //   * single-aud + azp="" + client_id -> azp_mismatch (the oracle's mismatch
    //     guard is `azp is not None`, so a present empty string is compared);
    //   * single-aud + azp="" + no client_id -> accept (no client_id to compare).
    #[test]
    fn empty_string_azp_matches_oracle_truthiness() {
        // multi-aud + azp="" with no configured client_id: the former
        // `azp.is_none()` accepted this; the oracle rejects it.
        let multi_empty =
            claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": ""}));
        assert_id_token_reject(
            &validate_id_token_claims(
                &multi_empty,
                Some("RS256"),
                &IdTokenValidationOptions::new(),
            )
            .unwrap_err(),
            "multiple audiences must contain an 'azp'",
        );

        // multi-aud + azp="" WITH a client_id: the required-multi-aud check
        // fires first (matching the oracle), not the mismatch check.
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&multi_empty, Some("RS256"), &cid).unwrap_err(),
            "multiple audiences must contain an 'azp'",
        );

        // single-aud + azp="" WITH a client_id: the oracle's `azp is not None`
        // guard compares the empty string and rejects as a mismatch.
        let single_empty_cid = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": ""}));
        assert_id_token_reject(
            &validate_id_token_claims(&single_empty_cid, Some("RS256"), &cid).unwrap_err(),
            "'azp' claim does not match",
        );

        // single-aud + azp="" with NO client_id: nothing to compare, accept.
        validate_id_token_claims(
            &single_empty_cid,
            Some("RS256"),
            &IdTokenValidationOptions::new(),
        )
        .expect("empty azp on single audience with no client_id validates");
    }

    // IDT-004: a present azp is validated even for a single audience.
    #[test]
    fn validates_present_azp_for_single_audience() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        let ok = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "s6BhdRkqt3"}));
        validate_id_token_claims(&ok, Some("RS256"), &cid).expect("matching azp validates");

        let bad = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "impostor-client"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &cid).unwrap_err(),
            "'azp' claim does not match",
        );
    }

    // IDT-005: the nonce binding requires a present, matching nonce.
    #[test]
    fn enforces_nonce_binding() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "nonce": "n-0S6_WzA2Mj"}));
        let matching = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .nonce("n-0S6_WzA2Mj")
            .build();
        validate_id_token_claims(&c, Some("RS256"), &matching).expect("matching nonce validates");

        let mismatch = IdTokenValidationOptions::builder()
            .nonce("a-different-nonce")
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&c, Some("RS256"), &mismatch).unwrap_err(),
            "'nonce' claim does not match",
        );

        let absent = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &matching).unwrap_err(),
            "'nonce' claim does not match",
        );
    }

    // IDT-006: auth_time must be present and within max_age (+ leeway).
    #[test]
    fn enforces_auth_time_freshness() {
        let within = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_999_900}));
        let opts = IdTokenValidationOptions::builder()
            .max_age(3600)
            .now(1_700_000_000)
            .build();
        validate_id_token_claims(&within, Some("RS256"), &opts).expect("fresh auth_time validates");

        let leeway_case =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_996_390}));
        let with_leeway = IdTokenValidationOptions::builder()
            .max_age(3600)
            .leeway(Duration::from_secs(60))
            .now(1_700_000_000)
            .build();
        validate_id_token_claims(&leeway_case, Some("RS256"), &with_leeway)
            .expect("just-past max_age but within leeway validates");

        let stale = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_992_800}));
        assert_id_token_reject(
            &validate_id_token_claims(&stale, Some("RS256"), &opts).unwrap_err(),
            "'auth_time' is older than",
        );

        let missing = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&missing, Some("RS256"), &opts).unwrap_err(),
            "missing required numeric 'auth_time'",
        );
    }

    // IDT-007: at_hash binds to the access token under RS256 (SHA-256), using
    // the real OIDC §3.3.2.11 left-half construction.
    #[test]
    fn enforces_at_hash_rs256() {
        let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU";
        let opts = IdTokenValidationOptions::builder()
            .access_token(access_token)
            .build();

        let good =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));
        validate_id_token_claims(&good, Some("RS256"), &opts).expect("correct at_hash validates");

        let bad =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "DyAleB7ctGQvU9M3DbMBYQ"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &opts).unwrap_err(),
            "'at_hash' claim does not match",
        );

        let absent = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &opts).unwrap_err(),
            "'at_hash' claim does not match",
        );

        // No access_token supplied -> at_hash present but unchecked.
        let unchecked = IdTokenValidationOptions::new();
        validate_id_token_claims(&good, Some("RS256"), &unchecked)
            .expect("at_hash unchecked without an access token");
    }

    // IDT-008: the header alg selects the hash — an ES512 (SHA-512) at_hash
    // validates; an SHA-256-sized at_hash fails closed under ES512.
    #[test]
    fn at_hash_hash_is_selected_by_alg() {
        let es512 = IdTokenValidationOptions::builder()
            .access_token("YmExYzZmZTgtZXM1MTItYWNjZXNzLXRva2VuLWV4YW1wbGU")
            .build();
        let good = claims(json!({
            "sub": "u", "aud": "s6BhdRkqt3",
            "at_hash": "2azZeYx02zZttjvAxgBshVhQxqEJ6Ku0oRgkegwI9Ww"
        }));
        validate_id_token_claims(&good, Some("ES512"), &es512).expect("ES512 at_hash validates");

        // An SHA-256-sized at_hash under an ES512 header must not validate.
        let sha256_sized = IdTokenValidationOptions::builder()
            .access_token("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU")
            .build();
        let mismatched =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));
        assert_id_token_reject(
            &validate_id_token_claims(&mismatched, Some("ES512"), &sha256_sized).unwrap_err(),
            "'at_hash' claim does not match",
        );
    }

    // IDT-009 / IDT-010: c_hash binds to the authorization code under RS256 and
    // ES512. The RS256 case is the OIDC Core §3.3.2.11 worked example.
    #[test]
    fn enforces_c_hash() {
        let rs = IdTokenValidationOptions::builder()
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .build();
        let good =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "LDktKdoQak3Pk0cnXxCltA"}));
        validate_id_token_claims(&good, Some("RS256"), &rs).expect("RS256 c_hash validates");

        let bad =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "DyAleB7ctGQvU9M3DbMBYQ"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &rs).unwrap_err(),
            "'c_hash' claim does not match",
        );

        let es = IdTokenValidationOptions::builder()
            .code("Y29kZS1lczUxMi1hdXRob3JpemF0aW9uLWNvZGUtZXhhbXBsZQ")
            .build();
        let es_good = claims(json!({
            "sub": "u", "aud": "s6BhdRkqt3",
            "c_hash": "5ZRO6ySh8Y5x73OPd63wcyIunjtbSNZh9sQvDCegRDY"
        }));
        validate_id_token_claims(&es_good, Some("ES512"), &es).expect("ES512 c_hash validates");
    }

    // IDT-011: an unknown or missing header alg on a hash check fails closed.
    #[test]
    fn hash_check_fails_closed_on_bad_alg() {
        let at = IdTokenValidationOptions::builder()
            .access_token("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU")
            .build();
        let with_at =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));

        assert_id_token_reject(
            &validate_id_token_claims(&with_at, Some("UNKNOWN"), &at).unwrap_err(),
            "Unsupported ID token 'alg'",
        );
        assert_id_token_reject(
            &validate_id_token_claims(&with_at, None, &at).unwrap_err(),
            "header 'alg' is required",
        );

        let code = IdTokenValidationOptions::builder()
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .build();
        let with_code =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "LDktKdoQak3Pk0cnXxCltA"}));
        assert_id_token_reject(
            &validate_id_token_claims(&with_code, Some("RS999"), &code).unwrap_err(),
            "Unsupported ID token 'alg'",
        );
    }

    // A JSON-boolean auth_time is not a numeric date and fails the max_age check
    // closed rather than coercing.
    #[test]
    fn boolean_auth_time_is_not_numeric() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": true}));
        let opts = IdTokenValidationOptions::builder()
            .max_age(3600)
            .now(1_700_000_000)
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&c, Some("RS256"), &opts).unwrap_err(),
            "missing required numeric 'auth_time'",
        );
    }
}
