//! OpenID Connect ID Token profile validation (OIDC Core 1.0 §3.1.3.7 / §3.3.2.11).
//!
//! Standard JWT validation — signature (via JWKS), `iss`, `aud`, `iat` and
//! `exp` — is performed by the base [`validate_token`](crate::validate_token)
//! path. [`validate_id_token_claims`] enforces only the additional rules that
//! make an ID Token an ID Token, on an already-decoded [`Claims`] set:
//!
//! * `sub` is REQUIRED and must be non-empty (§2 / §3.1.3.7).
//! * every `aud` value must be trusted by the client — its `client_id` or one
//!   of the caller's
//!   [`trusted_audiences`](IdTokenValidationOptionsBuilder::trusted_audiences)
//!   — and `aud` must list the `client_id` itself (§3.1.3.7 step 3). With
//!   neither configured, any `aud` value is untrusted (fail closed).
//! * `azp` authorized-party rules, only when the caller opts in with
//!   [`validate_azp`](IdTokenValidationOptionsBuilder::validate_azp)
//!   (§3.1.3.7 steps 4-5; §2 says to ignore `azp` otherwise).
//! * `nonce` binding, when the caller supplies the `nonce` it sent on the
//!   authorization request (§3.1.3.7 step 11).
//! * `auth_time` freshness against `max_age` (§3.1.3.7 step 12).
//! * `at_hash` / `c_hash` token/code binding for the hybrid and
//!   authorization-code flows (§3.3.2.11). A present hash claim must match. An
//!   absent one is rejected unless the caller says the value did not come in
//!   the same authorization response as the ID Token
//!   (`access_token_issued_with_id_token(false)` /
//!   `code_issued_with_id_token(false)`, §3.1.3.6 / §3.2.2.10 / §3.3.2.11).
//!
//! The `at_hash`/`c_hash` hash is chosen from the ID Token header `alg` — the
//! *signature-verified* algorithm ([`super::parse_header_alg`]), never an
//! unauthenticated header read — and the profile fails **closed**: an unknown
//! or missing `alg` on a hash check is an error, not a skipped check. Claim
//! comparisons (`nonce`/`at_hash`/`c_hash`) are constant-time
//! ([`subtle::ConstantTimeEq`]).
//!
//! Behaviour is proven against the cross-language spec-vector IDs
//! `IDT-001`..`IDT-015` in `spec/vectors/id-token.json`
//! (`rust/tests/it/internal/id_token.rs`) — the same language-neutral
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

use super::claims::{Claims, malformed_claim, missing_claim};
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
/// non-empty `sub`, every `aud` value trusted, and a configured `client_id`
/// listed in `aud`) — with no `client_id` and no trusted audiences configured,
/// any `aud` value is untrusted, so set a `client_id` (or use
/// [`validate_id_token`], which defaults it to the base audience and requires
/// one). Each remaining check runs only when its input is supplied — `validate_azp(true)` (for the `azp`
/// rules), a `nonce`, an `access_token` (for `at_hash`), a `code` (for
/// `c_hash`), or a `max_age` (for `auth_time`).
#[derive(Clone, Debug)]
pub struct IdTokenValidationOptions {
    pub(crate) client_id: Option<String>,
    pub(crate) trusted_audiences: Vec<String>,
    pub(crate) validate_azp: bool,
    pub(crate) nonce: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) access_token_issued_with_id_token: bool,
    pub(crate) code: Option<String>,
    pub(crate) code_issued_with_id_token: bool,
    pub(crate) max_age: Option<i64>,
    pub(crate) leeway: Duration,
    pub(crate) now: Option<i64>,
}

impl Default for IdTokenValidationOptions {
    fn default() -> Self {
        Self {
            client_id: None,
            trusted_audiences: Vec::new(),
            validate_azp: false,
            nonce: None,
            access_token: None,
            // A supplied access token / code is taken to have come back with the
            // ID Token, so its hash claim is required (§3.2.2.10, §3.3.2.11).
            access_token_issued_with_id_token: true,
            code: None,
            code_issued_with_id_token: true,
            max_age: None,
            leeway: Duration::default(),
            now: None,
        }
    }
}

impl IdTokenValidationOptions {
    /// Returns an options set with every opt-in check disabled (only the
    /// always-on `sub` and trusted-audience rules apply).
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

    /// Sets the relying party's `client_id`. The ID Token's `aud` must list it
    /// (§3.1.3.7 step 3), otherwise the token is rejected with
    /// [`IdentityError::AudienceMismatch`]; it is always a trusted `aud`
    /// value, and with
    /// [`validate_azp`](Self::validate_azp) a present `azp` must equal it.
    /// [`validate_id_token`]
    /// defaults it to the base audience when unset. An empty `client_id` is
    /// treated as unset.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.inner.client_id = Some(client_id.into()).filter(|id| !id.is_empty());
        self
    }

    /// Sets the additional audiences, besides the `client_id`, that this client
    /// trusts to appear in the ID Token's `aud` (§3.1.3.7 step 3). Every `aud`
    /// value MUST be the `client_id` or one of these, otherwise the token is
    /// rejected with [`IdentityError::IdTokenUntrustedAudience`].
    ///
    /// The list only *adds* trusted values: an empty list (the default) trusts
    /// the `client_id` alone, and nothing here can switch the check off. A
    /// trusted audience never stands in for the `client_id`, which `aud` must
    /// still list.
    /// Replaces any previously set list.
    pub fn trusted_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inner.trusted_audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Opts in to the authorized-party (`azp`) rules: a token with multiple
    /// audiences must carry a non-empty `azp`, and a present `azp` must equal
    /// the `client_id`. OIDC Core 1.0 errata set 2 makes neither a MUST —
    /// §3.1.3.7 step 5 is a MAY/SHOULD, and the multiple-audience rule is the
    /// Core 1.0 (2014) step-4 SHOULD that errata set 2 removed. Defaults to
    /// `false`: `azp` is ignored, as §2 advises relying parties that use no
    /// extensions. Requires a `client_id`: without one validation fails with
    /// [`IdentityError::IdTokenAzpRequiresClientId`].
    pub fn validate_azp(mut self, validate_azp: bool) -> Self {
        self.inner.validate_azp = validate_azp;
        self
    }

    /// Requires the token's `nonce` to be present and equal `nonce` — the value
    /// the RP sent on the authorization request (§3.1.3.7 step 11).
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.inner.nonce = Some(nonce.into());
        self
    }

    /// Requires the token's `at_hash` to match the left-half hash of
    /// `access_token` (§3.3.2.11). The claim must also be present unless
    /// [`access_token_issued_with_id_token`](Self::access_token_issued_with_id_token)
    /// is `false`.
    pub fn access_token(mut self, access_token: impl Into<String>) -> Self {
        self.inner.access_token = Some(access_token.into());
        self
    }

    /// States whether the [`access_token`](Self::access_token) came back in the
    /// same authorization response as the ID Token (`response_type`
    /// `id_token token` or `code id_token token`), which makes `at_hash`
    /// REQUIRED (§3.2.2.10, §3.3.2.11). Defaults to `true`. Pass `false` for a
    /// token-endpoint ID Token, which may omit `at_hash` (§3.1.3.6); a present
    /// `at_hash` must still match. Has no effect without an access token.
    pub fn access_token_issued_with_id_token(mut self, issued_with_id_token: bool) -> Self {
        self.inner.access_token_issued_with_id_token = issued_with_id_token;
        self
    }

    /// Requires the token's `c_hash` to match the left-half hash of `code`, the
    /// authorization code (§3.3.2.11). The claim must also be present unless
    /// [`code_issued_with_id_token`](Self::code_issued_with_id_token) is
    /// `false`.
    pub fn code(mut self, code: impl Into<String>) -> Self {
        self.inner.code = Some(code.into());
        self
    }

    /// States whether the [`code`](Self::code) came back in the same
    /// authorization response as the ID Token (`response_type` `code id_token`
    /// or `code id_token token`), which makes `c_hash` REQUIRED (§3.3.2.11).
    /// Defaults to `true`. Pass `false` when it did not; a present `c_hash`
    /// must still match. Has no effect without a code.
    pub fn code_issued_with_id_token(mut self, issued_with_id_token: bool) -> Self {
        self.inner.code_issued_with_id_token = issued_with_id_token;
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
/// [`IdentityError::UnsupportedHashAlgorithm`] when `alg` is missing
/// (`alg: None`) or cannot be mapped to a hash. Fails **closed** — an
/// unknown `alg` for a hash check is an error, never a silently skipped check.
fn digest_for_alg(bytes: &[u8], alg: Option<&str>) -> Result<Vec<u8>> {
    let alg = alg.map(str::trim).unwrap_or_default();
    if alg.is_empty() {
        return Err(IdentityError::UnsupportedHashAlgorithm { alg: None });
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
        Err(IdentityError::UnsupportedHashAlgorithm {
            alg: Some(alg.to_string()),
        })
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

/// Rejects [`validate_azp(true)`](IdTokenValidationOptionsBuilder::validate_azp)
/// without a `client_id` (§3.1.3.7 step 5). Reads only the caller's options,
/// so it runs before any claim is read.
fn check_azp_config(options: &IdTokenValidationOptions) -> Result<()> {
    if options.validate_azp && options.client_id.is_none() {
        return Err(IdentityError::IdTokenAzpRequiresClientId);
    }
    Ok(())
}

/// Enforces the opt-in authorized-party (`azp`) rules
/// ([`validate_azp`](IdTokenValidationOptionsBuilder::validate_azp)).
///
/// The trusted Python oracle (`core/id_token_logic.py`) gates the
/// multi-audience rule on `not azp`, whose truthiness treats an EMPTY-STRING
/// `azp` identically to an absent one — so a multi-aud token carrying
/// `azp: ""` is rejected, not accepted. The mismatch check keeps the oracle's
/// `azp is not None` guard, so a present-but-empty `azp` is still compared
/// against `client_id`.
fn validate_azp(claims: &Claims, audiences: &[String], client_id: &str) -> Result<()> {
    let azp = claims.authorized_party.as_deref();
    let azp_present = azp.is_some_and(|value| !value.is_empty());
    if audiences.len() > 1 && !azp_present {
        // Core 1.0 (2014) step 4 SHOULD: multiple audiences carry an `azp`.
        return Err(missing_claim("azp"));
    }
    if let Some(azp) = azp
        && azp != client_id
    {
        // Errata 2 step 5: a present `azp` identifies this client.
        return Err(IdentityError::AuthorizedPartyMismatch {
            expected: client_id.to_string(),
            actual: azp.to_string(),
        });
    }
    Ok(())
}

/// Validates the ID-Token-specific claim rules on an already-decoded claim set
/// (OIDC Core §3.1.3.7 / §3.3.2.11).
///
/// Assumes the JWT signature, `iss`, `aud`, `iat` and (when present) `exp` have
/// ALREADY been verified by the base [`validate_token`](crate::validate_token)
/// path. This function enforces only the rules unique to ID Tokens, including
/// §3.1.3.7 step 3 in full: a configured `client_id` must be an `aud` member
/// whether or not the base path checked an audience.
///
/// `header_alg` is the ID Token's JOSE-header `alg` (the signature-verified
/// algorithm), used to select the `at_hash`/`c_hash` hash. Pass it as the
/// already-decoded [`Claims`] plus `header_alg` plus [`IdTokenValidationOptions`]
/// so the check is fully offline (no network, no signature step) — this is the
/// entry point the cross-language spec vectors drive.
///
/// # Errors
///
/// - [`IdentityError::IdTokenAzpRequiresClientId`] when `validate_azp` is set
///   without a `client_id`, before any claim is read.
/// - [`IdentityError::IdTokenUntrustedAudience`] when an `aud` value is
///   neither the `client_id` nor one of the configured trusted audiences
///   (§3.1.3.7 step 3), carrying the untrusted values. Checked after `sub` and
///   before the opt-in `azp` rules.
/// - [`IdentityError::AudienceMismatch`] when a `client_id` is configured and
///   `aud` does not list it (§3.1.3.7 step 3), carrying the `client_id` and
///   the token's audiences. Checked after the untrusted-audience rule.
/// - [`IdentityError::MissingClaim`] when `sub` is absent or empty, `aud` is
///   absent, null or holds only empty strings (§2, checked after `sub`), a
///   multi-audience token has no `azp`, `auth_time` is absent under `max_age`,
///   or a required `at_hash` / `c_hash` is absent.
/// - [`IdentityError::AuthorizedPartyMismatch`], [`IdentityError::NonceMismatch`],
///   [`IdentityError::MaxAgeExceeded`] or [`IdentityError::TokenHashMismatch`]
///   when the matching opt-in check fails; [`IdentityError::MalformedClaim`]
///   for a non-numeric `auth_time`.
/// - [`IdentityError::UnsupportedHashAlgorithm`] when a hash check's
///   `header_alg` is missing or unmappable. Fails **closed**: an error, not a
///   skipped check.
pub fn validate_id_token_claims(
    claims: &Claims,
    header_alg: Option<&str>,
    options: &IdTokenValidationOptions,
) -> Result<()> {
    // §3.1.3.7 step 5 needs a `client_id` to compare `azp` with.
    check_azp_config(options)?;

    // §2 / §3.1.3.7 — `sub` is REQUIRED and must be non-empty.
    if claims.subject.as_deref().unwrap_or_default().is_empty() {
        return Err(missing_claim("sub"));
    }

    // §2 — `aud` is REQUIRED. An absent or null `aud`, or one holding only
    // empty strings, names no audience and is rejected with or without a
    // `client_id`.
    let audiences = claims.audience.values();
    if audiences.iter().all(String::is_empty) {
        return Err(missing_claim("aud"));
    }

    // §3.1.3.7 step 3 — reject additional audiences not trusted by the
    // client. The trusted set is {client_id} ∪ trusted_audiences; the list
    // only adds trusted values, so with neither configured every `aud` value
    // is untrusted (fail closed).
    let untrusted: Vec<String> = audiences
        .iter()
        .filter(|aud| {
            options.client_id.as_deref() != Some(aud.as_str())
                && !options.trusted_audiences.contains(aud)
        })
        .cloned()
        .collect();
    if !untrusted.is_empty() {
        return Err(IdentityError::IdTokenUntrustedAudience(untrusted));
    }

    // §3.1.3.7 step 3 — the ID Token MUST list the client as a valid
    // audience: trusted additional audiences never stand in for the
    // `client_id`. Checked after the untrusted-audience rule, so a token
    // failing both reports the untrusted values.
    if let Some(client_id) = options.client_id.as_deref()
        && !audiences.iter().any(|aud| aud == client_id)
    {
        return Err(IdentityError::AudienceMismatch {
            expected: client_id.to_string(),
            actual: audiences.to_vec(),
        });
    }

    // §3.1.3.7 steps 4-5 — authorized-party (`azp`) rules, opt-in only.
    if options.validate_azp
        && let Some(client_id) = options.client_id.as_deref()
    {
        validate_azp(claims, audiences, client_id)?;
    }

    // §3.1.3.7 step 11 — `nonce` binding (only when the caller passed one).
    if let Some(expected) = options.nonce.as_deref() {
        let matches = claims
            .nonce
            .as_deref()
            .is_some_and(|actual| ct_eq(actual, expected));
        if !matches {
            return Err(IdentityError::NonceMismatch);
        }
    }

    // §3.1.3.7 step 12 — `auth_time` freshness (only when `max_age` passed).
    if let Some(max_age) = options.max_age {
        let Some(raw_auth_time) = claims.get("auth_time") else {
            return Err(missing_claim("auth_time"));
        };
        let Some(auth_time) = numeric_seconds(raw_auth_time) else {
            return Err(malformed_claim("auth_time", "must be a numeric date"));
        };
        let now = options.now.unwrap_or_else(now_unix);
        let leeway = i64::try_from(options.leeway.as_secs()).unwrap_or(i64::MAX);
        if now.saturating_sub(auth_time) > max_age.saturating_add(leeway) {
            return Err(IdentityError::MaxAgeExceeded {
                auth_time,
                max_age,
                now,
            });
        }
    }

    // §3.3.2.11 — `at_hash` binding (only when an access token was passed).
    if let Some(access_token) = options.access_token.as_deref() {
        validate_hash_binding(
            claims,
            header_alg,
            "at_hash",
            access_token,
            options.access_token_issued_with_id_token,
        )?;
    }

    // §3.3.2.11 — `c_hash` binding (only when an authorization code was passed).
    if let Some(code) = options.code.as_deref() {
        validate_hash_binding(
            claims,
            header_alg,
            "c_hash",
            code,
            options.code_issued_with_id_token,
        )?;
    }

    Ok(())
}

/// Checks that the `claim` hash (`at_hash`/`c_hash`) binds to `value`
/// (§3.3.2.11). Presence is required only when `value` came in the same
/// authorization response as the ID Token (`required`, §3.2.2.10 /
/// §3.3.2.11); otherwise an absent claim is accepted. A present claim must
/// match whatever its type. Presence is checked before the hash is computed,
/// so an absent, unrequired claim never consults the `alg`.
fn validate_hash_binding(
    claims: &Claims,
    header_alg: Option<&str>,
    claim: &str,
    value: &str,
    required: bool,
) -> Result<()> {
    if !claims.has(claim) {
        if required {
            return Err(missing_claim(claim));
        }
        return Ok(());
    }
    let expected = left_half_hash(value, header_alg)?;
    let matches = claims
        .get_str(claim)
        .is_some_and(|actual| ct_eq(actual, &expected));
    if !matches {
        return Err(IdentityError::TokenHashMismatch {
            claim: claim.to_string(),
        });
    }
    Ok(())
}

/// Validates an OpenID Connect ID Token end-to-end (OIDC Core §3.1.3.7 /
/// §3.3.2.11).
///
/// Runs the standard JWT validation via
/// [`validate_token_with_jwks`](crate::validate_token_with_jwks) (signature
/// resolved from `jwks`/`jwks_uri`, plus `iss`/`aud`/`iat`/`exp` per `base`),
/// then applies the ID-Token profile from `profile`: required `sub`, the
/// `client_id` listed in `aud`, every `aud` value trusted (the `client_id` or a
/// [`trusted_audiences`](IdTokenValidationOptionsBuilder::trusted_audiences)
/// entry), and the opt-in `azp`/`nonce`/`max_age`/`at_hash`/`c_hash` checks,
/// each run only when the corresponding option is supplied.
///
/// When `profile.client_id` is unset it defaults to the `base` audience, so a
/// caller that already set the audience need not repeat the `client_id`. One
/// of the two is required.
///
/// # Errors
///
/// - [`IdentityError::IdTokenAzpRequiresClientId`] — `validate_azp` is set but
///   neither `profile` nor the `base` audience supplies a `client_id`. Reported
///   before the JWKS fetch.
/// - [`IdentityError::IdTokenClientIdRequired`] — neither `profile` nor the
///   `base` audience supplies a `client_id` (§3.1.3.7 step 3 needs one to bind
///   the token to). Reported before the JWKS fetch.
/// - the typed JWT errors of [`validate_token`](crate::validate_token) —
///   [`IdentityError::SignatureInvalid`], [`IdentityError::IssuerMismatch`],
///   [`IdentityError::AudienceMismatch`], [`IdentityError::Expired`], ... — when
///   standard JWT validation fails.
/// - [`IdentityError::KeyNotFound`] — no JWKS key matched the token's `kid`.
/// - [`IdentityError::AmbiguousKey`] — the token has no `kid` and more than
///   one JWKS key could verify it.
/// - [`IdentityError::IdTokenUntrustedAudience`] — the token's `aud` carries
///   a value the client does not trust (§3.1.3.7 step 3).
/// - [`IdentityError::AudienceMismatch`] — the token's `aud` does not list the
///   `client_id` (§3.1.3.7 step 3), from the base check when `base` sets the
///   audience, else from the profile.
/// - the ID-Token-profile errors of [`validate_id_token_claims`] when another
///   profile rule fails.
/// - the transport/parse errors of
///   [`validate_token_with_jwks`](crate::validate_token_with_jwks).
pub async fn validate_id_token(
    id_token: &str,
    jwks: &JwksClient,
    jwks_uri: &str,
    base: &ValidationOptions,
    profile: &IdTokenValidationOptions,
) -> Result<Claims> {
    let mut effective = profile.clone();
    // An empty client id (profile or base audience) is unset, as in Python and
    // Go: `aud: [""]` must never bind a token to this client.
    effective.client_id = effective
        .client_id
        .filter(|id| !id.is_empty())
        .or_else(|| base.expected_audience.clone().filter(|aud| !aud.is_empty()));
    check_azp_config(&effective)?;
    // §3.1.3.7 step 3 binds the token to this client's `client_id`; with none
    // configured there is nothing to bind it to.
    if effective.client_id.is_none() {
        return Err(IdentityError::IdTokenClientIdRequired);
    }

    let claims = validate_token_with_jwks(id_token, jwks, jwks_uri, base).await?;
    // The signature was verified under exactly this header `alg`, so reading it
    // back is the *verified* algorithm, not an unauthenticated header read.
    let header_alg = parse_header_alg(id_token)?;

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

    /// Asserts a rejection is exactly the `want` variant.
    fn assert_id_token_reject(err: &IdentityError, want: &IdentityError) {
        assert_eq!(err, want);
    }

    fn missing(claim: &str) -> IdentityError {
        IdentityError::MissingClaim {
            claim: claim.into(),
        }
    }

    fn hash_mismatch(claim: &str) -> IdentityError {
        IdentityError::TokenHashMismatch {
            claim: claim.into(),
        }
    }

    fn azp_mismatch(actual: &str) -> IdentityError {
        IdentityError::AuthorizedPartyMismatch {
            expected: "s6BhdRkqt3".into(),
            actual: actual.into(),
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
            &missing("sub"),
        );
        let empty = claims(json!({"sub": "", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&empty, Some("RS256"), &opts).unwrap_err(),
            &missing("sub"),
        );
    }

    // IDT-013: aud is REQUIRED (§2). A token naming no audience is rejected
    // with or without a client_id, ahead of the untrusted-audience rule.
    #[test]
    fn rejects_missing_audience() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        let none = IdTokenValidationOptions::new();
        for (aud, opts) in [
            (None, &none),
            (None, &cid),
            (Some(json!(null)), &cid),
            (Some(json!("")), &cid),
            (Some(json!([])), &cid),
            (Some(json!(["", ""])), &cid),
        ] {
            let mut value = json!({"sub": "u"});
            if let Some(aud) = &aud {
                value["aud"] = aud.clone();
            }
            assert_id_token_reject(
                &validate_id_token_claims(&claims(value), Some("RS256"), opts).unwrap_err(),
                &missing("aud"),
            );
        }

        // An empty string beside a real audience is untrusted, not missing.
        let mixed = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", ""], "azp": "s6BhdRkqt3"}));
        assert_untrusted_audience(
            &validate_id_token_claims(&mixed, Some("RS256"), &cid).unwrap_err(),
            &[""],
        );
    }

    /// Asserts a rejection is an [`IdentityError::IdTokenUntrustedAudience`]
    /// carrying exactly `expected` (in `aud` order).
    fn assert_untrusted_audience(err: &IdentityError, expected: &[&str]) {
        match err {
            IdentityError::IdTokenUntrustedAudience(untrusted) => {
                let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
                assert_eq!(untrusted, &expected);
            }
            other => panic!("expected IdTokenUntrustedAudience, got {other:?}"),
        }
    }

    // IDT-012: an additional audience the client does not trust is rejected
    // (§3.1.3.7 step 3), carrying exactly the untrusted values.
    #[test]
    fn rejects_untrusted_additional_audience() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        let c = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "s6BhdRkqt3"}),
        );
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &cid).unwrap_err(),
            &["other-client-9x"],
        );

        // Only the values outside the trusted set are reported.
        let partly = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .build();
        let three = claims(json!({
            "sub": "u",
            "aud": ["s6BhdRkqt3", "other-client-9x", "unknown-api-7q"],
            "azp": "s6BhdRkqt3"
        }));
        assert_untrusted_audience(
            &validate_id_token_claims(&three, Some("RS256"), &partly).unwrap_err(),
            &["unknown-api-7q"],
        );
    }

    // IDT-012: listing the additional audience as trusted accepts the token.
    #[test]
    fn accepts_trusted_additional_audience() {
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(vec!["other-client-9x".to_string()])
            .build();
        let c = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "s6BhdRkqt3"}),
        );
        validate_id_token_claims(&c, Some("RS256"), &opts).expect("trusted extra aud validates");
    }

    // IDT-012: an empty trusted list adds nothing — it cannot switch the check
    // off.
    #[test]
    fn empty_trusted_list_still_rejects() {
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(Vec::<String>::new())
            .build();
        let c = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "s6BhdRkqt3"}),
        );
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &opts).unwrap_err(),
            &["other-client-9x"],
        );
    }

    // With no client_id and no trusted list the trusted set is empty, so any
    // aud value is untrusted (fail closed).
    #[test]
    fn no_client_id_and_no_trusted_list_fails_closed() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &IdTokenValidationOptions::new())
                .unwrap_err(),
            &["s6BhdRkqt3"],
        );
    }

    // IDT-012: a single audience equal to the client_id is unaffected, with or
    // without a trusted list.
    #[test]
    fn single_audience_unchanged_by_trusted_list() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        let plain = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        validate_id_token_claims(&c, Some("RS256"), &plain).expect("single aud validates");
        let with_list = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .build();
        validate_id_token_claims(&c, Some("RS256"), &with_list)
            .expect("single aud validates with a trusted list");
    }

    /// The [`IdentityError::AudienceMismatch`] a token whose `aud` lacks the
    /// `s6BhdRkqt3` client id is rejected with.
    fn client_id_not_in_aud(actual: &[&str]) -> IdentityError {
        IdentityError::AudienceMismatch {
            expected: "s6BhdRkqt3".into(),
            actual: actual.iter().map(|aud| (*aud).to_string()).collect(),
        }
    }

    // IDT-015 (#1166): §3.1.3.7 step 3 — the ID Token MUST list the client as
    // an audience. Trusted additional audiences never stand in for the
    // `client_id`, whether `aud` is a string or an array.
    #[test]
    fn rejects_trusted_foreign_audience_without_client_id() {
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x", "api-7q"])
            .build();
        for (aud, want) in [
            (json!(["other-client-9x"]), vec!["other-client-9x"]),
            (json!("other-client-9x"), vec!["other-client-9x"]),
            (
                json!(["other-client-9x", "api-7q"]),
                vec!["other-client-9x", "api-7q"],
            ),
        ] {
            let c = claims(json!({"sub": "u", "aud": aud}));
            assert_id_token_reject(
                &validate_id_token_claims(&c, Some("RS256"), &opts).unwrap_err(),
                &client_id_not_in_aud(&want),
            );
        }
    }

    // IDT-015 ordering: the untrusted-audience rule runs first, so a token
    // failing both reports the untrusted values (keeps IDT-012's verdicts).
    #[test]
    fn untrusted_audience_checked_before_client_id_membership() {
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .build();
        let c = claims(json!({"sub": "u", "aud": ["other-client-9x", "unknown-api-7q"]}));
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &opts).unwrap_err(),
            &["unknown-api-7q"],
        );
    }

    // Without a `client_id` there is no membership rule to apply: a token
    // whose audiences are all trusted passes the profile (the end-to-end
    // `validate_id_token` refuses to run without a client id).
    #[test]
    fn trusted_audiences_alone_accept_without_client_id() {
        let opts = IdTokenValidationOptions::builder()
            .trusted_audiences(["other-client-9x"])
            .build();
        let c = claims(json!({"sub": "u", "aud": ["other-client-9x"]}));
        validate_id_token_claims(&c, Some("RS256"), &opts)
            .expect("all audiences trusted, no client_id to require");
    }

    const E2E_ISSUER: &str = "https://op.example.com";

    /// Signs `claims` with the shared RS256 fixture key (`kid=test-key-1`).
    fn mint_fixture(claims: &Value) -> String {
        let key = jsonwebtoken::EncodingKey::from_rsa_der(
            &std::fs::read("../spec/test-fixtures/validation/signing-key.pkcs1.der")
                .expect("read signing key fixture"),
        );
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key-1".into());
        jsonwebtoken::encode(&header, claims, &key).expect("sign token")
    }

    /// Serves the shared JWKS fixture at `/jwks`; returns the server and URI.
    async fn serve_fixture_jwks() -> (wiremock::MockServer, String) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let jwks: Value = serde_json::from_slice(
            &std::fs::read("../spec/test-fixtures/validation/jwks.json")
                .expect("read jwks fixture"),
        )
        .expect("parse jwks fixture");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        let uri = format!("{}/jwks", server.uri());
        (server, uri)
    }

    // #1166 end to end: with the profile `client_id` set and no base audience,
    // a correctly signed token whose only (trusted) audience is another client
    // is rejected — the profile no longer relies on the base audience check.
    #[tokio::test]
    async fn validate_id_token_requires_client_id_in_aud() {
        let (_server, uri) = serve_fixture_jwks().await;
        let jwks = JwksClient::builder().allow_http(true).build();
        let now = super::super::now_unix();
        let base = ValidationOptions::builder().issuer(E2E_ISSUER).build();
        let profile = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .build();

        let foreign = mint_fixture(&json!({
            "iss": E2E_ISSUER, "sub": "u", "aud": ["other-client-9x"],
            "iat": now - 5, "exp": now + 3600,
        }));
        let err = validate_id_token(&foreign, &jwks, &uri, &base, &profile)
            .await
            .unwrap_err();
        assert_id_token_reject(&err, &client_id_not_in_aud(&["other-client-9x"]));

        let own = mint_fixture(&json!({
            "iss": E2E_ISSUER, "sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"],
            "iat": now - 5, "exp": now + 3600,
        }));
        let claims = validate_id_token(&own, &jwks, &uri, &base, &profile)
            .await
            .expect("client_id listed among trusted audiences validates");
        assert_eq!(claims.subject.as_deref(), Some("u"));
    }

    // #1166: `validate_id_token` needs a client id to bind the token to — from
    // the profile or, by default, the base audience. With neither it fails as
    // a configuration error before any JWKS fetch or token parse.
    #[tokio::test]
    async fn validate_id_token_without_client_id_is_config_error() {
        let base = ValidationOptions::builder().issuer(E2E_ISSUER).build();
        let profile = IdTokenValidationOptions::builder()
            .trusted_audiences(["other-client-9x"])
            .build();
        let err = validate_id_token(
            "not-a-jwt",
            &JwksClient::new(),
            "http://127.0.0.1:9/jwks",
            &base,
            &profile,
        )
        .await
        .unwrap_err();
        assert_eq!(err, IdentityError::IdTokenClientIdRequired);
    }

    // #1166: an empty client id — from the profile or the base audience — is
    // unset, so a token with `aud: ["", <trusted-foreign>]` cannot pass by
    // matching the empty string.
    #[tokio::test]
    async fn validate_id_token_empty_client_id_is_unset() {
        let (_server, uri) = serve_fixture_jwks().await;
        let jwks = JwksClient::builder().allow_http(true).build();
        let now = super::super::now_unix();
        let token = mint_fixture(&json!({
            "iss": E2E_ISSUER, "sub": "u", "aud": ["", "other-client-9x"],
            "iat": now - 5, "exp": now + 3600,
        }));
        let trusted = || IdTokenValidationOptions::builder().trusted_audiences(["other-client-9x"]);
        let issuer = || ValidationOptions::builder().issuer(E2E_ISSUER);

        for (base, profile) in [
            (issuer().build(), trusted().client_id("").build()),
            (issuer().audience("").build(), trusted().build()),
        ] {
            let err = validate_id_token(&token, &jwks, &uri, &base, &profile)
                .await
                .unwrap_err();
            assert_eq!(err, IdentityError::IdTokenClientIdRequired);
        }

        // The pure claims check treats `client_id("")` as unset too, so the
        // empty `aud` value is untrusted.
        let c = claims(json!({"sub": "u", "aud": ["", "other-client-9x"]}));
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &trusted().client_id("").build())
                .unwrap_err(),
            &[""],
        );
    }

    // IDT-012 ordering: step 3 runs before the azp rules, so a multi-aud token
    // with no azp and an untrusted audience reports the untrusted audience.
    #[test]
    fn untrusted_audience_checked_before_azp() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .validate_azp(true)
            .build();
        let c = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"]}));
        assert_untrusted_audience(
            &validate_id_token_claims(&c, Some("RS256"), &cid).unwrap_err(),
            &["other-client-9x"],
        );
    }

    // IDT-003: by default azp is ignored, so multiple audiences need no azp and
    // a foreign azp is accepted. The second audience is trusted so step 3
    // passes and only the azp rules are in play.
    #[test]
    fn ignores_azp_by_default() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .build();

        let no_azp = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"]}));
        validate_id_token_claims(&no_azp, Some("RS256"), &cid)
            .expect("multi-aud without azp validates by default");

        let wrong_azp = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "other-client-9x"}),
        );
        validate_id_token_claims(&wrong_azp, Some("RS256"), &cid)
            .expect("multi-aud with a foreign azp validates by default");

        // Google's Android-to-backend flow: aud is this client, azp the
        // presenting mobile client.
        let cross_client =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "android-client"}));
        validate_id_token_claims(&cross_client, Some("RS256"), &cid)
            .expect("cross-client azp validates by default");

        let explicitly_off = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .validate_azp(false)
            .build();
        validate_id_token_claims(&cross_client, Some("RS256"), &explicitly_off)
            .expect("cross-client azp validates with azp validation off");
    }

    // IDT-003 with `validate_azp(true)`: multiple audiences require an azp that
    // identifies this client.
    #[test]
    fn enforces_azp_for_multiple_audiences() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .validate_azp(true)
            .build();

        let single_list = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3"]}));
        validate_id_token_claims(&single_list, Some("RS256"), &cid)
            .expect("single-element aud list needs no azp");

        let no_azp = claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"]}));
        assert_id_token_reject(
            &validate_id_token_claims(&no_azp, Some("RS256"), &cid).unwrap_err(),
            &missing("azp"),
        );

        let wrong_azp = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "other-client-9x"}),
        );
        assert_id_token_reject(
            &validate_id_token_claims(&wrong_azp, Some("RS256"), &cid).unwrap_err(),
            &azp_mismatch("other-client-9x"),
        );

        let right_azp = claims(
            json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": "s6BhdRkqt3"}),
        );
        validate_id_token_claims(&right_azp, Some("RS256"), &cid)
            .expect("multi-aud with matching azp validates");
    }

    // With `validate_azp(true)`, an empty-string `azp` must behave exactly like
    // the Python oracle's `not azp` / `azp is not None` truthiness (F-1
    // parity), NOT like Rust's former `azp.is_none()`:
    //   * multi-aud + azp=""            -> azp_required_multi_aud (was fail-open
    //     accept when no client_id was configured);
    //   * multi-aud + azp="" + client_id -> still azp_required_multi_aud, since
    //     the required-multi-aud check precedes the mismatch check;
    //   * single-aud + azp="" + client_id -> azp_mismatch (the oracle's mismatch
    //     guard is `azp is not None`, so a present empty string is compared);
    //   * single-aud + azp="" + no client_id -> accept (no client_id to compare).
    // Every audience is listed as trusted so step 3 passes and the azp rules
    // are what is exercised.
    #[test]
    fn empty_string_azp_matches_oracle_truthiness() {
        // multi-aud + azp="" with a client_id: the required-multi-aud check
        // fires first (matching the oracle), not the mismatch check. Without a
        // client_id the azp rules are a configuration error (IDT-014).
        let multi_empty =
            claims(json!({"sub": "u", "aud": ["s6BhdRkqt3", "other-client-9x"], "azp": ""}));
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .trusted_audiences(["other-client-9x"])
            .validate_azp(true)
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&multi_empty, Some("RS256"), &cid).unwrap_err(),
            &missing("azp"),
        );

        // single-aud + azp="" WITH a client_id: the oracle's `azp is not None`
        // guard compares the empty string and rejects as a mismatch.
        let single_empty_cid = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": ""}));
        assert_id_token_reject(
            &validate_id_token_claims(&single_empty_cid, Some("RS256"), &cid).unwrap_err(),
            &azp_mismatch(""),
        );
    }

    // IDT-004 with `validate_azp(true)`: a present azp is validated even for a
    // single audience.
    #[test]
    fn validates_present_azp_for_single_audience() {
        let cid = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .validate_azp(true)
            .build();
        let ok = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "s6BhdRkqt3"}));
        validate_id_token_claims(&ok, Some("RS256"), &cid).expect("matching azp validates");

        let bad = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "impostor-client"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &cid).unwrap_err(),
            &azp_mismatch("impostor-client"),
        );
    }

    // IDT-014 (#930): `validate_azp(true)` without a `client_id` is a
    // configuration error, raised before any claim is read — whether or not
    // the token carries an `azp`, and even when `sub` is missing.
    #[test]
    fn azp_validation_without_client_id_is_config_error() {
        let opts = IdTokenValidationOptions::builder()
            .trusted_audiences(["s6BhdRkqt3"])
            .validate_azp(true)
            .build();
        for value in [
            json!({"sub": "u", "aud": "s6BhdRkqt3", "azp": "android-client"}),
            json!({"sub": "u", "aud": "s6BhdRkqt3"}),
            json!({"aud": "s6BhdRkqt3"}),
            json!({}),
        ] {
            let err =
                validate_id_token_claims(&claims(value.clone()), Some("RS256"), &opts).unwrap_err();
            assert!(
                matches!(err, IdentityError::IdTokenAzpRequiresClientId),
                "{value}: expected IdTokenAzpRequiresClientId, got {err:?}"
            );
        }
    }

    // The end-to-end entry point reports the configuration error before any
    // JWKS fetch or token parse: neither the malformed token nor the
    // unreachable JWKS URI is touched.
    #[tokio::test]
    async fn validate_id_token_rejects_azp_without_client_id_before_fetch() {
        let base = ValidationOptions::builder()
            .issuer("https://op.example.com")
            .build();
        let profile = IdTokenValidationOptions::builder()
            .validate_azp(true)
            .build();
        let err = validate_id_token(
            "not-a-jwt",
            &JwksClient::new(),
            "http://127.0.0.1:9/jwks",
            &base,
            &profile,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, IdentityError::IdTokenAzpRequiresClientId),
            "expected IdTokenAzpRequiresClientId, got {err:?}"
        );
    }

    // IDT-005: the nonce binding requires a present, matching nonce.
    #[test]
    fn enforces_nonce_binding() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "nonce": "n-0S6_WzA2Mj"}));
        let matching = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .client_id("s6BhdRkqt3")
            .nonce("n-0S6_WzA2Mj")
            .build();
        validate_id_token_claims(&c, Some("RS256"), &matching).expect("matching nonce validates");

        let mismatch = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .nonce("a-different-nonce")
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&c, Some("RS256"), &mismatch).unwrap_err(),
            &IdentityError::NonceMismatch,
        );

        let absent = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &matching).unwrap_err(),
            &IdentityError::NonceMismatch,
        );
    }

    // IDT-006: auth_time must be present and within max_age (+ leeway).
    #[test]
    fn enforces_auth_time_freshness() {
        let within = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_999_900}));
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .max_age(3600)
            .now(1_700_000_000)
            .build();
        validate_id_token_claims(&within, Some("RS256"), &opts).expect("fresh auth_time validates");

        let leeway_case =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_996_390}));
        let with_leeway = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .max_age(3600)
            .leeway(Duration::from_secs(60))
            .now(1_700_000_000)
            .build();
        validate_id_token_claims(&leeway_case, Some("RS256"), &with_leeway)
            .expect("just-past max_age but within leeway validates");

        let stale = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_992_800}));
        assert_id_token_reject(
            &validate_id_token_claims(&stale, Some("RS256"), &opts).unwrap_err(),
            &IdentityError::MaxAgeExceeded {
                auth_time: 1_699_992_800,
                max_age: 3600,
                now: 1_700_000_000,
            },
        );

        let no_auth_time = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&no_auth_time, Some("RS256"), &opts).unwrap_err(),
            &missing("auth_time"),
        );
    }

    // IDT-007: at_hash binds to the access token under RS256 (SHA-256), using
    // the real OIDC §3.3.2.11 left-half construction.
    #[test]
    fn enforces_at_hash_rs256() {
        let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU";
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token(access_token)
            .build();

        let good =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));
        validate_id_token_claims(&good, Some("RS256"), &opts).expect("correct at_hash validates");

        let bad =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "DyAleB7ctGQvU9M3DbMBYQ"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &opts).unwrap_err(),
            &hash_mismatch("at_hash"),
        );

        // By default the access token is taken to have come back with the ID
        // Token (§3.2.2.10, §3.3.2.11), so at_hash is required.
        let absent = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &opts).unwrap_err(),
            &missing("at_hash"),
        );
        let issued_with = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token(access_token)
            .access_token_issued_with_id_token(true)
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &issued_with).unwrap_err(),
            &missing("at_hash"),
        );
        validate_id_token_claims(&good, Some("RS256"), &issued_with)
            .expect("required at_hash present and correct");
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &issued_with).unwrap_err(),
            &hash_mismatch("at_hash"),
        );

        // A token-endpoint ID Token may omit at_hash (§3.1.3.6).
        let token_endpoint = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token(access_token)
            .access_token_issued_with_id_token(false)
            .build();
        validate_id_token_claims(&absent, Some("RS256"), &token_endpoint)
            .expect("absent at_hash accepted when not issued with the ID Token");

        // A present at_hash must match whatever its type.
        let null = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": null}));
        assert_id_token_reject(
            &validate_id_token_claims(&null, Some("RS256"), &token_endpoint).unwrap_err(),
            &hash_mismatch("at_hash"),
        );

        // With nothing to verify, an unmappable alg is never consulted.
        validate_id_token_claims(&absent, Some("UNKNOWN"), &token_endpoint)
            .expect("absent, unrequired at_hash skips the alg lookup");

        // No access_token supplied -> at_hash present but unchecked.
        let unchecked = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .build();
        validate_id_token_claims(&good, Some("RS256"), &unchecked)
            .expect("at_hash unchecked without an access token");
    }

    // IDT-008: the header alg selects the hash — an ES512 (SHA-512) at_hash
    // validates; an SHA-256-sized at_hash fails closed under ES512.
    #[test]
    fn at_hash_hash_is_selected_by_alg() {
        let es512 = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token("YmExYzZmZTgtZXM1MTItYWNjZXNzLXRva2VuLWV4YW1wbGU")
            .build();
        let good = claims(json!({
            "sub": "u", "aud": "s6BhdRkqt3",
            "at_hash": "2azZeYx02zZttjvAxgBshVhQxqEJ6Ku0oRgkegwI9Ww"
        }));
        validate_id_token_claims(&good, Some("ES512"), &es512).expect("ES512 at_hash validates");

        // An SHA-256-sized at_hash under an ES512 header must not validate.
        let sha256_sized = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU")
            .build();
        let mismatched =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));
        assert_id_token_reject(
            &validate_id_token_claims(&mismatched, Some("ES512"), &sha256_sized).unwrap_err(),
            &hash_mismatch("at_hash"),
        );
    }

    // IDT-009 / IDT-010: c_hash binds to the authorization code under RS256 and
    // ES512. The RS256 case is the OIDC Core §3.3.2.11 worked example.
    #[test]
    fn enforces_c_hash() {
        let rs = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .build();
        let good =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "LDktKdoQak3Pk0cnXxCltA"}));
        validate_id_token_claims(&good, Some("RS256"), &rs).expect("RS256 c_hash validates");

        let bad =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "DyAleB7ctGQvU9M3DbMBYQ"}));
        assert_id_token_reject(
            &validate_id_token_claims(&bad, Some("RS256"), &rs).unwrap_err(),
            &hash_mismatch("c_hash"),
        );

        let es = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .code("Y29kZS1lczUxMi1hdXRob3JpemF0aW9uLWNvZGUtZXhhbXBsZQ")
            .build();
        let es_good = claims(json!({
            "sub": "u", "aud": "s6BhdRkqt3",
            "c_hash": "5ZRO6ySh8Y5x73OPd63wcyIunjtbSNZh9sQvDCegRDY"
        }));
        validate_id_token_claims(&es_good, Some("ES512"), &es).expect("ES512 c_hash validates");

        // c_hash presence is required by default, and only for a code issued
        // with the ID Token.
        let absent = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &rs).unwrap_err(),
            &missing("c_hash"),
        );
        let issued_with = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .code_issued_with_id_token(true)
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&absent, Some("RS256"), &issued_with).unwrap_err(),
            &missing("c_hash"),
        );
        validate_id_token_claims(&good, Some("RS256"), &issued_with)
            .expect("required c_hash present and correct");
        let not_issued_with = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .code_issued_with_id_token(false)
            .build();
        validate_id_token_claims(&absent, Some("RS256"), &not_issued_with)
            .expect("absent c_hash accepted when not issued with the ID Token");
    }

    // The issued-with-ID-Token switches only apply to a supplied value.
    #[test]
    fn issued_with_id_token_switches_need_their_value() {
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token_issued_with_id_token(true)
            .code_issued_with_id_token(true)
            .build();
        let bare = claims(json!({"sub": "u", "aud": "s6BhdRkqt3"}));
        validate_id_token_claims(&bare, Some("RS256"), &opts)
            .expect("switches without an access token or code are no-ops");
    }

    // IDT-011: an unknown or missing header alg on a hash check fails closed.
    #[test]
    fn hash_check_fails_closed_on_bad_alg() {
        let at = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .access_token("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU")
            .build();
        let with_at =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "at_hash": "T7VF8gELfbwjUBkK04GEhg"}));

        assert_id_token_reject(
            &validate_id_token_claims(&with_at, Some("UNKNOWN"), &at).unwrap_err(),
            &IdentityError::UnsupportedHashAlgorithm {
                alg: Some("UNKNOWN".into()),
            },
        );
        assert_id_token_reject(
            &validate_id_token_claims(&with_at, None, &at).unwrap_err(),
            &IdentityError::UnsupportedHashAlgorithm { alg: None },
        );

        let code = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .code("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
            .build();
        let with_code =
            claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "c_hash": "LDktKdoQak3Pk0cnXxCltA"}));
        assert_id_token_reject(
            &validate_id_token_claims(&with_code, Some("RS999"), &code).unwrap_err(),
            &IdentityError::UnsupportedHashAlgorithm {
                alg: Some("RS999".into()),
            },
        );
    }

    // A JSON-boolean auth_time is not a numeric date and fails the max_age check
    // closed rather than coercing.
    // Boundary: an auth_time exactly max_age old (no leeway) is still fresh;
    // only an older one exceeds max_age (§3.1.3.7 step 12).
    #[test]
    fn auth_time_exactly_max_age_old_is_fresh() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": 1_699_996_400}));
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .max_age(3600)
            .now(1_700_000_000)
            .build();
        validate_id_token_claims(&c, Some("RS256"), &opts).expect("auth_time == now - max_age");
    }

    #[test]
    fn boolean_auth_time_is_not_numeric() {
        let c = claims(json!({"sub": "u", "aud": "s6BhdRkqt3", "auth_time": true}));
        let opts = IdTokenValidationOptions::builder()
            .client_id("s6BhdRkqt3")
            .max_age(3600)
            .now(1_700_000_000)
            .build();
        assert_id_token_reject(
            &validate_id_token_claims(&c, Some("RS256"), &opts).unwrap_err(),
            &IdentityError::MalformedClaim {
                claim: "auth_time".into(),
                reason: "must be a numeric date".into(),
            },
        );
    }
}
