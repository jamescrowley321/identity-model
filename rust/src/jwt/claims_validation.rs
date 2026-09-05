//! Injectable, composable claims validation (issue #603; Rust port of the
//! Python foundation #623).
//!
//! After [`crate::validate_token`] verifies the signature, the algorithm
//! allowlist, and the registered/configured claims, it runs an optional
//! caller-supplied *claims validator* — the hook an application uses to enforce
//! its own rules on the decoded claims (tenant membership, custom scopes, role
//! checks, ...). This module makes that contract first-class and composable:
//!
//! * [`ClaimsValidator`] — the trait a validator implements (any
//!   `Fn(&Claims) -> Result<(), IdentityError>` can be wrapped into one with
//!   [`from_fn`]).
//! * [`ClaimsValidationError`] — a structured rejection carrying a `reason` and
//!   an optional offending `claim`. It converts into
//!   [`IdentityError::ClaimsValidation`] so a rejection integrates with the
//!   crate error type and surfaces *why* without parsing a message string.
//! * [`combine_claims_validators`] — compose several validators into one
//!   (all-must-pass or any-must-pass).
//! * Ready-made, portable validators: [`require_claims`], [`require_claim_value`],
//!   [`require_scopes`].
//!
//! The same interface shape is intended to be mirrored across the Python, Go,
//! and Rust libraries so a resource server can express the same policy in any
//! language. That parity is enforced by the shared conformance vectors in
//! `spec/test-fixtures/claims-validation/vectors.json` (driven by
//! `tests/claims_validation_conformance.rs`). For a runnable end-to-end
//! demonstration of composing these validators, see
//! `examples/combined_claims_validator.rs`
//! (`cargo run --example combined_claims_validator`).
//!
//! ```
//! use rs_identity_model::{ValidationOptions, require_scopes};
//!
//! # fn main() -> Result<(), rs_identity_model::IdentityError> {
//! let options = ValidationOptions::builder()
//!     .issuer("https://accounts.example.com")
//!     .claims_validator(require_scopes(["read"])?)
//!     .build();
//! # let _ = options;
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::fmt;

use serde_json::Value;

use crate::{IdentityError, Result};

use super::Claims;

/// A composable validator run over decoded [`Claims`] after the standard
/// signature, algorithm, and registered-claim checks pass.
///
/// Return `Ok(())` to accept. To reject *cleanly*, return a
/// [`ClaimsValidationError`] converted into [`IdentityError`] (e.g.
/// `Err(ClaimsValidationError::new("...").into())`, or use one of the
/// ready-made validators). Returning any *other* [`IdentityError`] variant is
/// treated as a hard failure that propagates immediately rather than an
/// aggregatable rejection — see [`combine_claims_validators`].
///
/// Any `Fn(&Claims) -> Result<(), IdentityError> + Send + Sync` can be turned
/// into a `ClaimsValidator` with [`from_fn`].
pub trait ClaimsValidator: Send + Sync {
    /// Validates the decoded claims, returning `Ok(())` to accept.
    fn validate(&self, claims: &Claims) -> Result<()>;
}

/// A type-erased, heap-allocated [`ClaimsValidator`] — the boxed-closure form of
/// the trait. Produced by [`boxed`] and consumed by [`combine_claims_validators`].
pub type BoxedClaimsValidator = Box<dyn ClaimsValidator>;

/// A structured claims-validation rejection: a human-readable `reason` and,
/// when the validator identified one, the offending `claim` name.
///
/// Converts into [`IdentityError::ClaimsValidation`] via `From`, so a validator
/// rejects with `Err(err.into())` and the structured reason survives to the
/// caller. This is the Rust analogue of the Python `ClaimsValidationError`
/// (a `TokenValidationException` subclass).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimsValidationError {
    /// Why the claims were rejected.
    pub reason: String,
    /// The offending claim name, when the validator identified one.
    pub claim: Option<String>,
}

impl ClaimsValidationError {
    /// Builds a rejection with a `reason` and no specific claim.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            claim: None,
        }
    }

    /// Builds a rejection naming the offending `claim`.
    pub fn for_claim(reason: impl Into<String>, claim: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            claim: Some(claim.into()),
        }
    }

    /// Attaches (or replaces) the offending claim name.
    #[must_use]
    pub fn with_claim(mut self, claim: impl Into<String>) -> Self {
        self.claim = Some(claim.into());
        self
    }
}

impl fmt::Display for ClaimsValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.claim {
            Some(claim) => write!(f, "{} (claim {claim:?})", self.reason),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for ClaimsValidationError {}

impl From<ClaimsValidationError> for IdentityError {
    fn from(err: ClaimsValidationError) -> Self {
        IdentityError::ClaimsValidation {
            reason: err.reason,
            claim: err.claim,
        }
    }
}

/// Wraps a closure into a [`ClaimsValidator`]. Internal; the public entry points
/// are [`from_fn`] and the ready-made `require_*` validators.
struct FnClaimsValidator<F>(F);

impl<F> ClaimsValidator for FnClaimsValidator<F>
where
    F: Fn(&Claims) -> Result<()> + Send + Sync,
{
    fn validate(&self, claims: &Claims) -> Result<()> {
        (self.0)(claims)
    }
}

/// Adapts a plain closure into a [`ClaimsValidator`], the boxed-closure form of
/// the trait.
///
/// ```
/// use rs_identity_model::{from_fn, ClaimsValidationError, IdentityError};
///
/// let tenant_bound = from_fn(|claims| -> Result<(), IdentityError> {
///     if claims.has("tid") {
///         Ok(())
///     } else {
///         Err(ClaimsValidationError::for_claim("no tenant", "tid").into())
///     }
/// });
/// # let _: &dyn rs_identity_model::ClaimsValidator = &tenant_bound;
/// ```
pub fn from_fn<F>(validator: F) -> impl ClaimsValidator
where
    F: Fn(&Claims) -> Result<()> + Send + Sync + 'static,
{
    FnClaimsValidator(validator)
}

/// Boxes any [`ClaimsValidator`] into a [`BoxedClaimsValidator`] so validators
/// of different concrete types can share a collection (e.g. the argument to
/// [`combine_claims_validators`]).
pub fn boxed<V>(validator: V) -> BoxedClaimsValidator
where
    V: ClaimsValidator + 'static,
{
    Box::new(validator)
}

/// How [`combine_claims_validators`] combines its members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineMode {
    /// Every member must accept; the combined validator fails fast on the first
    /// rejection (or propagates the first non-`ClaimsValidation` error).
    All,
    /// At least one member must accept; the combined validator rejects only if
    /// *all* members reject, aggregating their reasons.
    Any,
}

/// A [`ClaimsValidator`] composed from several members via
/// [`combine_claims_validators`].
pub struct CombinedValidator {
    members: Vec<BoxedClaimsValidator>,
    mode: CombineMode,
}

impl ClaimsValidator for CombinedValidator {
    fn validate(&self, claims: &Claims) -> Result<()> {
        match self.mode {
            CombineMode::All => {
                // Fail fast: the first member to reject (or otherwise error)
                // determines the outcome.
                for member in &self.members {
                    member.validate(claims)?;
                }
                Ok(())
            }
            CombineMode::Any => {
                let mut reasons: Vec<String> = Vec::with_capacity(self.members.len());
                for member in &self.members {
                    match member.validate(claims) {
                        Ok(()) => return Ok(()),
                        // Only a clean claims rejection is aggregated and the
                        // next member tried. Any other error (Http,
                        // Configuration, KeyNotFound, ...) is a hard failure and
                        // propagates immediately — the load-bearing invariant
                        // mirrored from the Python `any` mode.
                        Err(IdentityError::ClaimsValidation { reason, .. }) => reasons.push(reason),
                        Err(other) => return Err(other),
                    }
                }
                Err(ClaimsValidationError::new(format!(
                    "no validator accepted the claims: {}",
                    reasons.join("; ")
                ))
                .into())
            }
        }
    }
}

/// Composes `validators` into a single [`CombinedValidator`].
///
/// * [`CombineMode::All`] — every member must accept; the combined validator
///   rejects with the first member's error (fail fast). An empty `All` set is a
///   no-op that accepts everything (harmless).
/// * [`CombineMode::Any`] — at least one member must accept; the combined
///   validator rejects with a [`ClaimsValidationError`] aggregating every
///   member's reason only if all of them reject. In `Any` mode only a clean
///   [`IdentityError::ClaimsValidation`] rejection is aggregated; any other
///   error propagates immediately.
///
/// # Errors
///
/// Returns [`IdentityError::Configuration`] if [`CombineMode::Any`] is given no
/// validators — an empty any-of set can never be satisfied, so it would reject
/// every token. (The Python API also guards an invalid `require` string; here
/// [`CombineMode`] makes that state unrepresentable.)
pub fn combine_claims_validators(
    validators: impl IntoIterator<Item = BoxedClaimsValidator>,
    mode: CombineMode,
) -> Result<CombinedValidator> {
    let members: Vec<BoxedClaimsValidator> = validators.into_iter().collect();
    if mode == CombineMode::Any && members.is_empty() {
        return Err(IdentityError::Configuration(
            "combine_claims_validators(Any) needs at least one validator; an empty any-of set \
             rejects every token"
                .to_string(),
        ));
    }
    Ok(CombinedValidator { members, mode })
}

/// Returns a validator that rejects unless every named claim is present with a
/// meaningful value.
///
/// A claim that is absent, JSON `null`, an empty string, or an empty
/// array/object is treated as missing — the same presence notion the built-in
/// [`crate::ValidationOptions`] `required_claims` (JWT-012) enforces, so the two
/// required-claim surfaces agree and a present-but-null `aud` cannot slip
/// through the typed-field reconstruction. This is marginally stricter than the
/// Python `require_claims` (which treats only `None`/absent as missing); the
/// difference — rejecting present-but-empty values — is fail-closed.
///
/// # Errors
///
/// Returns [`IdentityError::Configuration`] if no claim names are supplied.
pub fn require_claims<I, S>(names: I) -> Result<impl ClaimsValidator>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let names: Vec<String> = names.into_iter().map(Into::into).collect();
    if names.is_empty() {
        return Err(IdentityError::Configuration(
            "require_claims needs at least one claim name".to_string(),
        ));
    }
    Ok(FnClaimsValidator(move |claims: &Claims| {
        for name in &names {
            if is_missing(claims, name) {
                return Err(ClaimsValidationError::for_claim(
                    format!("required claim '{name}' is missing"),
                    name.as_str(),
                )
                .into());
            }
        }
        Ok(())
    }))
}

/// Returns a validator that rejects unless claim `name` is present *and* equals
/// `value`.
///
/// An absent claim always rejects — including when `value` is
/// [`Value::Null`], so `require_claim_value("x", Value::Null)` means "`x` must
/// be present and null", not "`x` may be missing" (the fail-open a plain
/// "get-or-default != value" would allow).
///
/// # Comparison semantics
///
/// The claim is compared against the decoded [`Claims`] representation, not the
/// raw token JSON. Two consequences, both **fail-closed** (a mismatch rejects,
/// never accepts):
///
/// * The `aud` claim is normalised to an array of strings, so
///   `require_claim_value("aud", "acme")` does **not** match a token carrying
///   `aud: "acme"`. To assert an audience, prefer the token-validation
///   `audience` check, or compare against the array form
///   (`require_claim_value("aud", serde_json::json!(["acme"]))`).
/// * Numeric equality is exact by JSON number type: an integer `1` in the token
///   is not equal to a float `1.0` passed here.
///
/// For the common case — string claims such as `role`, `tid`, or `iss` — this
/// is exactly the intended behaviour.
pub fn require_claim_value(
    name: impl Into<String>,
    value: impl Into<Value>,
) -> impl ClaimsValidator {
    let name = name.into();
    let expected = value.into();
    FnClaimsValidator(move |claims: &Claims| {
        let matches = claims.has(&name) && claim_value(claims, &name).as_ref() == Some(&expected);
        if matches {
            Ok(())
        } else {
            Err(ClaimsValidationError::for_claim(
                format!("claim '{name}' must equal {expected}"),
                name.as_str(),
            )
            .into())
        }
    })
}

/// Returns a validator that rejects unless the token grants every named scope.
///
/// Scopes are read from the OAuth 2.0 `scope` (space-delimited string) or `scp`
/// (array) claim. An absent or empty-string `scope` falls through to `scp`; a
/// malformed `scope` (any other JSON shape) yields no scopes and therefore
/// rejects (fail closed); non-string members of an array claim are ignored.
///
/// # Errors
///
/// Returns [`IdentityError::Configuration`] if no scopes are supplied.
pub fn require_scopes<I, S>(scopes: I) -> Result<impl ClaimsValidator>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let scopes: Vec<String> = scopes.into_iter().map(Into::into).collect();
    if scopes.is_empty() {
        return Err(IdentityError::Configuration(
            "require_scopes needs at least one scope".to_string(),
        ));
    }
    Ok(FnClaimsValidator(move |claims: &Claims| {
        let granted = granted_scopes(claims);
        let missing: Vec<&str> = scopes
            .iter()
            .filter(|scope| !granted.contains(scope.as_str()))
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(ClaimsValidationError::for_claim(
                format!("missing required scope(s): {}", missing.join(", ")),
                "scope",
            )
            .into())
        }
    }))
}

/// The JSON value of any top-level claim — modelled field or unmodelled `extra`
/// — as it appeared in the token, or `None` if the claim was absent. A claim
/// present as JSON `null` returns `Some(Value::Null)`.
///
/// [`Claims`] parses the registered claims into typed fields, so their raw JSON
/// is reconstructed here; every other claim is read straight from `extra`.
fn claim_value(claims: &Claims, name: &str) -> Option<Value> {
    if let Some(value) = claims.get(name) {
        return Some(value.clone());
    }
    match name {
        "iss" => claims.issuer.clone().map(Value::String),
        "sub" => claims.subject.clone().map(Value::String),
        "jti" => claims.id.clone().map(Value::String),
        "nonce" => claims.nonce.clone().map(Value::String),
        "azp" => claims.authorized_party.clone().map(Value::String),
        "exp" => claims.expiry.map(Value::from),
        "nbf" => claims.not_before.map(Value::from),
        "iat" => claims.issued_at.map(Value::from),
        "aud" if claims.has("aud") => Some(Value::Array(
            claims
                .audience
                .values()
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        )),
        _ => None,
    }
}

/// Whether `name` is missing for `require_claims`.
///
/// Routed through the crate's own presence logic ([`Claims::has_meaningful`],
/// the `meaningful` set the built-in `required_claims` uses) rather than the
/// lossy typed-field reconstruction in [`claim_value`]: a present-but-`null`
/// `aud` reconstructs to an empty array, which would otherwise read as present.
/// Delegating keeps the injectable and built-in required-claim checks in
/// agreement and fails closed on `null`/empty (marginally stricter than the
/// Python `_missing`, which treats only `None`/absent as missing).
fn is_missing(claims: &Claims, name: &str) -> bool {
    !claims.has_meaningful(name)
}

/// The scopes the token grants, from `scope` (space-delimited string) or `scp`
/// (array). Any other shape yields no granted scopes rather than erroring — a
/// malformed scope claim must fail closed, not crash validation.
fn granted_scopes(claims: &Claims) -> HashSet<String> {
    let mut raw = claims.get("scope");
    // An absent OR empty-string `scope` falls through to `scp`: some IdPs send
    // `{"scope": "", "scp": [...]}` and an empty string must not shadow the
    // populated array. A malformed (non-string) `scope` does NOT fall through —
    // it yields no scopes and rejects (fail closed).
    let fall_through = match raw {
        None => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    };
    if fall_through {
        raw = claims.get("scp");
    }
    match raw {
        Some(Value::String(s)) => s.split_whitespace().map(str::to_owned).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => HashSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a claim set from a JSON object literal.
    fn claims(value: Value) -> Claims {
        Claims::from_value(value).expect("valid claims object")
    }

    /// Runs a validator and returns the [`IdentityError`] it rejected with.
    fn reject(validator: &dyn ClaimsValidator, value: Value) -> IdentityError {
        validator
            .validate(&claims(value))
            .expect_err("expected a rejection")
    }

    /// Runs a validator and returns the structured claims rejection, asserting
    /// it rejected via [`IdentityError::ClaimsValidation`].
    fn reject_claims(validator: &dyn ClaimsValidator, value: Value) -> (String, Option<String>) {
        match reject(validator, value) {
            IdentityError::ClaimsValidation { reason, claim } => (reason, claim),
            other => panic!("expected ClaimsValidation, got {other:?}"),
        }
    }

    // --- ClaimsValidationError -------------------------------------------------

    #[test]
    fn claims_validation_error_converts_into_identity_error() {
        let err: IdentityError = ClaimsValidationError::for_claim("nope", "tenant").into();
        match err {
            IdentityError::ClaimsValidation { reason, claim } => {
                assert_eq!(reason, "nope");
                assert_eq!(claim.as_deref(), Some("tenant"));
            }
            other => panic!("expected ClaimsValidation, got {other:?}"),
        }
    }

    #[test]
    fn claims_validation_error_without_claim() {
        let err = ClaimsValidationError::new("nope");
        assert!(err.claim.is_none());
        assert_eq!(err.to_string(), "nope");
    }

    // --- require_claims --------------------------------------------------------

    #[test]
    fn require_claims_accepts_when_all_present() {
        let v = require_claims(["sub", "tid"]).expect("names supplied");
        v.validate(&claims(json!({ "sub": "u1", "tid": "t1" })))
            .expect("all present passes");
    }

    #[test]
    fn require_claims_rejects_missing_with_claim_name() {
        let v = require_claims(["sub", "tid"]).expect("names supplied");
        let (_, claim) = reject_claims(&v, json!({ "sub": "u1" }));
        assert_eq!(claim.as_deref(), Some("tid"));
    }

    #[test]
    fn require_claims_treats_null_as_missing() {
        let v = require_claims(["tid"]).expect("names supplied");
        let (_, claim) = reject_claims(&v, json!({ "tid": null }));
        assert_eq!(claim.as_deref(), Some("tid"));
    }

    #[test]
    fn require_claims_treats_null_aud_as_missing() {
        // Regression: a present-but-null `aud` reconstructs to an empty audience
        // via the typed field, so it must be treated as missing (fail closed)
        // rather than accepted — matching the built-in `required_claims`.
        let v = require_claims(["aud"]).expect("names supplied");
        let (_, claim) = reject_claims(&v, json!({ "aud": null }));
        assert_eq!(claim.as_deref(), Some("aud"));
    }

    #[test]
    fn require_claims_treats_empty_value_as_missing() {
        // Consistent with the built-in required_claims (JWT-012): a present-but-
        // empty value does not satisfy a required-claim check.
        let v = require_claims(["x"]).expect("names supplied");
        reject(&v, json!({ "x": "" }));
        reject(&v, json!({ "x": [] }));
        reject(&v, json!({ "x": {} }));
    }

    #[test]
    fn require_claims_needs_a_name() {
        let err = match require_claims(Vec::<String>::new()) {
            Ok(_) => panic!("empty names must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    // --- require_claim_value ---------------------------------------------------

    #[test]
    fn require_claim_value_accepts_and_rejects() {
        let v = require_claim_value("role", "admin");
        v.validate(&claims(json!({ "role": "admin" })))
            .expect("matching value passes");
        let (_, claim) = reject_claims(&v, json!({ "role": "user" }));
        assert_eq!(claim.as_deref(), Some("role"));
    }

    #[test]
    fn require_claim_value_rejects_absent_claim() {
        let v = require_claim_value("role", "admin");
        let (_, claim) = reject_claims(&v, json!({}));
        assert_eq!(claim.as_deref(), Some("role"));
    }

    #[test]
    fn require_claim_value_null_requires_present_null_not_absent() {
        // "must equal null" means present-and-null — an absent claim must NOT
        // pass (the fail-open a plain get-or-default != value would allow).
        let v = require_claim_value("x", Value::Null);
        v.validate(&claims(json!({ "x": null })))
            .expect("present null matches expected null");
        reject(&v, json!({}));
    }

    // --- require_scopes --------------------------------------------------------

    #[test]
    fn require_scopes_from_space_delimited_string() {
        let v = require_scopes(["read"]).expect("scopes supplied");
        v.validate(&claims(json!({ "scope": "read write" })))
            .expect("space-delimited scope passes");
    }

    #[test]
    fn require_scopes_from_scp_list() {
        let v = require_scopes(["read", "write"]).expect("scopes supplied");
        v.validate(&claims(json!({ "scp": ["read", "write", "admin"] })))
            .expect("scp array passes");
    }

    #[test]
    fn require_scopes_rejects_missing_and_names_only_them() {
        let v = require_scopes(["read", "delete"]).expect("scopes supplied");
        let (reason, claim) = reject_claims(&v, json!({ "scope": "read" }));
        assert_eq!(claim.as_deref(), Some("scope"));
        assert!(reason.contains("delete"), "{reason}");
        assert!(
            !reason.contains("read"),
            "only the missing scope is named: {reason}"
        );
    }

    #[test]
    fn require_scopes_malformed_claim_fails_closed() {
        // A non-string, non-array scope yields no granted scopes -> reject,
        // never crash.
        let v = require_scopes(["read"]).expect("scopes supplied");
        for bad in [json!({ "unexpected": "shape" }), json!(123), json!(null)] {
            reject(&v, json!({ "scope": bad }));
        }
    }

    #[test]
    fn require_scopes_list_drops_non_string_members_without_crashing() {
        let read = require_scopes(["read"]).expect("scopes supplied");
        read.validate(&claims(json!({ "scope": ["read", 7, null] })))
            .expect("valid string scope still counts");
        let admin = require_scopes(["admin"]).expect("scopes supplied");
        reject(&admin, json!({ "scope": ["read", 7, null] }));
    }

    #[test]
    fn require_scopes_empty_scope_falls_through_to_scp() {
        let v = require_scopes(["read"]).expect("scopes supplied");
        v.validate(&claims(json!({ "scope": "", "scp": ["read", "write"] })))
            .expect("empty scope must not shadow populated scp");
    }

    #[test]
    fn require_scopes_nonempty_scope_takes_precedence_over_scp() {
        let v = require_scopes(["write"]).expect("scopes supplied");
        // A present, non-empty `scope` wins; `scp` is not consulted.
        reject(&v, json!({ "scope": "read", "scp": ["write"] }));
    }

    #[test]
    fn require_scopes_needs_a_scope() {
        let err = match require_scopes(Vec::<String>::new()) {
            Ok(_) => panic!("empty scopes must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    // --- combine_claims_validators ---------------------------------------------

    #[test]
    fn combine_all_passes_when_every_validator_passes() {
        let combined = combine_claims_validators(
            [
                boxed(require_claims(["sub"]).unwrap()),
                boxed(require_scopes(["read"]).unwrap()),
            ],
            CombineMode::All,
        )
        .expect("non-empty all");
        combined
            .validate(&claims(json!({ "sub": "u1", "scope": "read" })))
            .expect("both pass");
    }

    #[test]
    fn combine_all_raises_first_failure() {
        let combined = combine_claims_validators(
            [
                boxed(require_claims(["sub"]).unwrap()),
                boxed(require_claim_value("role", "admin")),
            ],
            CombineMode::All,
        )
        .expect("non-empty all");
        let (_, claim) = reject_claims(&combined, json!({ "sub": "u1", "role": "user" }));
        assert_eq!(claim.as_deref(), Some("role"));
    }

    #[test]
    fn combine_any_passes_when_one_passes() {
        let combined = combine_claims_validators(
            [
                boxed(require_claim_value("role", "admin")),
                boxed(require_scopes(["read"]).unwrap()),
            ],
            CombineMode::Any,
        )
        .expect("non-empty any");
        // The second member accepts.
        combined
            .validate(&claims(json!({ "role": "user", "scope": "read" })))
            .expect("one passing member accepts");
    }

    #[test]
    fn combine_any_aggregates_reasons_when_all_reject() {
        let combined = combine_claims_validators(
            [
                boxed(require_claims(["a"]).unwrap()),
                boxed(require_claims(["b"]).unwrap()),
            ],
            CombineMode::Any,
        )
        .expect("non-empty any");
        let (reason, _) = reject_claims(&combined, json!({ "c": 1 }));
        assert!(reason.contains("'a'"), "{reason}");
        assert!(reason.contains("'b'"), "{reason}");
    }

    #[test]
    fn combine_any_empty_is_rejected_at_construction() {
        let err = match combine_claims_validators(Vec::new(), CombineMode::Any) {
            Ok(_) => panic!("empty any must be rejected at construction"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn combine_all_empty_is_a_noop() {
        let combined =
            combine_claims_validators(Vec::new(), CombineMode::All).expect("empty all is a no-op");
        combined
            .validate(&claims(json!({ "anything": true })))
            .expect("empty all accepts");
    }

    #[test]
    fn combine_all_propagates_non_claims_error() {
        // A non-ClaimsValidation error from a member is not swallowed as a
        // rejection — it propagates.
        let combined = combine_claims_validators(
            [boxed(from_fn(|_| {
                Err(IdentityError::Configuration("bug".to_string()))
            }))],
            CombineMode::All,
        )
        .expect("non-empty all");
        assert!(matches!(
            reject(&combined, json!({})),
            IdentityError::Configuration(_)
        ));
    }

    #[test]
    fn combine_any_propagates_non_claims_error() {
        // The load-bearing invariant: `Any` aggregates only ClaimsValidation
        // rejections, so a member's hard error is NOT recorded as a rejection
        // reason (which could flip the result to accept) — it propagates.
        let combined = combine_claims_validators(
            [
                boxed(from_fn(|_| {
                    Err(IdentityError::Configuration("bug".to_string()))
                })),
                boxed(require_claims(["sub"]).unwrap()),
            ],
            CombineMode::Any,
        )
        .expect("non-empty any");
        assert!(matches!(
            reject(&combined, json!({})),
            IdentityError::Configuration(_)
        ));
    }

    // --- nesting / trait plumbing ----------------------------------------------

    #[test]
    fn combined_validators_nest() {
        // A CombinedValidator is itself a ClaimsValidator, so it can be boxed
        // into another combination.
        let inner =
            combine_claims_validators([boxed(require_claims(["sub"]).unwrap())], CombineMode::All)
                .expect("inner all");
        let outer = combine_claims_validators(
            [boxed(inner), boxed(require_scopes(["read"]).unwrap())],
            CombineMode::All,
        )
        .expect("outer all");
        outer
            .validate(&claims(json!({ "sub": "u1", "scope": "read" })))
            .expect("nested combination passes");
    }
}
