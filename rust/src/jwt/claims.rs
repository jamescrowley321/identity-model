//! Typed JWT claim set and registered-claim validation (RFC 7519 §4).

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::{IdentityError, Result};

use super::options::ValidationOptions;

/// Beyond this magnitude (2^53 seconds) a JSON number can no longer hold an
/// integer second exactly, so a crafted far-future `exp` could wrap into a
/// garbage timestamp that defeats the expiry check. Real epoch timestamps are
/// many orders of magnitude inside this bound. Mirrors `go/pkg/jwt`
/// `maxNumericDate`.
const MAX_NUMERIC_DATE: i64 = 1 << 53;

/// The JWT `aud` claim, which may be a single string or an array of strings
/// (RFC 7519 §4.1.3). It always resolves to a list of audiences.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Audience(pub Vec<String>);

impl Audience {
    /// Parses an `aud` value that is either a JSON string or an array of
    /// strings. A JSON `null` yields an empty audience rather than a slice
    /// holding one empty string; a `null` array element is rejected (not a
    /// string per RFC 7519 §4.1.3).
    fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Null => Ok(Audience(Vec::new())),
            Value::String(s) => Ok(Audience(vec![s.clone()])),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::String(s) => out.push(s.clone()),
                        _ => {
                            return Err(IdentityError::Validation(
                                "claim \"aud\" invalid: array must contain only strings"
                                    .to_string(),
                            ));
                        }
                    }
                }
                Ok(Audience(out))
            }
            _ => Err(IdentityError::Validation(
                "claim \"aud\" invalid: must be a string or array of strings".to_string(),
            )),
        }
    }

    /// Reports whether the audience includes `s`.
    pub fn contains(&self, s: &str) -> bool {
        self.0.iter().any(|v| v == s)
    }

    /// Returns the audience values.
    pub fn values(&self) -> &[String] {
        &self.0
    }
}

/// A validated set of JWT claims (RFC 7519 §4).
///
/// The registered claims are exposed as fields; any additional claims are
/// preserved in [`Claims::extra`] and reachable through [`Claims::get`] /
/// [`Claims::get_str`]. Presence of a claim (regardless of value) is queryable
/// with [`Claims::has`].
#[derive(Clone, Debug)]
pub struct Claims {
    /// `iss` — the issuer (RFC 7519 §4.1.1).
    pub issuer: Option<String>,
    /// `sub` — the subject (RFC 7519 §4.1.2).
    pub subject: Option<String>,
    /// `aud` — the audience(s) (RFC 7519 §4.1.3).
    pub audience: Audience,
    /// `exp` — expiry, seconds since the Unix epoch (RFC 7519 §4.1.4).
    pub expiry: Option<i64>,
    /// `nbf` — not-before, seconds since the Unix epoch (RFC 7519 §4.1.5).
    pub not_before: Option<i64>,
    /// `iat` — issued-at, seconds since the Unix epoch (RFC 7519 §4.1.6).
    pub issued_at: Option<i64>,
    /// `jti` — the token identifier (RFC 7519 §4.1.7).
    pub id: Option<String>,
    /// `nonce` — the OIDC nonce (OIDC Core 1.0 §3.1.3.7).
    pub nonce: Option<String>,

    /// Claims not modelled above (e.g. `email`, `scope`, `groups`).
    pub extra: HashMap<String, Value>,

    /// Every top-level claim name present in the payload, so [`Claims::has`]
    /// can report presence for modelled and unmodelled claims alike.
    present: HashSet<String>,

    /// The subset of `present` whose value is meaningful — not JSON `null`, an
    /// empty string, or an empty array/object. `required_claims` enforcement
    /// consults this set so a claim carrying `null`/`""`/`[]`/`{}` does not
    /// silently satisfy a "required" check.
    meaningful: HashSet<String>,
}

/// The registered claim names decoded into named [`Claims`] fields; everything
/// else lands in [`Claims::extra`].
const MODELLED_CLAIMS: &[&str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "nonce"];

impl Claims {
    /// Builds a typed claim set from a decoded JWS payload object.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Deserialization`] when the payload is not a JSON object;
    /// [`IdentityError::Validation`] when a claim has the wrong JSON shape (e.g.
    /// a non-numeric `exp` or a malformed `aud`).
    pub(crate) fn from_value(value: Value) -> Result<Self> {
        let Value::Object(map) = value else {
            return Err(IdentityError::Deserialization(
                "JWT claims payload is not a JSON object".to_string(),
            ));
        };
        Self::from_map(map)
    }

    fn from_map(map: Map<String, Value>) -> Result<Self> {
        let present: HashSet<String> = map.keys().cloned().collect();
        let meaningful: HashSet<String> = map
            .iter()
            .filter(|(_, v)| is_meaningful_value(v))
            .map(|(k, _)| k.clone())
            .collect();

        let issuer = string_claim(&map, "iss")?;
        let subject = string_claim(&map, "sub")?;
        let audience = match map.get("aud") {
            Some(v) => Audience::from_value(v)?,
            None => Audience::default(),
        };
        let expiry = numeric_date_claim(&map, "exp")?;
        let not_before = numeric_date_claim(&map, "nbf")?;
        let issued_at = numeric_date_claim(&map, "iat")?;
        let id = string_claim(&map, "jti")?;
        let nonce = string_claim(&map, "nonce")?;

        let modelled: HashSet<&str> = MODELLED_CLAIMS.iter().copied().collect();
        let extra: HashMap<String, Value> = map
            .into_iter()
            .filter(|(k, _)| !modelled.contains(k.as_str()))
            .collect();

        Ok(Claims {
            issuer,
            subject,
            audience,
            expiry,
            not_before,
            issued_at,
            id,
            nonce,
            extra,
            present,
            meaningful,
        })
    }

    /// Reports whether the named claim was present in the token payload,
    /// regardless of whether it is modelled as a field or held in
    /// [`Claims::extra`].
    pub fn has(&self, claim: &str) -> bool {
        self.present.contains(claim)
    }

    /// Returns the raw JSON value of an unmodelled claim, if present.
    pub fn get(&self, claim: &str) -> Option<&Value> {
        self.extra.get(claim)
    }

    /// Returns the named unmodelled claim decoded as a string, if present and a
    /// JSON string.
    pub fn get_str(&self, claim: &str) -> Option<&str> {
        self.extra.get(claim).and_then(Value::as_str)
    }

    /// Enforces the registered and configured claim rules against `now_unix`
    /// (seconds since the Unix epoch).
    ///
    /// `iat` must always be present (JWT-013). `exp` must be present and
    /// unexpired by default (JWT-005), but its presence requirement can be
    /// relaxed with [`ValidationOptions`] `require_exp(false)` — a present `exp`
    /// is still checked for expiry. The remaining checks apply only when the
    /// matching option is configured.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Validation`] identifying the offending claim.
    pub(crate) fn validate(&self, opts: &ValidationOptions, now_unix: i64) -> Result<()> {
        let skew = i64::try_from(opts.clock_skew.as_secs()).unwrap_or(i64::MAX);

        // iat MUST be present (JWT-002/JWT-013). Required by this validator even
        // though RFC 7519 §4.1.6 marks it optional.
        if self.issued_at.is_none() {
            return Err(claim_err("iat", "required claim is missing"));
        }

        // exp is required by default and, when present, must not be expired
        // allowing for clock skew (JWT-005/JWT-011, AC-3/AC-6, RFC 7519 §4.1.4).
        match self.expiry {
            None if opts.require_exp => {
                return Err(claim_err("exp", "required claim is missing"));
            }
            None => {}
            Some(exp) => {
                if now_unix.saturating_sub(skew) >= exp {
                    // AC-6: surface the exp value (and the reference now) so the
                    // caller can see how far past expiry the token is.
                    return Err(claim_err(
                        "exp",
                        &format!("token expired at {exp} (now {now_unix}, skew {skew}s)"),
                    ));
                }
            }
        }

        // nbf is validated when present; with require_nbf it must also be
        // present (JWT-006, AC-3, RFC 7519 §4.1.5).
        match self.not_before {
            None if opts.require_nbf => {
                return Err(claim_err("nbf", "required claim is missing"));
            }
            None => {}
            Some(nbf) => {
                if now_unix.saturating_add(skew) < nbf {
                    return Err(claim_err("nbf", "token is not yet valid"));
                }
            }
        }

        // iss exact match when expected (JWT-007, RFC 7519 §4.1.1).
        if let Some(expected) = &opts.expected_issuer {
            let actual = self.issuer.as_deref().unwrap_or_default();
            if actual != expected {
                return Err(claim_err(
                    "iss",
                    &format!("expected {expected:?}, got {actual:?}"),
                ));
            }
        }

        // aud must contain the expected audience when expected (JWT-008,
        // AC-7, RFC 7519 §4.1.3).
        if let Some(expected) = &opts.expected_audience
            && !self.audience.contains(expected)
        {
            // AC-7: list both the expected value and the token's actual
            // audience(s) so the mismatch is diagnosable.
            return Err(claim_err(
                "aud",
                &format!(
                    "does not contain expected audience {expected:?} (token audiences: {:?})",
                    self.audience.values()
                ),
            ));
        }

        // nonce match when expected (JWT-004, OIDC Core 1.0 §3.1.3.7). An
        // expected nonce (even the empty string) requires the claim to be
        // present — an absent nonce must not satisfy the expectation.
        if let Some(expected) = &opts.expected_nonce {
            match &self.nonce {
                None => return Err(claim_err("nonce", "required nonce claim is missing")),
                Some(actual) if actual != expected => {
                    return Err(claim_err("nonce", "nonce does not match expected value"));
                }
                Some(_) => {}
            }
        }

        // Custom required claims must be present with a meaningful (non-null,
        // non-empty) value (JWT-012, RFC 7519 §4.1).
        for claim in &opts.required_claims {
            if !self.meaningful.contains(claim) {
                return Err(claim_err(claim, "required claim is missing or empty"));
            }
        }

        Ok(())
    }
}

/// Builds the standard claim-validation error, mirroring `go/pkg/jwt`
/// `ClaimValidationError` message shape.
fn claim_err(claim: &str, reason: &str) -> IdentityError {
    IdentityError::Validation(format!("claim {claim:?} invalid: {reason}"))
}

/// Extracts a string-valued registered claim, erroring on a wrong JSON type.
fn string_claim(map: &Map<String, Value>, name: &str) -> Result<Option<String>> {
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(claim_err(name, "must be a string")),
    }
}

/// Extracts a numeric-date registered claim (seconds since the epoch), erroring
/// on a wrong type or an out-of-range magnitude (RFC 7519 §2).
///
/// A JSON integer is read losslessly via [`Value::as_i64`] first, so a value
/// just above `2^53` is bounded on its exact magnitude rather than after an
/// f64 rounding step that could pull it back under the guard. Fractional
/// NumericDate values (RFC 7519 §2 permits them) fall back to the f64 path.
fn numeric_date_claim(map: &Map<String, Value>, name: &str) -> Result<Option<i64>> {
    let Some(value) = map.get(name) else {
        return Ok(None);
    };
    if let Some(secs) = value.as_i64() {
        if secs.unsigned_abs() > MAX_NUMERIC_DATE as u64 {
            return Err(claim_err(name, "numeric date is out of range"));
        }
        return Ok(Some(secs));
    }
    let Some(secs) = value.as_f64() else {
        return Err(claim_err(name, "must be a numeric date"));
    };
    if !secs.is_finite() || secs.abs() > MAX_NUMERIC_DATE as f64 {
        return Err(claim_err(name, "numeric date is out of range"));
    }
    Ok(Some(secs.trunc() as i64))
}

/// Reports whether a claim value is meaningful for a `required_claims` check —
/// i.e. not JSON `null`, an empty string, or an empty array/object. Numbers and
/// booleans are always meaningful.
fn is_meaningful_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const NOW: i64 = 1_700_000_000;

    /// Builds a claim set from a JSON object literal.
    fn claims(value: Value) -> Claims {
        Claims::from_value(value).expect("valid claims object")
    }

    // JWT-002: a token carrying iss/aud/exp/nbf/iat with the expected issuer and
    // audience passes all registered-claim checks.
    #[test]
    fn accepts_valid_registered_claims() {
        let c = claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "sub": "user-1",
            "aud": "test-client",
            "exp": NOW + 3600,
            "nbf": NOW - 10,
            "iat": NOW - 10,
        }));
        let opts = ValidationOptions::builder()
            .issuer("https://issuer.example.com")
            .audience("test-client")
            .build();
        c.validate(&opts, NOW).expect("valid token passes");
    }

    // JWT-013: a token without iat is rejected.
    #[test]
    fn rejects_missing_iat() {
        let c = claims(serde_json::json!({ "exp": NOW + 3600 }));
        let err = c
            .validate(&ValidationOptions::new(), NOW)
            .expect_err("missing iat rejected");
        assert!(err.to_string().contains("iat"), "{err}");
    }

    // JWT-005: a token whose exp is in the past beyond the skew is expired.
    #[test]
    fn rejects_expired() {
        let c = claims(serde_json::json!({ "exp": NOW - 3600, "iat": NOW - 7200 }));
        let err = c
            .validate(&ValidationOptions::new(), NOW)
            .expect_err("expired rejected");
        assert!(err.to_string().contains("expired"), "{err}");
    }

    // JWT-011: an exp marginally in the past is tolerated within the skew.
    #[test]
    fn tolerates_clock_skew() {
        let c = claims(serde_json::json!({ "exp": NOW - 30, "iat": NOW - 3600 }));
        let opts = ValidationOptions::builder()
            .clock_skew(Duration::from_secs(60))
            .build();
        c.validate(&opts, NOW).expect("within skew passes");
    }

    // JWT-006: a token whose nbf is in the future beyond the skew is not yet
    // valid.
    #[test]
    fn rejects_not_yet_valid() {
        let c = claims(serde_json::json!({
            "exp": NOW + 3600,
            "nbf": NOW + 3600,
            "iat": NOW,
        }));
        let err = c
            .validate(&ValidationOptions::new(), NOW)
            .expect_err("nbf in future rejected");
        assert!(err.to_string().contains("nbf"), "{err}");
    }

    // JWT-007: a token whose iss differs from the expected issuer is rejected.
    #[test]
    fn rejects_wrong_issuer() {
        let c = claims(serde_json::json!({
            "iss": "https://evil.example.com",
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        let opts = ValidationOptions::builder()
            .issuer("https://issuer.example.com")
            .build();
        let err = c.validate(&opts, NOW).expect_err("wrong issuer rejected");
        assert!(err.to_string().contains("iss"), "{err}");
    }

    // JWT-008: a token whose aud lacks the expected audience is rejected, and an
    // absent aud is likewise rejected when an audience is expected.
    #[test]
    fn rejects_wrong_or_absent_audience() {
        let opts = ValidationOptions::builder().audience("test-client").build();

        let wrong = claims(serde_json::json!({
            "aud": ["other-client"],
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        let err = wrong.validate(&opts, NOW).expect_err("wrong aud rejected");
        assert!(err.to_string().contains("aud"), "{err}");

        let absent = claims(serde_json::json!({ "exp": NOW + 3600, "iat": NOW }));
        absent
            .validate(&opts, NOW)
            .expect_err("absent aud rejected when expected");
    }

    // JWT-004: with an expected nonce, a mismatch is rejected and a match passes.
    #[test]
    fn validates_nonce_when_expected() {
        let opts = ValidationOptions::builder().expected_nonce("n-123").build();

        let mismatch = claims(serde_json::json!({
            "nonce": "other",
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        mismatch
            .validate(&opts, NOW)
            .expect_err("nonce mismatch rejected");

        let matching = claims(serde_json::json!({
            "nonce": "n-123",
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        matching
            .validate(&opts, NOW)
            .expect("matching nonce passes");
    }

    // JWT-012: a token missing a claim named in required_claims is rejected,
    // identifying the missing claim.
    #[test]
    fn enforces_custom_required_claims() {
        let c = claims(serde_json::json!({ "exp": NOW + 3600, "iat": NOW }));
        let opts = ValidationOptions::builder()
            .required_claims(["scope"])
            .build();
        let err = c
            .validate(&opts, NOW)
            .expect_err("missing required claim rejected");
        assert!(err.to_string().contains("scope"), "{err}");

        // Present required claim passes.
        let with = claims(serde_json::json!({
            "exp": NOW + 3600,
            "iat": NOW,
            "scope": "openid",
        }));
        with.validate(&opts, NOW).expect("present required claim");
    }

    // aud accepts either a single string or an array of strings (RFC 7519
    // §4.1.3); extra claims land in `extra` and stay queryable.
    #[test]
    fn parses_audience_forms_and_extra_claims() {
        let single = claims(serde_json::json!({ "aud": "a", "iat": NOW, "exp": NOW + 1 }));
        assert_eq!(single.audience.values(), ["a"]);

        let many = claims(serde_json::json!({
            "aud": ["a", "b"],
            "iat": NOW,
            "exp": NOW + 1,
            "email": "user@example.com",
        }));
        assert!(many.audience.contains("b"));
        assert_eq!(many.get_str("email"), Some("user@example.com"));
        assert!(many.has("email") && many.has("aud"));
        assert!(!many.has("groups"));
    }

    // A null aud array element is rejected rather than coerced (RFC 7519 §4.1.3).
    #[test]
    fn rejects_null_audience_element() {
        let err =
            Claims::from_value(serde_json::json!({ "aud": ["a", null] })).expect_err("null aud");
        assert!(err.to_string().contains("aud"), "{err}");
    }

    // A far-future exp beyond the safe numeric-date bound is rejected as
    // out-of-range rather than silently wrapping.
    #[test]
    fn rejects_out_of_range_numeric_date() {
        let huge = (MAX_NUMERIC_DATE as f64) * 2.0;
        let err = Claims::from_value(serde_json::json!({ "exp": huge, "iat": NOW }))
            .expect_err("out-of-range exp");
        assert!(err.to_string().contains("exp"), "{err}");
    }

    // An integer exp just above 2^53 is bounded on its exact value, not after a
    // lossy f64 round that would pull it back under the guard.
    #[test]
    fn rejects_large_integer_numeric_date_precisely() {
        let just_over = MAX_NUMERIC_DATE + 1;
        let err = Claims::from_value(serde_json::json!({ "exp": just_over, "iat": NOW }))
            .expect_err("out-of-range integer exp");
        assert!(err.to_string().contains("exp"), "{err}");
    }

    // AC-3: with require_exp(false), a token lacking exp validates; a present but
    // expired exp is still rejected.
    #[test]
    fn require_exp_false_allows_missing_exp() {
        let opts = ValidationOptions::builder().require_exp(false).build();

        let no_exp = claims(serde_json::json!({ "iat": NOW }));
        no_exp.validate(&opts, NOW).expect("missing exp tolerated");

        let expired = claims(serde_json::json!({ "exp": NOW - 3600, "iat": NOW - 7200 }));
        expired
            .validate(&opts, NOW)
            .expect_err("present-but-expired exp still rejected");
    }

    // AC-3: with require_nbf(true), a token lacking nbf is rejected.
    #[test]
    fn require_nbf_true_rejects_missing_nbf() {
        let opts = ValidationOptions::builder().require_nbf(true).build();
        let c = claims(serde_json::json!({ "exp": NOW + 3600, "iat": NOW }));
        let err = c.validate(&opts, NOW).expect_err("missing nbf rejected");
        assert!(err.to_string().contains("nbf"), "{err}");
    }

    // AC-6: the expiry error carries the exp value in its context.
    #[test]
    fn expired_error_includes_exp_value() {
        let exp = NOW - 3600;
        let c = claims(serde_json::json!({ "exp": exp, "iat": NOW - 7200 }));
        let err = c
            .validate(&ValidationOptions::new(), NOW)
            .expect_err("expired rejected");
        assert!(err.to_string().contains(&exp.to_string()), "{err}");
    }

    // AC-7: the audience-mismatch error lists the token's actual audience(s).
    #[test]
    fn audience_error_lists_actual_values() {
        let opts = ValidationOptions::builder().audience("test-client").build();
        let c = claims(serde_json::json!({
            "aud": ["other-a", "other-b"],
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        let err = c.validate(&opts, NOW).expect_err("aud mismatch rejected");
        let msg = err.to_string();
        assert!(msg.contains("test-client"), "expected value missing: {msg}");
        assert!(msg.contains("other-a"), "actual value missing: {msg}");
    }

    // Blind: a required claim carrying null or an empty value does not satisfy
    // the presence check.
    #[test]
    fn required_claim_rejects_null_or_empty_value() {
        let opts = ValidationOptions::builder()
            .required_claims(["scope"])
            .build();

        for empty in [
            serde_json::json!(null),
            serde_json::json!(""),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let c = claims(serde_json::json!({
                "exp": NOW + 3600,
                "iat": NOW,
                "scope": empty,
            }));
            c.validate(&opts, NOW)
                .expect_err("null/empty required claim rejected");
        }
    }

    // Blind: an expected nonce (even the empty string) is not satisfied by a
    // token that omits the nonce claim.
    #[test]
    fn expected_empty_nonce_requires_presence() {
        let opts = ValidationOptions::builder().expected_nonce("").build();

        let absent = claims(serde_json::json!({ "exp": NOW + 3600, "iat": NOW }));
        absent
            .validate(&opts, NOW)
            .expect_err("absent nonce rejected when expected");

        let present = claims(serde_json::json!({
            "nonce": "",
            "exp": NOW + 3600,
            "iat": NOW,
        }));
        present
            .validate(&opts, NOW)
            .expect("present empty nonce matches expected empty nonce");
    }
}
