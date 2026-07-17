//! Validation options for [`crate::validate_token`] (RFC 7519 §4.1).

use std::time::Duration;

/// The default set of accepted JWS algorithms when the caller does not override
/// it with [`ValidationOptionsBuilder::allowed_algorithms`].
///
/// Only asymmetric signature algorithms are permitted: the symmetric `HS*`
/// family is intentionally excluded so a token signed with HMAC cannot be
/// verified against a provider's public key (algorithm-confusion attack), and
/// the unsecured `none` algorithm is never accepted (JWT-003). Mirrors
/// `go/pkg/jwt` `defaultAllowedAlgorithms` minus `ES512` (P-521), which the
/// underlying `jsonwebtoken` verifier does not support; a caller can still add
/// it via [`ValidationOptionsBuilder::allowed_algorithms`] but a token using it
/// will fail as an unsupported algorithm.
pub const DEFAULT_ALLOWED_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
];

/// Resolved settings for a token validation.
///
/// Construct one with [`ValidationOptions::builder`]. An empty
/// [`ValidationOptions`] (via [`ValidationOptions::new`]) checks only the
/// mandatory rules — signature, the algorithm allowlist, `iat` presence, and
/// `exp` expiry — leaving issuer, audience, and nonce unchecked. The `With*`
/// surface mirrors the discovery and jwks builders so the modules compose
/// consistently.
#[derive(Clone, Debug)]
pub struct ValidationOptions {
    pub(crate) expected_issuer: Option<String>,
    pub(crate) expected_audience: Option<String>,
    /// `Some` records that a nonce was requested; the empty string is a valid
    /// expected value, so presence is tracked separately from the value.
    pub(crate) expected_nonce: Option<String>,
    pub(crate) clock_skew: Duration,
    pub(crate) required_claims: Vec<String>,
    pub(crate) allowed_algorithms: Vec<String>,
    /// When `true` (the default), `exp` must be present and not expired. When
    /// `false`, an absent `exp` is tolerated, though a present `exp` is still
    /// enforced (JWT-005).
    pub(crate) require_exp: bool,
    /// When `true`, `nbf` must be present (and in the past within skew). When
    /// `false` (the default), `nbf` is checked only if present (JWT-006).
    pub(crate) require_nbf: bool,
}

impl ValidationOptions {
    /// Returns options with the defaults: no issuer/audience/nonce check, zero
    /// clock skew, no custom required claims, and the default asymmetric
    /// algorithm allowlist ([`DEFAULT_ALLOWED_ALGORITHMS`]).
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Returns a builder for customising the validation settings.
    pub fn builder() -> ValidationOptionsBuilder {
        ValidationOptionsBuilder::new()
    }
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for [`ValidationOptions`]. Obtain one via
/// [`ValidationOptions::builder`].
#[derive(Clone, Debug)]
pub struct ValidationOptionsBuilder {
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    expected_nonce: Option<String>,
    clock_skew: Duration,
    required_claims: Vec<String>,
    allowed_algorithms: Vec<String>,
    require_exp: bool,
    require_nbf: bool,
}

impl ValidationOptionsBuilder {
    /// Returns a builder seeded with the default configuration.
    fn new() -> Self {
        Self {
            expected_issuer: None,
            expected_audience: None,
            expected_nonce: None,
            clock_skew: Duration::ZERO,
            required_claims: Vec::new(),
            allowed_algorithms: DEFAULT_ALLOWED_ALGORITHMS
                .iter()
                .map(|a| (*a).to_string())
                .collect(),
            require_exp: true,
            require_nbf: false,
        }
    }

    /// Requires the token's `iss` claim to exactly match `issuer` (JWT-007,
    /// RFC 7519 §4.1.1). When unset, `iss` is not checked.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Requires the token's `aud` claim to contain `audience` (JWT-008,
    /// RFC 7519 §4.1.3). When unset, `aud` is not checked.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Requires the token's `nonce` claim to equal `nonce` (JWT-004, OIDC Core
    /// 1.0 §3.1.3.7). When unset, `nonce` is not checked. An empty string is a
    /// valid expected value, so calling this records that a nonce was requested.
    pub fn expected_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.expected_nonce = Some(nonce.into());
        self
    }

    /// Tolerates up to `skew` of clock drift when evaluating the time-based
    /// claims `exp` and `nbf` (JWT-011, RFC 7519 §4.1.4–4.1.5). The default is
    /// zero.
    pub fn clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Requires each named claim to be present in the token payload (JWT-012,
    /// RFC 7519 §4.1). Presence only — value checks for the registered claims
    /// use the dedicated methods above.
    pub fn required_claims<I, S>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_claims = claims.into_iter().map(Into::into).collect();
        self
    }

    /// Overrides the accepted JWS algorithms. Supplying `none` has no effect: it
    /// is always rejected (JWT-003). Passing an empty set keeps the default
    /// asymmetric allowlist ([`DEFAULT_ALLOWED_ALGORITHMS`]).
    pub fn allowed_algorithms<I, S>(mut self, algs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let algs: Vec<String> = algs
            .into_iter()
            .map(Into::into)
            .filter(|a| !a.is_empty() && !a.eq_ignore_ascii_case("none"))
            .collect();
        if !algs.is_empty() {
            self.allowed_algorithms = algs;
        }
        self
    }

    /// Requires the token to carry an `exp` claim (default `true`). When set to
    /// `false`, a token without `exp` is accepted; a present `exp` is still
    /// checked for expiry (AC-3, JWT-005, RFC 7519 §4.1.4).
    pub fn require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
        self
    }

    /// Requires the token to carry an `nbf` claim (default `false`). When left
    /// `false`, `nbf` is validated only if present; when `true`, an absent `nbf`
    /// is rejected (AC-3, JWT-006, RFC 7519 §4.1.5).
    pub fn require_nbf(mut self, require: bool) -> Self {
        self.require_nbf = require;
        self
    }

    /// Builds the [`ValidationOptions`].
    pub fn build(self) -> ValidationOptions {
        ValidationOptions {
            expected_issuer: self.expected_issuer,
            expected_audience: self.expected_audience,
            expected_nonce: self.expected_nonce,
            clock_skew: self.clock_skew,
            required_claims: self.required_claims,
            allowed_algorithms: self.allowed_algorithms,
            require_exp: self.require_exp,
            require_nbf: self.require_nbf,
        }
    }
}

impl Default for ValidationOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AC3: an empty options set carries the default asymmetric allowlist and no
    // issuer/audience/nonce expectations.
    #[test]
    fn defaults_are_empty_with_asymmetric_allowlist() {
        let opts = ValidationOptions::new();
        assert!(opts.expected_issuer.is_none());
        assert!(opts.expected_audience.is_none());
        assert!(opts.expected_nonce.is_none());
        assert_eq!(opts.clock_skew, Duration::ZERO);
        assert!(opts.required_claims.is_empty());
        // AC3: exp is required by default; nbf is not.
        assert!(opts.require_exp);
        assert!(!opts.require_nbf);
        assert_eq!(opts.allowed_algorithms, DEFAULT_ALLOWED_ALGORITHMS);
        // The default allowlist never contains a symmetric or unsecured alg.
        assert!(!opts.allowed_algorithms.iter().any(|a| a.starts_with("HS")));
        assert!(!opts.allowed_algorithms.iter().any(|a| a == "none"));
    }

    // AC3: the builder records each configured expectation.
    #[test]
    fn builder_records_expectations() {
        let opts = ValidationOptions::builder()
            .issuer("https://issuer.example.com")
            .audience("test-client")
            .expected_nonce("n-123")
            .clock_skew(Duration::from_secs(60))
            .required_claims(["scope", "email"])
            .build();
        assert_eq!(
            opts.expected_issuer.as_deref(),
            Some("https://issuer.example.com")
        );
        assert_eq!(opts.expected_audience.as_deref(), Some("test-client"));
        assert_eq!(opts.expected_nonce.as_deref(), Some("n-123"));
        assert_eq!(opts.clock_skew, Duration::from_secs(60));
        assert_eq!(opts.required_claims, vec!["scope", "email"]);
    }

    // AC3: the require_exp/require_nbf toggles named in the AC flip the defaults.
    #[test]
    fn builder_toggles_exp_and_nbf_requirements() {
        let opts = ValidationOptions::builder()
            .require_exp(false)
            .require_nbf(true)
            .build();
        assert!(!opts.require_exp);
        assert!(opts.require_nbf);
    }

    // JWT-004: an empty expected nonce is still "set" (presence tracked apart
    // from value), so an empty-string nonce can be required explicitly.
    #[test]
    fn empty_nonce_is_recorded_as_set() {
        let opts = ValidationOptions::builder().expected_nonce("").build();
        assert_eq!(opts.expected_nonce.as_deref(), Some(""));
    }

    // A custom allowlist replaces the default and drops none/empty entries.
    #[test]
    fn custom_allowlist_filters_none_and_empty() {
        let opts = ValidationOptions::builder()
            .allowed_algorithms(["RS256", "none", "", "ES256"])
            .build();
        assert_eq!(opts.allowed_algorithms, vec!["RS256", "ES256"]);
    }

    // An all-none/empty override is ignored and the default allowlist is kept.
    #[test]
    fn empty_allowlist_override_keeps_default() {
        let opts = ValidationOptions::builder()
            .allowed_algorithms(["none", ""])
            .build();
        assert_eq!(opts.allowed_algorithms, DEFAULT_ALLOWED_ALGORITHMS);
    }
}
