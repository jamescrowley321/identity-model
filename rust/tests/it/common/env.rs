//! Provider selection from the shared `TEST_*` environment convention, and the
//! fail rule every live test is gated on.
//!
//! The Makefile sources a profile such as `.env.node-oidc` before running the
//! live suite. `TEST_DISCO_ADDRESS` is the full discovery-document URL; the
//! issuer is that URL minus the `/.well-known/openid-configuration` suffix.
//! Client credentials arrive as `TEST_CLIENT_ID`/`TEST_CLIENT_SECRET` (JWT
//! access tokens) and `TEST_OPAQUE_CLIENT_ID`/`TEST_OPAQUE_CLIENT_SECRET`
//! (opaque tokens, for introspection and revocation).

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// Returns the issuer derived from `TEST_DISCO_ADDRESS`, or `None` when the
/// variable is unset or blank.
pub fn issuer_from_env() -> Option<String> {
    let disco = std::env::var("TEST_DISCO_ADDRESS").ok()?;
    let disco = disco.trim();
    if disco.is_empty() {
        return None;
    }
    Some(
        disco
            .strip_suffix(WELL_KNOWN_SUFFIX)
            .unwrap_or(disco)
            .trim_end_matches('/')
            .to_string(),
    )
}

/// Reads a non-empty `TEST_*` environment variable.
pub fn env_nonempty(name: &str) -> Option<String> {
    let v = std::env::var(name).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Fails the test: a live prerequisite (reachable provider, sourced profile,
/// client credentials, advertised endpoint) is missing.
///
/// Live tests are `#[ignore]`-gated and run only via
/// `make test-integration-rust`, which boots the fixture and sources
/// `.env.node-oidc` first — so a missing prerequisite there is always a bug,
/// never a reason to skip (mechanical-gate rule, CONS-1.4 review). The Go
/// integration suite follows the same rule.
pub fn fail_live_prerequisite(msg: &str) {
    panic!("{msg}");
}
