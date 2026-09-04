//! Integration test for the ID-Token profile (`validate_id_token`) against a
//! real provider.
//!
//! `#[ignore]`-gated so a bare `cargo test` (no provider up) stays green. The
//! `integration-tests-rust` CI job boots the local `infra/` node-oidc-provider
//! (`:9010`), runs the unit suite, then runs these with
//! `cargo test -- --ignored` under `TEST_REQUIRE_LIVE=1` (infra skips fail).
//!
//! Run locally:
//!
//! ```text
//! make infra-up
//! make test-integration-rust      # or: cd rust && cargo test -- --ignored
//! make infra-down
//! ```
//!
//! Provider selection follows the shared `TEST_*` convention (the
//! `.env.node-oidc` profile the Makefile sources). If `TEST_DISCO_ADDRESS` is
//! unset the test skips (returns) rather than failing.
//!
//! What it proves (`integration_validate_id_token_live`, OIDC Core §3.1.3.7):
//! a genuine ID Token is minted through a real authorization-code + PKCE flow
//! (headless devInteractions, no browser), requesting a `nonce` and a
//! `max_age`, then [`validate_id_token`] enforces the full profile end-to-end:
//!
//! * base profile — signature (live discovery → JWKS), `iss`, `aud`, `exp` and
//!   the required `sub` — validate on the real claim set;
//! * the same real ID Token is rejected when validated for a different
//!   `client_id` ([`IdentityError::Validation`], `aud` mismatch);
//! * the `nonce` sent on the authorization request binds (a wrong nonce is an
//!   [`IdentityError::IdTokenValidation`]);
//! * `max_age`/`auth_time` freshness holds on the real `auth_time`.
//!
//! node-oidc-provider, like most OPs, mints `at_hash` only for
//! authorization-endpoint (implicit/hybrid) responses, not the code flow, so
//! the `at_hash` binding is asserted only when the real ID Token actually
//! carries one — that leg self-guards and documents why it is skipped
//! otherwise.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs_identity_model::{
    DiscoveryClient, IdTokenValidationOptions, IdentityError, JwksClient, PkceChallenge,
    TokenClient, ValidationOptions, validate_id_token,
};
use serde_json::Value;

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// A fixed nonce/max_age sent on the authorization request so the OP echoes a
/// `nonce` and an `auth_time` into the minted ID Token, exercising the
/// §3.1.3.7 nonce (step 11) and max_age/auth_time (step 12) bindings on a real
/// token.
const LIVE_NONCE: &str = "live-rs-id-token-nonce-4d1f7a";
const LIVE_MAX_AGE: i64 = 3600;

/// Returns the issuer derived from `TEST_DISCO_ADDRESS`, or `None` when unset.
fn issuer_from_env() -> Option<String> {
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
fn env_nonempty(name: &str) -> Option<String> {
    let v = std::env::var(name).ok()?;
    let v = v.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Prints a SKIP marker — unless `TEST_REQUIRE_LIVE=1`, in which case it panics.
/// CI sets the variable in the leg that just booted the fixture, so an
/// unreachable provider or unsourced profile turns the leg red instead of
/// green-skipping every test (mechanical-gate rule).
fn skip_or_fail(msg: &str) {
    if std::env::var("TEST_REQUIRE_LIVE").as_deref() == Ok("1") {
        panic!("TEST_REQUIRE_LIVE=1 but {msg}");
    }
    eprintln!("SKIP: {msg}");
}

/// Decodes an ID Token's payload claims WITHOUT verifying — only to branch on
/// the presence of `nonce`/`auth_time`/`at_hash`.
fn decode_payload(id_token: &str) -> Value {
    let payload = id_token
        .split('.')
        .nth(1)
        .expect("compact JWS has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("decode ID Token payload");
    serde_json::from_slice(&bytes).expect("parse ID Token payload JSON")
}

// ── Headless devInteractions auth-code + PKCE flow ──────────────────────────
//
// Mirrors `token_client.rs::integration_authorization_code_pkce_end_to_end`:
// drives node-oidc-provider's login + consent with a plain HTTP client (no
// browser). Duplicated per test file, matching the crate's integration-test
// convention.

/// Absorbs `Set-Cookie` name=value pairs; deletions (empty value) are removed.
fn absorb_cookies(store: &mut HashMap<String, String>, resp: &reqwest::Response) {
    for sc in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let Ok(s) = sc.to_str() else { continue };
        let Some(pair) = s.split(';').next() else {
            continue;
        };
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            store.remove(name.trim());
        } else {
            store.insert(name.trim().to_string(), value.to_string());
        }
    }
}

fn cookie_header(store: &HashMap<String, String>) -> String {
    store
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Follows a redirect chain manually, stopping when a `Location` targets the
/// (unserved) `redirect_uri`. Returns `(final_url, status, Some(callback_url))`
/// at the callback, `(final_url, status, None)` on a non-redirect page.
async fn follow_to_callback(
    client: &reqwest::Client,
    cookies: &mut HashMap<String, String>,
    mut request: reqwest::RequestBuilder,
    redirect_uri: &str,
) -> Result<(url::Url, reqwest::StatusCode, Option<String>), String> {
    for _hop in 0..10 {
        let req = request
            .header(reqwest::header::COOKIE, cookie_header(cookies))
            .build()
            .map_err(|e| format!("build request: {e}"))?;
        let current = req.url().clone();
        let resp = client
            .execute(req)
            .await
            .map_err(|e| format!("request {current} failed: {e}"))?;
        absorb_cookies(cookies, &resp);
        let status = resp.status();
        if !status.is_redirection() {
            return Ok((current, status, None));
        }
        let loc = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| format!("redirect without Location at {current}"))?;
        let next = current
            .join(loc)
            .map_err(|e| format!("resolve redirect {loc:?}: {e}"))?;
        if next.as_str().starts_with(redirect_uri) {
            return Ok((current, status, Some(next.into())));
        }
        request = client.get(next);
    }
    Err("too many redirects (>10)".into())
}

/// Runs the full headless auth-code + PKCE flow and returns the callback URL
/// carrying the authorization `code`, or `None` when the provider has no
/// headless devInteractions (caller skips).
async fn drive_auth_code_flow(
    http: &reqwest::Client,
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkceChallenge,
    state: &str,
) -> Option<String> {
    let mut cookies = HashMap::new();
    let auth_url = url::Url::parse_with_params(
        authorization_endpoint,
        &[
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "openid profile email"),
            ("state", state),
            ("code_challenge", pkce.code_challenge.as_str()),
            ("code_challenge_method", pkce.code_challenge_method.as_str()),
            ("nonce", LIVE_NONCE),
            ("max_age", &LIVE_MAX_AGE.to_string()),
        ],
    )
    .expect("build authorize URL");

    let (landed, status, mut callback) =
        follow_to_callback(http, &mut cookies, http.get(auth_url), redirect_uri)
            .await
            .expect("authorize leg");

    if callback.is_none() {
        let auth_path = url::Url::parse(authorization_endpoint)
            .map(|u| u.path().to_string())
            .unwrap_or_default();
        // A >=400 rendered AT the authorization endpoint itself is a real
        // regression (unknown client_id, redirect mismatch), never a skip.
        assert!(
            !((status.is_client_error() || status.is_server_error()) && landed.path() == auth_path),
            "authorization endpoint rejected the request: {status} at {landed}"
        );
        // Providers without node-oidc's devInteractions redirect to a real
        // browser login UI; skip rather than fail.
        if status.is_client_error()
            || status.is_server_error()
            || !landed.path().contains("/interaction/")
        {
            skip_or_fail(&format!(
                "provider has no devInteractions (landed on {landed} with {status}); headless flow unavailable"
            ));
            return None;
        }
        // devInteractions login: one endpoint dispatches on `prompt`.
        let login = http.post(landed.clone()).form(&[
            ("prompt", "login"),
            ("login", "test-user"),
            ("password", "test"),
        ]);
        let (after_login, status, cb) = follow_to_callback(http, &mut cookies, login, redirect_uri)
            .await
            .expect("login leg");
        assert!(
            cb.is_some() || !(status.is_client_error() || status.is_server_error()),
            "login failed: {status} at {after_login}"
        );
        callback = cb;
        if callback.is_none() && after_login.path().contains("/interaction/") {
            let consent = http
                .post(after_login.clone())
                .form(&[("prompt", "consent")]);
            let (after_consent, status, cb) =
                follow_to_callback(http, &mut cookies, consent, redirect_uri)
                    .await
                    .expect("consent leg");
            assert!(
                cb.is_some() || !(status.is_client_error() || status.is_server_error()),
                "consent failed: {status} at {after_consent}"
            );
            callback = cb;
        }
    }
    callback
}

// OIDC Core §3.1.3.7 end-to-end: mint a real ID Token via a headless auth-code +
// PKCE flow, then validate it (and its nonce/aud/max_age bindings) through the
// public `validate_id_token` entry point against the live provider.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_validate_id_token_live() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(client_id) = env_nonempty("TEST_PKCE_PUBLIC_CLIENT_ID") else {
        skip_or_fail("TEST_PKCE_PUBLIC_CLIENT_ID unset for this provider profile");
        return;
    };
    let Some(redirect_uri) = env_nonempty("TEST_REDIRECT_URI") else {
        skip_or_fail("TEST_REDIRECT_URI unset for this provider profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    let meta = match discovery.discover(&issuer).await {
        Ok(meta) => meta,
        Err(e) => {
            skip_or_fail(&format!(
                "provider not reachable at {issuer} (run `make infra-up`): {e}"
            ));
            return;
        }
    };
    assert!(
        !meta.authorization_endpoint.is_empty(),
        "discovery returned empty authorization_endpoint"
    );
    assert!(
        !meta.jwks_uri.is_empty(),
        "discovery returned empty jwks_uri"
    );
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );

    // --- Mint a real ID Token through the headless auth-code + PKCE flow. ---
    let pkce = PkceChallenge::generate().expect("generate PKCE challenge");
    let state = PkceChallenge::generate()
        .expect("generate state entropy")
        .code_verifier;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build flow http client");

    let Some(callback) = drive_auth_code_flow(
        &http,
        &meta.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &pkce,
        &state,
    )
    .await
    else {
        return; // skipped: no headless devInteractions on this provider
    };

    let callback = url::Url::parse(&callback).expect("parse callback URL");
    let params: HashMap<_, _> = callback.query_pairs().collect();
    assert!(
        !params.contains_key("error"),
        "authorization error at callback: {callback}"
    );
    assert_eq!(
        params.get("state").map(AsRef::as_ref),
        Some(state.as_str()),
        "callback state mismatch"
    );
    let code = params.get("code").expect("callback carried no code");

    let token = TokenClient::builder()
        .client_id(client_id.clone())
        .token_endpoint(meta.token_endpoint.clone())
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build public token client")
        .exchange_code(code, &redirect_uri, Some(&pkce.code_verifier))
        .await
        .expect("authorization-code exchange with PKCE verifier");

    let id_token = token
        .id_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .expect("openid-scoped code exchange returned no id_token");
    let payload = decode_payload(id_token);

    let jwks = JwksClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();

    // --- Base profile: signature + iss/aud/exp + required sub. ---
    let base = ValidationOptions::builder()
        .issuer(meta.issuer.as_str())
        .audience(client_id.as_str())
        .build();
    let profile = IdTokenValidationOptions::builder()
        .client_id(client_id.as_str())
        .build();
    let claims = validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &profile)
        .await
        .unwrap_or_else(|e| panic!("validate live ID Token: {e}"));
    assert!(
        claims.subject.as_deref().is_some_and(|s| !s.is_empty()),
        "validated ID Token is missing the required sub claim"
    );
    assert_eq!(
        claims.issuer.as_deref(),
        Some(meta.issuer.as_str()),
        "validated ID Token issuer mismatch"
    );
    assert!(
        claims.audience.contains(&client_id),
        "validated ID Token aud does not contain the client_id"
    );

    // --- The same real ID Token is rejected for a different client_id. ---
    let wrong_aud_base = ValidationOptions::builder()
        .issuer(meta.issuer.as_str())
        .audience("some-other-audience")
        .build();
    let err = validate_id_token(id_token, &jwks, &meta.jwks_uri, &wrong_aud_base, &profile)
        .await
        .expect_err("ID Token must be rejected for a different audience");
    assert!(
        matches!(err, IdentityError::Validation(_)),
        "err = {err:?}, want Validation for aud mismatch"
    );

    // --- nonce binding (only if the OP echoed the requested nonce). ---
    if payload.get("nonce").and_then(Value::as_str).is_some() {
        let matching = IdTokenValidationOptions::builder()
            .client_id(client_id.as_str())
            .nonce(LIVE_NONCE)
            .build();
        let bound = validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &matching)
            .await
            .expect("matching nonce validates on the real ID Token");
        assert_eq!(
            bound.nonce.as_deref(),
            Some(LIVE_NONCE),
            "validated ID Token nonce mismatch"
        );

        let wrong_nonce = IdTokenValidationOptions::builder()
            .client_id(client_id.as_str())
            .nonce("not-the-nonce-we-sent")
            .build();
        let err = validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &wrong_nonce)
            .await
            .expect_err("a wrong nonce must be rejected");
        assert!(
            matches!(err, IdentityError::IdTokenValidation(_)),
            "err = {err:?}, want IdTokenValidation for nonce mismatch"
        );
    } else {
        eprintln!("SKIP(nonce): OP did not echo the requested nonce into the ID Token");
    }

    // --- max_age/auth_time freshness (only if the OP included auth_time). ---
    if payload.get("auth_time").is_some() {
        let with_max_age = IdTokenValidationOptions::builder()
            .client_id(client_id.as_str())
            .max_age(LIVE_MAX_AGE)
            .build();
        let fresh = validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &with_max_age)
            .await
            .expect("a just-minted auth_time is within max_age");
        assert!(
            fresh.get("auth_time").is_some(),
            "validated ID Token missing auth_time under a max_age check"
        );
    } else {
        eprintln!("SKIP(max_age): OP did not include auth_time in the ID Token");
    }

    // --- at_hash binding (only when the OP mints an at_hash — the code flow
    //     typically does not; asserted for correctness when present). ---
    if payload.get("at_hash").and_then(Value::as_str).is_some() {
        let access_token = token.access_token.as_str();
        assert!(
            !access_token.is_empty(),
            "ID Token carried an at_hash but the flow returned no access_token"
        );
        let good = IdTokenValidationOptions::builder()
            .client_id(client_id.as_str())
            .access_token(access_token)
            .build();
        validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &good)
            .await
            .expect("correct access token binds to at_hash");

        let bad = IdTokenValidationOptions::builder()
            .client_id(client_id.as_str())
            .access_token(format!("{access_token}tampered"))
            .build();
        let err = validate_id_token(id_token, &jwks, &meta.jwks_uri, &base, &bad)
            .await
            .expect_err("a tampered access token must fail the at_hash check");
        assert!(
            matches!(err, IdentityError::IdTokenValidation(_)),
            "err = {err:?}, want IdTokenValidation for at_hash mismatch"
        );
    } else {
        eprintln!(
            "SKIP(at_hash): OP's code-flow ID Token carries no at_hash \
             (emitted only for authorization-endpoint responses)"
        );
    }
}
