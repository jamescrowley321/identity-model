//! Integration tests for the OAuth 2.0 token revocation client (RFC 7009)
//! against a real provider.
//!
//! `#[ignore]`-gated so a bare `cargo test` (no provider up) stays green. The
//! `rust-integration` CI job boots the local `infra/` node-oidc-provider
//! (`:9010`, `revocation: { enabled: true }`), runs the unit suite, then runs
//! these with `cargo test -- --ignored` under `TEST_REQUIRE_LIVE=1` (infra skips
//! fail).
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
//! `.env.node-oidc` profile the Makefile sources). `TEST_DISCO_ADDRESS` is the
//! full discovery-document URL; the issuer is that URL minus the
//! `/.well-known/openid-configuration` suffix, and `revocation_endpoint` is
//! resolved from the fetched discovery document (REV-005). If
//! `TEST_DISCO_ADDRESS` is unset the test skips (returns) rather than failing.
//!
//! Revocation is only meaningful for opaque tokens (revoking a self-contained
//! JWT the server never tracked is a no-op), so — mirroring the Go reference
//! (`go/pkg/revocation/revocation_integration_test.go`) — the subject token is
//! minted via the client-credentials grant against the `test-opaque` client,
//! whose tokens node-oidc-provider issues in opaque form:
//!
//! * `integration_revoke_opaque_live` (REV-001/005): mint an opaque token,
//!   confirm it introspects `active`, revoke it, then confirm it introspects
//!   `active == false` — proving the revoked token is no longer accepted.
//! * `integration_revoke_idempotent_and_unknown_live` (REV-001 anti-scanning):
//!   revoking the same token twice and revoking a never-issued token all succeed.
//! * `integration_revoke_invalid_client_live` (REV-004): a bad client secret
//!   surfaces a typed [`IdentityError::TokenEndpoint`] (`invalid_client`) — or,
//!   for providers with a non-RFC error body, an [`IdentityError::Http`]
//!   carrying the 4xx status.

use std::time::Duration;

use rs_identity_model::{
    DiscoveryClient, IdentityError, IntrospectionClient, RevocationClient, TokenClient,
};

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// Returns the issuer derived from `TEST_DISCO_ADDRESS`, or `None` when the
/// variable is unset so the caller can skip gracefully.
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
/// green-skipping every test.
fn skip_or_fail(msg: &str) {
    if std::env::var("TEST_REQUIRE_LIVE").as_deref() == Ok("1") {
        panic!("TEST_REQUIRE_LIVE=1 but {msg}");
    }
    eprintln!("SKIP: {msg}");
}

/// Discovers the live provider's metadata, skipping when it is unreachable so a
/// missing local stack does not fail CI-less runs.
async fn discover_or_skip(
    issuer: &str,
    allow_http: bool,
) -> Option<rs_identity_model::ProviderMetadata> {
    let discovery = DiscoveryClient::builder()
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    match discovery.discover(issuer).await {
        Ok(meta) => Some(meta),
        Err(e) => {
            skip_or_fail(&format!(
                "provider not reachable at {issuer} (run `make infra-up`): {e}"
            ));
            None
        }
    }
}

/// Mints an opaque access token from the `test-opaque` client via the
/// client-credentials grant. node-oidc-provider issues opaque (non-JWT) tokens
/// for this client, which is the only kind its revocation endpoint tracks.
async fn mint_opaque_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    allow_http: bool,
) -> String {
    let client = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(token_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build token client");
    let resp = client
        .client_credentials(env_nonempty("TEST_SCOPE").as_deref())
        .await
        .unwrap_or_else(|e| panic!("mint opaque token via client_credentials: {e}"));
    assert!(!resp.access_token.is_empty(), "empty access_token minted");
    resp.access_token
}

// REV-001 / REV-005: mint an opaque token, resolve the endpoint from discovery,
// confirm it introspects active, revoke it, then confirm it introspects
// active=false — proving the revoked token is no longer accepted.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_opaque_live() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_OPAQUE_CLIENT_ID"),
        env_nonempty("TEST_OPAQUE_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_OPAQUE_CLIENT_ID/TEST_OPAQUE_CLIENT_SECRET unset for this profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some(meta) = discover_or_skip(&issuer, allow_http).await else {
        return;
    };
    let Some(revocation_endpoint) = meta.revocation_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise revocation_endpoint");
        return;
    };
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );

    let token =
        mint_opaque_token(&meta.token_endpoint, &client_id, &client_secret, allow_http).await;

    // Sanity: before revocation the token should introspect active (when the
    // provider advertises introspection — node-oidc-provider does).
    if let Some(introspection_endpoint) = meta.introspection_endpoint.clone() {
        let before = IntrospectionClient::builder()
            .client_id(&client_id)
            .client_secret(&client_secret)
            .introspection_endpoint(&introspection_endpoint)
            .allow_http(allow_http)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build introspection client")
            .introspect(&token, Some("access_token"))
            .await
            .unwrap_or_else(|e| panic!("introspect before revoke: {e}"));
        assert!(before.active, "token should be active before revocation");
    }

    // Revoke the freshly minted opaque token.
    RevocationClient::builder()
        .client_id(&client_id)
        .client_secret(&client_secret)
        .revocation_endpoint(&revocation_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build revocation client")
        .revoke(&token, Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("revoke opaque token against live provider: {e}"));

    // After revocation the token must no longer be accepted (introspects
    // active=false).
    if let Some(introspection_endpoint) = meta.introspection_endpoint.clone() {
        let after = IntrospectionClient::builder()
            .client_id(&client_id)
            .client_secret(&client_secret)
            .introspection_endpoint(&introspection_endpoint)
            .allow_http(allow_http)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build introspection client")
            .introspect(&token, Some("access_token"))
            .await
            .unwrap_or_else(|e| panic!("introspect after revoke: {e}"));
        assert!(
            !after.active,
            "revoked token must no longer be active: {after:?}"
        );
    }
}

// REV-001 (anti-scanning §2.1): revoking the same token twice and revoking a
// never-issued token all succeed — the endpoint MUST NOT distinguish token
// state, so none of these can error.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_idempotent_and_unknown_live() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_OPAQUE_CLIENT_ID"),
        env_nonempty("TEST_OPAQUE_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_OPAQUE_CLIENT_ID/TEST_OPAQUE_CLIENT_SECRET unset for this profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some(meta) = discover_or_skip(&issuer, allow_http).await else {
        return;
    };
    let Some(revocation_endpoint) = meta.revocation_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise revocation_endpoint");
        return;
    };

    let token =
        mint_opaque_token(&meta.token_endpoint, &client_id, &client_secret, allow_http).await;

    let revoker = RevocationClient::builder()
        .client_id(&client_id)
        .client_secret(&client_secret)
        .revocation_endpoint(&revocation_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build revocation client");

    // Revoke twice: the second call (token already revoked) must still succeed.
    revoker
        .revoke(&token, Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("first revoke: {e}"));
    revoker
        .revoke(&token, Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("second revoke of already-revoked token: {e}"));

    // Revoking a token the provider never issued must also succeed (§2.1).
    revoker
        .revoke("this-token-was-never-issued", Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("revoke of unknown token: {e}"));
}

// REV-004: a bad client secret produces a typed error from the live provider,
// exercising the real RFC 6749 §5.2 error path. node-oidc-provider returns a
// standard `invalid_client` error body -> TokenEndpoint; providers with a
// proprietary body surface as Http carrying the 4xx status.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_invalid_client_live() {
    let Some(issuer) = issuer_from_env() else {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        return;
    };
    let Some(client_id) = env_nonempty("TEST_OPAQUE_CLIENT_ID") else {
        skip_or_fail("TEST_OPAQUE_CLIENT_ID unset for this profile");
        return;
    };

    let allow_http = issuer.starts_with("http://");
    let Some(meta) = discover_or_skip(&issuer, allow_http).await else {
        return;
    };
    let Some(revocation_endpoint) = meta.revocation_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise revocation_endpoint");
        return;
    };

    let err = RevocationClient::builder()
        .client_id(client_id)
        .client_secret("wrong-secret")
        .revocation_endpoint(revocation_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build revocation client")
        .revoke("any-token", None)
        .await
        .expect_err("bad client secret must fail revocation");

    match err {
        IdentityError::TokenEndpoint { error, status, .. } => {
            assert_eq!(error, "invalid_client", "unexpected OAuth error: {error}");
            assert!(
                (400..500).contains(&status),
                "expected a 4xx status, got {status}"
            );
        }
        IdentityError::Http(msg) => {
            // A provider returning a non-RFC body surfaces as Http; still a 4xx.
            assert!(msg.contains("40"), "expected a 4xx Http error, got: {msg}");
        }
        other => panic!("expected TokenEndpoint or Http, got {other:?}"),
    }
}
