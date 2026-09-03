//! Integration tests for the OAuth 2.0 token introspection client (RFC 7662)
//! against a real provider.
//!
//! `#[ignore]`-gated so a bare `cargo test` (no provider up) stays green. The
//! `rust-integration` CI job boots the local `infra/` node-oidc-provider
//! (`:9010`, `introspection: { enabled: true }`), runs the unit suite, then runs
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
//! `/.well-known/openid-configuration` suffix, and `introspection_endpoint` is
//! resolved from the fetched discovery document (INTR-006). If
//! `TEST_DISCO_ADDRESS` is unset the test skips (returns) rather than failing.
//!
//! Introspection is only meaningful for opaque tokens (a provider cannot look up
//! a self-contained JWT), so — mirroring the Go reference
//! (`go/pkg/introspection/introspection_integration_test.go`) — the subject
//! token is minted via the client-credentials grant against the `test-opaque`
//! client, whose tokens node-oidc-provider issues in opaque form:
//!
//! * `integration_introspect_active_live` (INTR-001/003/006): mint an opaque
//!   token, discover the endpoint, introspect it, and assert `active == true`
//!   with the client_id echoed back.
//! * `integration_introspect_inactive_live` (INTR-002): introspecting a garbage
//!   token yields `active == false`.
//! * `integration_introspect_invalid_client_live` (INTR-005): a bad client
//!   secret surfaces a typed [`IdentityError::TokenEndpoint`] (`invalid_client`)
//!   — or, for providers with a non-RFC error body, an [`IdentityError::Http`]
//!   carrying the 4xx status.

use std::time::Duration;

use rs_identity_model::{DiscoveryClient, IdentityError, IntrospectionClient, TokenClient};

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
/// for this client, which is the only kind its introspection endpoint can look
/// up.
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

// INTR-001 / INTR-003 / INTR-006: mint an opaque token, resolve the endpoint
// from discovery, introspect it with the default client_secret_basic auth, and
// assert active=true with the client_id echoed back.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_introspect_active_live() {
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
    let Some(introspection_endpoint) = meta.introspection_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise introspection_endpoint");
        return;
    };
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );

    let token =
        mint_opaque_token(&meta.token_endpoint, &client_id, &client_secret, allow_http).await;

    let introspection = IntrospectionClient::builder()
        .client_id(&client_id)
        .client_secret(&client_secret)
        .introspection_endpoint(introspection_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build introspection client")
        .introspect(&token, Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("introspect active token against live provider: {e}"));

    assert!(
        introspection.active,
        "freshly minted token should be active: {introspection:?}"
    );
    assert_eq!(
        introspection.client_id.as_deref(),
        Some(client_id.as_str()),
        "introspection should echo the opaque client_id"
    );
}

// INTR-002: introspecting a token the provider has never issued yields
// active=false (probing an unknown token is not an error).
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_introspect_inactive_live() {
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
    let Some(introspection_endpoint) = meta.introspection_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise introspection_endpoint");
        return;
    };

    let introspection = IntrospectionClient::builder()
        .client_id(&client_id)
        .client_secret(&client_secret)
        .introspection_endpoint(introspection_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build introspection client")
        .introspect("this-token-was-never-issued", Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("introspect unknown token against live provider: {e}"));

    assert!(
        !introspection.active,
        "a never-issued token must be inactive: {introspection:?}"
    );
}

// INTR-005: a bad client secret produces a typed error from the live provider,
// exercising the real RFC 6749 §5.2 error path. node-oidc-provider returns a
// standard `invalid_client` error body -> TokenEndpoint; providers with a
// proprietary body surface as Http carrying the 4xx status.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_introspect_invalid_client_live() {
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
    let Some(introspection_endpoint) = meta.introspection_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise introspection_endpoint");
        return;
    };

    let err = IntrospectionClient::builder()
        .client_id(client_id)
        .client_secret("wrong-secret")
        .introspection_endpoint(introspection_endpoint)
        .allow_http(allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build introspection client")
        .introspect("any-token", None)
        .await
        .expect_err("bad client secret must fail introspection");

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
