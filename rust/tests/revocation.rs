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
//! ## Why these exist when the unit suite already covers REV-001..005
//!
//! The unit tests in `rust/src/revocation/mod.rs` drive a `wiremock` server, so
//! they prove the client's own behaviour — form encoding, the auth header,
//! status handling — against a server that answers however the test says. They
//! cannot prove the two things that actually matter here.
//!
//! **That the revocation took effect.** RFC 7009 §2.2 requires HTTP 200
//! regardless of outcome, so a 200 is not evidence. These tests mint an opaque
//! token, introspect it (`active: true`), revoke it, and introspect again
//! (`active: false`). That round trip is the only way to show the client sent
//! something the provider understood, and it needs two real endpoints.
//!
//! **That a real provider agrees with our reading of the spec.** A mock accepts
//! whatever we send. node-oidc-provider does not — it rejects a malformed
//! `token_type_hint`, enforces client auth, and decides for itself what an
//! unknown token means.
//!
//! Provider selection follows the shared `TEST_*` convention (the
//! `.env.node-oidc` profile the Makefile sources). `TEST_DISCO_ADDRESS` is the
//! full discovery-document URL; the issuer is that URL minus the
//! `/.well-known/openid-configuration` suffix, and `revocation_endpoint` is
//! resolved from the fetched discovery document (`REV-005`). If
//! `TEST_DISCO_ADDRESS` is unset the test skips rather than failing.
//!
//! Revocation is only meaningful for opaque tokens — a provider cannot revoke a
//! self-contained JWT it does not track — so, mirroring the introspection suite,
//! the subject token is minted from the `test-opaque` client, whose tokens
//! node-oidc-provider issues in opaque form.

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

/// Everything a revocation test needs from the live provider, resolved once.
struct Live {
    meta: rs_identity_model::ProviderMetadata,
    revocation_endpoint: String,
    client_id: String,
    client_secret: String,
    allow_http: bool,
}

/// Resolves the live profile, or returns `None` having already logged the skip.
async fn live_or_skip() -> Option<Live> {
    let issuer = issuer_from_env().or_else(|| {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        None
    })?;
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_OPAQUE_CLIENT_ID"),
        env_nonempty("TEST_OPAQUE_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_OPAQUE_CLIENT_ID/TEST_OPAQUE_CLIENT_SECRET unset for this profile");
        return None;
    };

    let allow_http = issuer.starts_with("http://");
    let meta = discover_or_skip(&issuer, allow_http).await?;

    // REV-005: the endpoint comes from the discovery document, never a constant.
    let Some(revocation_endpoint) = meta.revocation_endpoint.clone() else {
        skip_or_fail("discovery document does not advertise revocation_endpoint");
        return None;
    };
    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );

    Some(Live {
        meta,
        revocation_endpoint,
        client_id,
        client_secret,
        allow_http,
    })
}

/// Mints an opaque access token from the `test-opaque` client via the
/// client-credentials grant. node-oidc-provider issues opaque (non-JWT) tokens
/// for this client, which is the only kind its revocation endpoint can look up.
async fn mint_opaque_token(live: &Live) -> String {
    let client = TokenClient::builder()
        .client_id(&live.client_id)
        .client_secret(&live.client_secret)
        .token_endpoint(&live.meta.token_endpoint)
        .allow_http(live.allow_http)
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

/// Asks the live provider whether a token is active. Used to prove a revocation
/// actually landed, since the revocation response itself cannot say so.
async fn is_active(live: &Live, token: &str) -> bool {
    let endpoint = live
        .meta
        .introspection_endpoint
        .clone()
        .expect("fixture advertises introspection_endpoint");
    IntrospectionClient::builder()
        .client_id(&live.client_id)
        .client_secret(&live.client_secret)
        .introspection_endpoint(endpoint)
        .allow_http(live.allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build introspection client")
        .introspect(token, Some("access_token"))
        .await
        .unwrap_or_else(|e| panic!("introspect against live provider: {e}"))
        .active
}

fn revocation_client(live: &Live) -> RevocationClient {
    RevocationClient::builder()
        .client_id(&live.client_id)
        .client_secret(&live.client_secret)
        .revocation_endpoint(&live.revocation_endpoint)
        .allow_http(live.allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build revocation client")
}

// REV-001 / REV-005: the endpoint is resolved from discovery, and the revocation
// demonstrably takes effect — active before, inactive after. This is the test
// the unit suite cannot write: RFC 7009 §2.2 makes the response itself carry no
// information, so the only proof is asking a second endpoint.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_opaque_token_takes_effect_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };

    let token = mint_opaque_token(&live).await;
    assert!(
        is_active(&live, &token).await,
        "freshly minted token should be active before revocation"
    );

    revocation_client(&live)
        .revoke(&token, Some("access_token"))
        .await
        .expect("revoke a valid token against the live provider");

    assert!(
        !is_active(&live, &token).await,
        "token still active after revocation — the request reached the provider but did not revoke"
    );
}

// REV-001, the privacy property, against a real provider: revoking a token that
// never existed must be indistinguishable from revoking a live one. If a
// provider or our client ever started differentiating, the endpoint would become
// a token-scanning oracle.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_is_indistinguishable_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };
    let client = revocation_client(&live);

    let live_token = mint_opaque_token(&live).await;
    client
        .revoke(&live_token, Some("access_token"))
        .await
        .expect("revoking a live token succeeds");

    // Already revoked (RFC 7009 §2.2 explicitly requires this to succeed).
    client
        .revoke(&live_token, Some("access_token"))
        .await
        .expect("revoking an already-revoked token must also succeed");

    // Never issued by anyone.
    client
        .revoke("this-token-was-never-issued", Some("access_token"))
        .await
        .expect("revoking an unknown token must succeed identically");
}

// REV-002: the hint is accepted by a real provider, and a *wrong* hint does not
// fail the request — the server may use it to optimise lookup but MUST NOT
// reject on it. A mock cannot prove the provider honours that.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_tolerates_wrong_hint_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };

    let token = mint_opaque_token(&live).await;
    // Deliberately the wrong kind: this is an access token.
    revocation_client(&live)
        .revoke(&token, Some("refresh_token"))
        .await
        .expect("an incorrect token_type_hint must not fail the request");

    assert!(
        !is_active(&live, &token).await,
        "provider should still have revoked the token despite the wrong hint"
    );
}

// REV-002: omitting the hint entirely is valid — it is an OPTIONAL parameter.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_without_hint_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };

    let token = mint_opaque_token(&live).await;
    revocation_client(&live)
        .revoke(&token, None)
        .await
        .expect("revocation without a token_type_hint succeeds");

    assert!(!is_active(&live, &token).await, "token should be revoked");
}

// REV-004: bad client credentials surface as a typed error rather than a silent
// success. Getting this wrong would be the worst failure mode available here —
// the caller believes a token is dead while the provider never authenticated the
// request and left it live.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_revoke_invalid_client_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };

    let token = mint_opaque_token(&live).await;

    let err = RevocationClient::builder()
        .client_id(&live.client_id)
        .client_secret("wrong-secret")
        .revocation_endpoint(&live.revocation_endpoint)
        .allow_http(live.allow_http)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build revocation client")
        .revoke(&token, Some("access_token"))
        .await
        .expect_err("a bad client secret must not report success");

    // Providers differ on the error body: an RFC-shaped one yields a typed
    // TokenEndpoint error, a non-RFC one a transport error carrying the status.
    match &err {
        IdentityError::TokenEndpoint { error, status, .. } => {
            assert_eq!(error, "invalid_client", "unexpected OAuth error code");
            assert!(
                (400..500).contains(&(*status as u32)),
                "expected a 4xx, got {status}"
            );
        }
        IdentityError::Http(msg) => {
            assert!(
                msg.contains("40"),
                "expected a 4xx in the transport error, got: {msg}"
            );
        }
        other => panic!("expected a client-auth failure, got {other:?}"),
    }

    // The token must still be live: the request was rejected, not honoured.
    assert!(
        is_active(&live, &token).await,
        "token was revoked despite failed client authentication"
    );
}
