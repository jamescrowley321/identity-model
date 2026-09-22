//! Live integration tests for DPoP (RFC 9449) against a real provider.
//!
//! `#[ignore]`-gated so a bare `cargo test` (no provider up) stays green. The
//! `integration-tests-rust` CI job boots the local `infra/` node-oidc-provider
//! (`:9010`, `dPoP: { enabled: true }`, `dPoPSigningAlgValues: ["RS256",
//! "ES256"]`), runs the unit suite, then runs these with
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
//! ## Why these exist when `tests/dpop.rs` already covers DPOP-001..008
//!
//! The offline suite proves this crate is self-consistent: a proof it generates
//! is one it verifies, against claims it chose. Every assertion there is
//! ultimately about our own reading of RFC 9449. Two things only a real
//! authorization server can establish:
//!
//! **That a provider accepts the proof we emit.** `htu` normalisation, the
//! `typ: dpop+jwt` header, the embedded `jwk`, the `alg`/key-type pairing — a
//! mistake in any of them is invisible to a suite that both writes and reads
//! the proof. node-oidc-provider validates all of it independently and issues
//! `invalid_dpop_proof` when it disagrees.
//!
//! **That the binding actually happened.** The point of DPoP is `cnf.jkt` in
//! the issued token (RFC 9449 §6). Only the provider can put it there, and the
//! only proof that our RFC 7638 thumbprint is computed the way the rest of the
//! world computes it is that the value it independently derived from our
//! embedded `jwk` matches ours byte for byte. A mock cannot disagree with us;
//! a provider can.
//!
//! Provider selection follows the shared `TEST_*` convention (the
//! `.env.node-oidc` profile the Makefile sources). `TEST_DISCO_ADDRESS` is the
//! full discovery-document URL; the issuer is that URL minus the
//! `/.well-known/openid-configuration` suffix. A provider whose discovery
//! document does not advertise `dpop_signing_alg_values_supported` has the
//! feature switched off, so the suite skips rather than fails — keeping the
//! Keycloak/IdentityServer/Descope profiles green.
//!
//! The `test-client-credentials` client is used because node-oidc-provider
//! issues it a JWT access token (via the `urn:test:api` default resource),
//! which is what makes `cnf.jkt` readable; the `test-opaque` client's tokens
//! carry the same binding but expose nothing to inspect.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use rs_identity_model::{
    DiscoveryClient, DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, IdentityError,
    JwksClient, ProviderMetadata, TokenClient, ValidationOptions, verify_proof,
};

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

/// The discovery member whose presence means the provider has DPoP enabled.
const DPOP_ALGS_METADATA: &str = "dpop_signing_alg_values_supported";

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

/// Everything a DPoP test needs from the live provider, resolved once.
struct Live {
    meta: ProviderMetadata,
    client_id: String,
    client_secret: String,
    allow_http: bool,
    /// The proof algorithms the provider advertises, intersected with the two
    /// this crate implements. Never empty — an empty intersection skips.
    algorithms: Vec<DpopAlgorithm>,
}

/// Resolves the live profile, or returns `None` having already logged the skip.
async fn live_or_skip() -> Option<Live> {
    let issuer = issuer_from_env().or_else(|| {
        skip_or_fail("TEST_DISCO_ADDRESS unset; run `make infra-up` and source .env.node-oidc");
        None
    })?;
    let (Some(client_id), Some(client_secret)) = (
        env_nonempty("TEST_CLIENT_ID"),
        env_nonempty("TEST_CLIENT_SECRET"),
    ) else {
        skip_or_fail("TEST_CLIENT_ID/TEST_CLIENT_SECRET unset for this profile");
        return None;
    };

    // Case-insensitive: the client's own scheme gate lowercases, and a merely
    // capitalised TEST_DISCO_ADDRESS should not silently skip the whole suite.
    let allow_http = issuer.to_ascii_lowercase().starts_with("http://");
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
            return None;
        }
    };

    // The capability gate: a provider with DPoP switched off advertises nothing,
    // and every profile that does not support it skips here rather than failing.
    let Some(advertised) = meta.extra.get(DPOP_ALGS_METADATA) else {
        skip_or_fail(&format!(
            "discovery document does not advertise {DPOP_ALGS_METADATA}; DPoP not enabled"
        ));
        return None;
    };
    let advertised: Vec<String> = advertised
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let algorithms: Vec<DpopAlgorithm> = [DpopAlgorithm::Es256, DpopAlgorithm::Rs256]
        .into_iter()
        .filter(|alg| advertised.iter().any(|a| a == alg.as_str()))
        .collect();
    if algorithms.is_empty() {
        skip_or_fail(&format!(
            "provider advertises {DPOP_ALGS_METADATA}={advertised:?}, none of which this crate implements"
        ));
        return None;
    }

    assert!(
        !meta.token_endpoint.is_empty(),
        "discovery returned empty token_endpoint"
    );
    assert!(
        !meta.jwks_uri.is_empty(),
        "discovery returned empty jwks_uri"
    );

    Some(Live {
        meta,
        client_id,
        client_secret,
        allow_http,
        algorithms,
    })
}

/// Requests a client-credentials token with `proof` attached in the `DPoP`
/// header (RFC 9449 §5).
///
/// The crate does not yet attach the header itself (#573), so the proof rides on
/// a `reqwest::Client` built for this one request and handed to [`TokenClient`]
/// — which keeps the request on the crate's own token-client path rather than
/// hand-rolling the form encoding and client authentication here.
async fn token_request_with_proof(
    live: &Live,
    proof: &str,
) -> rs_identity_model::Result<rs_identity_model::TokenResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(
        "DPoP",
        HeaderValue::from_str(proof).expect("a compact JWS is a valid header value"),
    );
    // Start from the crate's hardened builder, not a bare `reqwest::Client`.
    // `http_client` REPLACES the default client, so building one from scratch
    // would drop the https -> http redirect refusal on the one request that
    // carries the client secret.
    let http = rs_identity_model::secure_client_builder()
        .default_headers(headers)
        .build()
        .expect("build DPoP-carrying HTTP client");

    TokenClient::builder()
        .client_id(&live.client_id)
        .client_secret(&live.client_secret)
        .token_endpoint(&live.meta.token_endpoint)
        .allow_http(live.allow_http)
        .timeout(Duration::from_secs(5))
        .http_client(http)
        .build()
        .expect("build token client")
        .client_credentials(env_nonempty("TEST_SCOPE").as_deref())
        .await
}

/// Validates `token` against the live JWKS and returns its claims, so `cnf` is
/// read from a token whose signature was actually checked.
async fn validated_claims(live: &Live, token: &str) -> rs_identity_model::Claims {
    let jwks = JwksClient::builder()
        .allow_http(live.allow_http)
        .timeout(Duration::from_secs(5))
        .build();
    let options = ValidationOptions::builder()
        .issuer(live.meta.issuer.as_str())
        .build();
    rs_identity_model::validate_token_with_jwks(token, &jwks, &live.meta.jwks_uri, &options)
        .await
        .unwrap_or_else(|e| panic!("validate the DPoP-bound access token: {e}"))
}

/// Reads `cnf.jkt` from a validated claim set, failing with the claim's actual
/// shape rather than an unwrap panic.
fn cnf_jkt(claims: &rs_identity_model::Claims) -> String {
    let cnf = claims
        .extra
        .get("cnf")
        .unwrap_or_else(|| panic!("access token carries no cnf claim — it was not DPoP-bound"));
    cnf.get("jkt")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("cnf claim has no string jkt member: {cnf}"))
        .to_string()
}

// DPOP-001 / DPOP-005 / DPOP-007, live: a proof this crate generates is accepted
// by a real authorization server, and the token it issues is bound to our key —
// `token_type: DPoP` and a `cnf.jkt` equal to our RFC 7638 thumbprint.
//
// Run for every algorithm the provider and this crate both support, because the
// `alg`-to-key-type pairing is exactly the kind of mistake a self-consistent
// offline suite cannot catch.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_dpop_bound_client_credentials_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };

    for algorithm in &live.algorithms {
        let key = DpopKey::generate(*algorithm)
            .unwrap_or_else(|e| panic!("generate {algorithm} DPoP key: {e}"));
        let proof = key
            .proof("POST", &live.meta.token_endpoint, &DpopProofOptions::new())
            .unwrap_or_else(|e| panic!("generate {algorithm} proof: {e}"));

        let resp = token_request_with_proof(&live, &proof)
            .await
            .unwrap_or_else(|e| {
                panic!("provider rejected the {algorithm} proof this crate generated: {e}")
            });

        // RFC 9449 §5: a bound token is issued as token_type DPoP, not Bearer.
        // The value is case-insensitive per RFC 6749 §5.1.
        assert!(
            resp.token_type.eq_ignore_ascii_case("DPoP"),
            "token_type = {:?}, want DPoP — the proof was accepted but the token is not bound",
            resp.token_type
        );
        assert!(!resp.access_token.is_empty(), "empty access_token issued");

        // RFC 9449 §6: the binding is cnf.jkt, and it must be the thumbprint we
        // computed — the provider derived its copy independently from the jwk we
        // embedded in the proof header.
        let claims = validated_claims(&live, &resp.access_token).await;
        let expected = key.thumbprint().expect("thumbprint the generated key");
        assert_eq!(
            cnf_jkt(&claims),
            expected,
            "cnf.jkt does not match our RFC 7638 thumbprint for the {algorithm} key"
        );
    }
}

// The negative control for the test above: without this, a provider that
// ignored the DPoP header entirely would still let the happy path pass on a
// `token_type` it happened to return. A proof whose `htm`/`htu` do not describe
// the request it accompanies must be refused (RFC 9449 §4.3), which is only
// true if the provider is reading the proof at all.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_dpop_mismatched_proof_is_rejected_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };
    let key = DpopKey::generate(live.algorithms[0]).expect("generate DPoP key");

    // Bound to a different resource than the one it is sent to.
    let wrong_htu = key
        .proof(
            "POST",
            "https://not-the-token-endpoint.example/token",
            &DpopProofOptions::new(),
        )
        .expect("generate proof for the wrong htu");
    let err = token_request_with_proof(&live, &wrong_htu)
        .await
        .expect_err("a proof bound to another URL must be refused");
    assert_dpop_rejection(&err, "htu");

    // Bound to a different method than the one it is sent with.
    let wrong_htm = key
        .proof("GET", &live.meta.token_endpoint, &DpopProofOptions::new())
        .expect("generate proof for the wrong htm");
    let err = token_request_with_proof(&live, &wrong_htm)
        .await
        .expect_err("a proof bound to another method must be refused");
    assert_dpop_rejection(&err, "htm");
}

/// Asserts the provider refused a request for the DPoP proof specifically, not
/// for some unrelated reason (bad credentials, a 500) that would make the
/// negative control pass vacuously.
fn assert_dpop_rejection(err: &IdentityError, what: &str) {
    match err {
        IdentityError::TokenEndpoint { error, status, .. } => {
            assert_eq!(
                error, "invalid_dpop_proof",
                "wrong {what} rejected as {error:?} (HTTP {status}), want invalid_dpop_proof"
            );
        }
        other => panic!("wrong {what} produced {other:?}, want a TokenEndpoint error"),
    }
}

// DPOP-008, live: the `ath` binding computed over a real provider-issued access
// token round-trips through this crate's resource-server verifier, and the
// thumbprint that verifier reports is the one the provider put in `cnf.jkt`.
//
// This is the join the offline suite cannot make. `tests/dpop.rs` verifies
// proofs over tokens it invented; here the token is one the provider minted and
// bound, so a resource server following RFC 9449 §7 — compare the verified
// proof's thumbprint against the token's `cnf.jkt`, then its `ath` against the
// presented token — is exercised against real material end to end.
#[tokio::test]
#[ignore = "requires a running OIDC provider (make infra-up); run via cargo test -- --ignored"]
async fn integration_dpop_ath_binds_a_live_token_live() {
    let Some(live) = live_or_skip().await else {
        return;
    };
    let key = DpopKey::generate(live.algorithms[0]).expect("generate DPoP key");
    let proof = key
        .proof("POST", &live.meta.token_endpoint, &DpopProofOptions::new())
        .expect("generate proof");
    let resp = token_request_with_proof(&live, &proof)
        .await
        .expect("mint a DPoP-bound token");

    let claims = validated_claims(&live, &resp.access_token).await;
    let bound_to = cnf_jkt(&claims);

    // The §7 resource-request proof: same key, the resource server's method and
    // URI, plus ath over the token being presented.
    let resource_uri = live
        .meta
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| live.meta.issuer.clone());
    let resource_proof = key
        .proof(
            "GET",
            &resource_uri,
            &DpopProofOptions::new().access_token(&resp.access_token),
        )
        .expect("generate a resource-request proof");

    let verified = verify_proof(
        &resource_proof,
        "GET",
        &resource_uri,
        &DpopVerifyOptions::new().access_token(&resp.access_token),
    )
    .expect("this crate must verify the proof it just generated");

    // The RS-side check RFC 9449 §7 requires: the proof's key is the key the
    // token was bound to. Both values crossed the wire independently — ours in
    // the proof's jwk header, the provider's in cnf.jkt.
    assert_eq!(
        verified.thumbprint, bound_to,
        "verified proof thumbprint does not match the live token's cnf.jkt"
    );
}
