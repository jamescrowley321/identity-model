//! Example: mint a DPoP-bound access token (RFC 9449), then build the proof a
//! resource server would verify.
//!
//! DPoP sender-constrains a token to a key the client holds, so a stolen token
//! is useless without the private half. The flow has three moves:
//!
//! 1. generate a key pair and sign a proof for the token request;
//! 2. send the proof in the `DPoP` header — the authorization server returns
//!    `token_type: DPoP` and binds the token to the key's RFC 7638 thumbprint
//!    in `cnf.jkt`;
//! 3. for each resource request, sign a fresh proof carrying `ath` (the hash of
//!    the access token) and present the token as `Authorization: DPoP <token>`.
//!
//! The library does not attach the header for you yet
//! ([#573](https://github.com/jamescrowley321/identity-model/issues/573)), so
//! this example shows the two lines that do it — which is the whole of what the
//! forthcoming transport will automate.
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS` (the
//! `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. Credentials come from
//! `TEST_CLIENT_ID` / `TEST_CLIENT_SECRET`, and the optional token scope from
//! `TEST_SCOPE`. Plain `http://` endpoints enable `allow_http` automatically
//! for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example dpop
//! ```

use reqwest::header::{HeaderMap, HeaderValue};
use rs_identity_model::{
    DiscoveryClient, DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, TokenClient,
    dpop_ath, verify_proof,
};

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = std::env::var("ISSUER")
        .ok()
        .or_else(|| {
            std::env::var("TEST_DISCO_ADDRESS").ok().map(|d| {
                d.trim_end_matches(WELL_KNOWN_SUFFIX)
                    .trim_end_matches('/')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "https://accounts.example.com".to_string());

    let (client_id, client_secret) = match (
        std::env::var("TEST_CLIENT_ID"),
        std::env::var("TEST_CLIENT_SECRET"),
    ) {
        (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => (id, secret),
        _ => {
            eprintln!("set TEST_CLIENT_ID and TEST_CLIENT_SECRET to mint a token from {issuer}");
            return Ok(());
        }
    };
    let scope = std::env::var("TEST_SCOPE").ok().filter(|s| !s.is_empty());
    let allow_http = issuer.starts_with("http://");

    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;

    // DPoP is optional, and a provider that supports it says so in discovery.
    // Sending a proof to one that does not simply leaves the token unbound, so
    // check before relying on the binding.
    match metadata.extra.get("dpop_signing_alg_values_supported") {
        Some(algs) => println!("provider supports DPoP proofs signed with {algs}"),
        None => {
            eprintln!("provider {issuer} does not advertise DPoP support");
            return Ok(());
        }
    }

    // 1. The key pair. Generated here for one run; a real client persists it
    //    (`to_pkcs8_pem` / `from_pkcs8_pem`) so restarts do not invalidate
    //    tokens already bound to it.
    let key = DpopKey::generate(DpopAlgorithm::Es256)?;
    let thumbprint = key.thumbprint()?;
    println!("key thumbprint (jkt) = {thumbprint}");

    // 2. The token-request proof. It covers the method and URI of the request
    //    it accompanies, and carries no `ath` — there is no access token yet.
    let proof = key.proof("POST", &metadata.token_endpoint, &DpopProofOptions::new())?;

    // This is the part the library does not do for you yet: put the proof in
    // the `DPoP` header of the token request. A client built per request keeps
    // each proof with the single request it was signed for.
    let mut headers = HeaderMap::new();
    headers.insert("DPoP", HeaderValue::from_str(&proof)?);
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let token = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(&metadata.token_endpoint)
        .allow_http(allow_http)
        .http_client(http)
        .build()?
        .client_credentials(scope.as_deref())
        .await?;

    // RFC 9449 §5: a bound token comes back as `DPoP`, not `Bearer`. A `Bearer`
    // here means the proof was ignored and the token is NOT sender-constrained.
    println!("token_type = {}", token.token_type);
    if !token.token_type.eq_ignore_ascii_case("DPoP") {
        eprintln!("provider did not bind the token — it is an ordinary bearer token");
        return Ok(());
    }

    // 3. The resource-request proof: same key, the resource server's method and
    //    URI, plus `ath` binding it to this specific access token (§7).
    let resource_uri = metadata
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| format!("{issuer}/resource"));
    println!("ath = {}", dpop_ath(&token.access_token));
    let resource_proof = key.proof(
        "GET",
        &resource_uri,
        &DpopProofOptions::new().access_token(&token.access_token),
    )?;

    println!("\nSend the protected-resource request as:");
    println!("  GET {resource_uri}");
    println!("  Authorization: DPoP {}", token.access_token);
    println!("  DPoP: {resource_proof}");

    // The other side of the wire, shown here so the check a resource server
    // owes is explicit. Verifying the proof is necessary but NOT sufficient:
    // the server must also confirm the proof's key is the key the token was
    // bound to, by comparing this thumbprint against the token's `cnf.jkt`.
    let verified = verify_proof(
        &resource_proof,
        "GET",
        &resource_uri,
        &DpopVerifyOptions::new().access_token(&token.access_token),
    )?;
    println!("\nresource server verified the proof:");
    println!("  jti        = {}", verified.jti);
    println!("  thumbprint = {}", verified.thumbprint);
    println!(
        "  binding    = {}",
        if verified.thumbprint == thumbprint {
            "matches the key the token was bound to"
        } else {
            "MISMATCH — reject the request"
        }
    );

    Ok(())
}
