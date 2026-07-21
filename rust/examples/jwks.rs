//! Example: fetch a provider's JWK Set, list its key IDs, and resolve one.
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS`
//! (the `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. The `jwks_uri` is resolved from
//! the discovery document. Plain `http://` issuers enable `allow_http`
//! automatically for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example jwks
//! # or point it anywhere:
//! ISSUER=https://accounts.google.com cargo run --example jwks
//! ```

use identity_model::{DiscoveryClient, JwksClient};

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
        .unwrap_or_else(|| "https://accounts.google.com".to_string());

    let allow_http = issuer.starts_with("http://");

    println!("Discovering {issuer} ...");
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let meta = discovery.discover(&issuer).await?;
    println!("jwks_uri: {}", meta.jwks_uri);

    let jwks = JwksClient::builder().allow_http(allow_http).build();
    let set = jwks.fetch(&meta.jwks_uri).await?;

    println!("fetched {} key(s):", set.keys().len());
    for key in set.keys() {
        let kid = if key.kid.is_empty() {
            "<none>"
        } else {
            &key.kid
        };
        println!(
            "  kid={kid:<24} kty={:<4} use={} alg={}",
            key.kty, key.use_, key.alg
        );
    }

    // Resolve the first key that publishes a kid.
    if let Some(first) = set.keys().iter().find(|k| !k.kid.is_empty()) {
        let resolved = jwks.resolve_key(&meta.jwks_uri, &first.kid).await?;
        println!("resolved kid={} (kty={})", resolved.kid, resolved.kty);
    }

    Ok(())
}
