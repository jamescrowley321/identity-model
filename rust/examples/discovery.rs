//! Example: fetch and print OIDC provider metadata via [`DiscoveryClient`].
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS`
//! (the `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. Plain `http://` issuers enable
//! `allow_http` automatically for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example discovery
//! # or point it anywhere:
//! ISSUER=https://accounts.google.com cargo run --example discovery
//! ```

use identity_model::DiscoveryClient;

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
    let client = DiscoveryClient::builder().allow_http(allow_http).build();

    println!("Discovering {issuer} ...");
    let meta = client.discover(&issuer).await?;

    println!("issuer:                 {}", meta.issuer);
    println!("authorization_endpoint: {}", meta.authorization_endpoint);
    println!("token_endpoint:         {}", meta.token_endpoint);
    println!("jwks_uri:               {}", meta.jwks_uri);
    if let Some(userinfo) = &meta.userinfo_endpoint {
        println!("userinfo_endpoint:      {userinfo}");
    }
    println!(
        "id_token_signing_algs:  {}",
        meta.id_token_signing_alg_values_supported.join(", ")
    );

    Ok(())
}
