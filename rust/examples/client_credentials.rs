//! Example: discover a provider, then acquire a client credentials token.
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS`
//! (the `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. The `token_endpoint` is resolved
//! from the discovery document. Credentials come from `TEST_CLIENT_ID` /
//! `TEST_CLIENT_SECRET` and the optional scope from `TEST_SCOPE`. Plain
//! `http://` endpoints enable `allow_http` automatically for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example client_credentials
//! ```

use identity_model::{DiscoveryClient, TokenClient};

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
            eprintln!("set TEST_CLIENT_ID and TEST_CLIENT_SECRET to acquire a token from {issuer}");
            return Ok(());
        }
    };
    let scope = std::env::var("TEST_SCOPE").ok().filter(|s| !s.is_empty());

    let allow_http = issuer.starts_with("http://");

    // Resolve the token endpoint from discovery.
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;
    println!("token_endpoint = {}", metadata.token_endpoint);

    // Configure the token client and acquire a token.
    let client = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(metadata.token_endpoint)
        .allow_http(allow_http)
        .build()?;

    let token = client.client_credentials(scope.as_deref()).await?;
    println!("access_token = {}", token.access_token);
    println!("token_type   = {}", token.token_type);
    println!("expires_in   = {}s", token.expires_in);

    Ok(())
}
