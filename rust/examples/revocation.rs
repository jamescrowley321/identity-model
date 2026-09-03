//! Example: discover a provider, mint an opaque token, then revoke it during
//! logout (RFC 7009).
//!
//! The `revocation_endpoint` is resolved from the discovery document. The issuer
//! is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS` (the
//! `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. Credentials come from
//! `TEST_CLIENT_ID` / `TEST_CLIENT_SECRET`, and the optional token scope from
//! `TEST_SCOPE`. Revocation is only meaningful for opaque tokens, so the example
//! mints one via `client_credentials` and revokes it — as an app would revoke a
//! refresh token during logout — then revokes a bogus token to show that an
//! unknown/already-invalid token also succeeds (§2.1). Plain `http://` endpoints
//! enable `allow_http` automatically for local development. No token or secret is
//! printed.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example revocation
//! ```

use rs_identity_model::{DiscoveryClient, RevocationClient, TokenClient};

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
            eprintln!("set TEST_CLIENT_ID and TEST_CLIENT_SECRET to revoke a token from {issuer}");
            return Ok(());
        }
    };
    let scope = std::env::var("TEST_SCOPE").ok().filter(|s| !s.is_empty());

    let allow_http = issuer.starts_with("http://");

    // Resolve the token and revocation endpoints from discovery (REV-005).
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;
    let Some(revocation_endpoint) = metadata.revocation_endpoint.clone() else {
        eprintln!("provider {issuer} advertises no revocation_endpoint");
        return Ok(());
    };
    println!("revocation_endpoint = {revocation_endpoint}");

    // Mint an opaque access token to revoke. Revocation is only meaningful for
    // opaque tokens the server tracks; a self-contained JWT still demonstrates
    // the request shape.
    let token_client = TokenClient::builder()
        .client_id(client_id.clone())
        .client_secret(client_secret.clone())
        .token_endpoint(metadata.token_endpoint)
        .allow_http(allow_http)
        .build()?;
    let token = token_client.client_credentials(scope.as_deref()).await?;

    let revoker = RevocationClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .revocation_endpoint(revocation_endpoint)
        .allow_http(allow_http)
        .build()?;

    // Revoke the freshly minted token — the shape an app uses to revoke a refresh
    // token during logout.
    revoker
        .revoke(&token.access_token, Some("access_token"))
        .await?;
    println!("revoked the freshly minted token");

    // Revoking a bogus token also succeeds: RFC 7009 §2.1 requires the server to
    // return success regardless of token validity so state cannot be probed.
    revoker.revoke("not-a-real-token", None).await?;
    println!("revoking an unknown token also succeeded (no scanning oracle)");

    Ok(())
}
