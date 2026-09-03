//! Example: discover a provider, mint an opaque token, then introspect it
//! (RFC 7662).
//!
//! The `introspection_endpoint` is resolved from the discovery document. The
//! issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS` (the
//! `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. Credentials come from
//! `TEST_CLIENT_ID` / `TEST_CLIENT_SECRET`, and the optional token scope from
//! `TEST_SCOPE`. Introspection is only meaningful for opaque tokens, so the
//! example mints one via `client_credentials` and introspects it, then
//! introspects a bogus token to show the inactive path. Plain `http://`
//! endpoints enable `allow_http` automatically for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example introspection
//! ```

use rs_identity_model::{DiscoveryClient, Introspection, IntrospectionClient, TokenClient};

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
            eprintln!(
                "set TEST_CLIENT_ID and TEST_CLIENT_SECRET to introspect a token from {issuer}"
            );
            return Ok(());
        }
    };
    let scope = std::env::var("TEST_SCOPE").ok().filter(|s| !s.is_empty());

    let allow_http = issuer.starts_with("http://");

    // Resolve the token and introspection endpoints from discovery (INTR-006).
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;
    let Some(introspection_endpoint) = metadata.introspection_endpoint.clone() else {
        eprintln!("provider {issuer} advertises no introspection_endpoint");
        return Ok(());
    };
    println!("introspection_endpoint = {introspection_endpoint}");

    // Mint an opaque access token to introspect. Introspection is only
    // meaningful for opaque tokens, so an issuer that returns a JWT here still
    // demonstrates the request/response shape.
    let token_client = TokenClient::builder()
        .client_id(client_id.clone())
        .client_secret(client_secret.clone())
        .token_endpoint(metadata.token_endpoint)
        .allow_http(allow_http)
        .build()?;
    let token = token_client.client_credentials(scope.as_deref()).await?;

    let introspector = IntrospectionClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .introspection_endpoint(introspection_endpoint)
        .allow_http(allow_http)
        .build()?;

    println!("\nIntrospecting the freshly minted token:");
    let active = introspector
        .introspect(&token.access_token, Some("access_token"))
        .await?;
    print_result(&active);

    // A bogus token demonstrates the inactive path: RFC 7662 §2.2 guarantees
    // only `active`, which is false, with no other members.
    println!("\nIntrospecting a bogus token:");
    let inactive = introspector.introspect("not-a-real-token", None).await?;
    print_result(&inactive);

    Ok(())
}

fn print_result(r: &Introspection) {
    println!("active: {}", r.active);
    if !r.active {
        // RFC 7662 §2.2: no other members are guaranteed when active is false.
        return;
    }
    if let Some(scope) = &r.scope {
        println!("scope:  {scope}");
    }
    if let Some(client_id) = &r.client_id {
        println!("client: {client_id}");
    }
    if let Some(sub) = &r.sub {
        println!("sub:    {sub}");
    }
    if !r.extra.is_empty() {
        println!("extra provider members: {:?}", r.extra);
    }
}
