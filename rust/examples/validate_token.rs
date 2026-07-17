//! Example: discover a provider, fetch its JWKS, and validate a JWT.
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS`
//! (the `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. The `jwks_uri` is resolved from
//! the discovery document, and the compact JWT to validate is read from the
//! `TOKEN` environment variable. An expected audience/issuer can be supplied via
//! `AUDIENCE` (the issuer defaults to the discovered one). Plain `http://`
//! issuers enable `allow_http` automatically for local development.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! # Acquire a token however your provider allows, then:
//! TOKEN=eyJ... AUDIENCE=my-api cd rust && cargo run --example validate_token
//! ```

use identity_model::{DiscoveryClient, JwksClient, ValidationOptions, validate_token_with_jwks};

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

    let token = match std::env::var("TOKEN") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            eprintln!("set TOKEN=<compact-jwt> to validate a token against {issuer}");
            return Ok(());
        }
    };

    let allow_http = issuer.starts_with("http://");

    println!("Discovering {issuer} ...");
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let meta = discovery.discover(&issuer).await?;
    println!("jwks_uri: {}", meta.jwks_uri);

    let jwks = JwksClient::builder().allow_http(allow_http).build();

    // Expect the discovered issuer; add an audience check when one is supplied.
    let mut builder = ValidationOptions::builder().issuer(&meta.issuer);
    if let Ok(audience) = std::env::var("AUDIENCE") {
        builder = builder.audience(audience);
    }
    let options = builder.build();

    match validate_token_with_jwks(token.trim(), &jwks, &meta.jwks_uri, &options).await {
        Ok(claims) => {
            println!("token is valid");
            println!("  iss = {:?}", claims.issuer);
            println!("  sub = {:?}", claims.subject);
            println!("  aud = {:?}", claims.audience.values());
            println!("  exp = {:?}", claims.expiry);
        }
        Err(e) => {
            eprintln!("token rejected: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
