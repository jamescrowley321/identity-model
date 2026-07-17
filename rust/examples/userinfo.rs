//! Example: acquire a token, then fetch and validate the UserInfo response.
//!
//! The issuer is taken from `ISSUER`, or derived from `TEST_DISCO_ADDRESS`
//! (the `.env.node-oidc` profile) by trimming the
//! `/.well-known/openid-configuration` suffix. The `userinfo_endpoint` is
//! resolved from the discovery document. Credentials come from `TEST_CLIENT_ID`
//! / `TEST_CLIENT_SECRET` and the optional scope from `TEST_SCOPE`. Plain
//! `http://` endpoints enable `allow_http` automatically for local development.
//!
//! Note: a `client_credentials` access token has no end-user subject, so the
//! provider may reject it at the UserInfo endpoint. The example prints whatever
//! the endpoint returns — claims or a typed error — to demonstrate the flow.
//!
//! ```text
//! make infra-up
//! set -a && . ./.env.node-oidc && set +a
//! cd rust && cargo run --example userinfo
//! ```

use identity_model::{DiscoveryClient, TokenClient, UserInfoClient};

const WELL_KNOWN_SUFFIX: &str = "/.well-known/openid-configuration";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = std::env::var("ISSUER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DISCO_ADDRESS")
                .ok()
                .filter(|d| !d.trim().is_empty())
                .map(|d| {
                    let base = d.strip_suffix(WELL_KNOWN_SUFFIX).unwrap_or(&d);
                    base.trim_end_matches('/').to_string()
                })
        })
        .unwrap_or_else(|| "https://accounts.example.com".to_string());

    let (client_id, client_secret) = match (
        std::env::var("TEST_CLIENT_ID"),
        std::env::var("TEST_CLIENT_SECRET"),
    ) {
        (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => (id, secret),
        _ => {
            eprintln!("set TEST_CLIENT_ID and TEST_CLIENT_SECRET to run against {issuer}");
            return Ok(());
        }
    };
    let scope = std::env::var("TEST_SCOPE").ok().filter(|s| !s.is_empty());
    let allow_http = issuer.starts_with("http://");

    // Resolve the userinfo endpoint from discovery.
    let discovery = DiscoveryClient::builder().allow_http(allow_http).build();
    let metadata = discovery.discover(&issuer).await?;
    let userinfo_endpoint = match metadata.userinfo_endpoint {
        Some(endpoint) => endpoint,
        None => {
            eprintln!("provider does not advertise a userinfo_endpoint");
            return Ok(());
        }
    };
    println!("userinfo_endpoint = {userinfo_endpoint}");

    // Acquire an access token.
    let token = TokenClient::builder()
        .client_id(client_id)
        .client_secret(client_secret)
        .token_endpoint(metadata.token_endpoint)
        .allow_http(allow_http)
        .build()?
        .client_credentials(scope.as_deref())
        .await?;
    println!("acquired access_token ({} bytes)", token.access_token.len());

    // Fetch the UserInfo claims and print the standard ones.
    let userinfo_client = UserInfoClient::builder()
        .userinfo_endpoint(userinfo_endpoint)
        .allow_http(allow_http)
        .build()?;

    match userinfo_client.fetch(&token.access_token).await {
        Ok(claims) => {
            println!("sub               = {}", claims.sub);
            println!("name              = {:?}", claims.name);
            println!("email             = {:?}", claims.email);
            println!("email_verified    = {:?}", claims.email_verified);
            println!("preferred_username= {:?}", claims.preferred_username);
            println!(
                "additional claims = {:?}",
                claims.claims().keys().collect::<Vec<_>>()
            );

            // Subject consistency (OIDC Core 1.0 §5.3.2): in a real flow the
            // expected `sub` comes from the *validated ID token*, and a UserInfo
            // response carrying a different `sub` must be rejected as a subject
            // substitution. Demonstrate the guard actually firing by asking for a
            // `sub` that cannot match — a genuine match check would be tautological
            // against the value we just fetched.
            let wrong_expected = format!("{}-tampered", claims.sub);
            match userinfo_client
                .fetch_with_subject(&token.access_token, &wrong_expected)
                .await
            {
                Ok(_) => println!("sub mismatch guard= UNEXPECTED match (guard did not fire)"),
                Err(e) => println!("sub mismatch guard= rejected as expected ({e})"),
            }
        }
        Err(e) => {
            // A client_credentials token has no end-user subject; the provider
            // may reject it here. That is expected for this demo.
            println!("userinfo error    = {e}");
        }
    }

    Ok(())
}
