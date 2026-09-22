//! Talking to the provider that [`super::env`] selected.

use std::time::Duration;

use rs_identity_model::{DiscoveryClient, ProviderMetadata};
use serde_json::Value;

use super::env::{env_nonempty, skip_or_fail};

/// Discovers the live provider's metadata, skipping (see
/// [`skip_or_fail`]) when it is unreachable so a missing local stack does not
/// fail CI-less runs.
pub async fn discover_or_skip(issuer: &str, allow_http: bool) -> Option<ProviderMetadata> {
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

/// Acquires a client-credentials access token via a raw `client_secret_basic`
/// POST to `token_endpoint`, bypassing the crate's own `TokenClient` so a test
/// of the *validation* path does not depend on the token path being right.
pub async fn client_credentials_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
) -> String {
    let mut form = vec![("grant_type", "client_credentials".to_string())];
    if let Some(scope) = env_nonempty("TEST_SCOPE") {
        form.push(("scope", scope));
    }
    let resp = reqwest::Client::new()
        .post(token_endpoint)
        .basic_auth(client_id, Some(client_secret))
        .form(&form)
        .send()
        .await
        .unwrap_or_else(|e| panic!("client_credentials POST to {token_endpoint}: {e}"));
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .unwrap_or_else(|e| panic!("decode token response: {e}"));
    assert!(
        status.is_success(),
        "token endpoint returned {status}: {body}"
    );
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("token response has no access_token: {body}"))
        .to_string()
}
