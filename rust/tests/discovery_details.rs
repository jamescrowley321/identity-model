//! Detailed discovery errors must survive misleading prose and retain legacy API behavior.

use rs_identity_model::{DiscoveryClient, DiscoveryError, IdentityError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn mount(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(response)
        .mount(server)
        .await;
}

#[tokio::test]
async fn status_is_structured_even_when_body_names_another_failure() {
    let server = MockServer::start().await;
    mount(
        &server,
        ResponseTemplate::new(404)
            .set_body_string("unexpected HTTP status 500; issuer mismatch; must use https"),
    )
    .await;
    let client = DiscoveryClient::builder().allow_http(true).build();
    let error = client.discover_detailed(&server.uri()).await.unwrap_err();
    assert!(matches!(
        error,
        DiscoveryError::HttpStatus { status: 404, .. }
    ));
    assert!(matches!(
        client.discover(&server.uri()).await.unwrap_err(),
        IdentityError::Http(_)
    ));
}

#[tokio::test]
async fn missing_fields_are_exact_and_legacy_validation_is_preserved() {
    let server = MockServer::start().await;
    mount(
        &server,
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": server.uri(),
            "authorization_endpoint": "https://example.com/auth",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })),
    )
    .await;
    let client = DiscoveryClient::builder().allow_http(true).build();
    match client.discover_detailed(&server.uri()).await.unwrap_err() {
        DiscoveryError::MissingFields { fields, .. } => {
            assert_eq!(fields, ["token_endpoint", "subject_types_supported"])
        }
        other => panic!("expected missing fields, got {other:?}"),
    }
    assert!(matches!(
        client.discover(&server.uri()).await.unwrap_err(),
        IdentityError::Validation(_)
    ));
}

#[tokio::test]
async fn issuer_mismatch_carries_actual_and_requested_issuers() {
    let server = MockServer::start().await;
    mount(
        &server,
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": "https://other.example.com",
            "authorization_endpoint": "https://other.example.com/auth",
            "token_endpoint": "https://other.example.com/token",
            "jwks_uri": "https://other.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })),
    )
    .await;
    let client = DiscoveryClient::builder().allow_http(true).build();
    match client.discover_detailed(&server.uri()).await.unwrap_err() {
        DiscoveryError::IssuerMismatch { requested, actual } => {
            assert_eq!(requested, server.uri());
            assert_eq!(actual, "https://other.example.com");
        }
        other => panic!("expected mismatch, got {other:?}"),
    }
    assert!(matches!(
        client.discover(&server.uri()).await.unwrap_err(),
        IdentityError::Validation(_)
    ));
}

#[tokio::test]
async fn https_failure_is_typed_before_any_request() {
    let server = MockServer::start().await;
    let client = DiscoveryClient::new();
    assert!(matches!(
        client.discover_detailed(&server.uri()).await.unwrap_err(),
        DiscoveryError::HttpsRequired { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(matches!(
        client.discover(&server.uri()).await.unwrap_err(),
        IdentityError::Validation(_)
    ));
}

#[tokio::test]
async fn invalid_json_remains_deserialization() {
    let server = MockServer::start().await;
    mount(
        &server,
        ResponseTemplate::new(200).set_body_string("invalid json"),
    )
    .await;
    let client = DiscoveryClient::builder().allow_http(true).build();
    assert!(matches!(
        client.discover_detailed(&server.uri()).await.unwrap_err(),
        DiscoveryError::Other(IdentityError::Deserialization(_))
    ));
    assert!(matches!(
        client.discover(&server.uri()).await.unwrap_err(),
        IdentityError::Deserialization(_)
    ));
}
