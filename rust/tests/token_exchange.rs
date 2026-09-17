//! Integration tests for the OAuth 2.0 Token Exchange grant (RFC 8693) against
//! a real RFC 8693 token endpoint over a real socket.
//!
//! Unlike the other integration suites here, these are **not** `#[ignore]`-gated
//! on a live provider. RFC 8693 token exchange has no support in
//! node-oidc-provider (the local `infra/` fixture) and none in the hosted
//! provider profiles, so there is no live endpoint to point at — the same
//! constraint the Go reference documents in
//! `go/pkg/token/token_exchange_integration_test.go`, which drives a
//! self-contained mock endpoint for exactly this reason.
//!
//! So this suite stands up a `wiremock` server — a real HTTP listener on a real
//! port — that implements the RFC 8693 token endpoint: it decodes the
//! `application/x-www-form-urlencoded` body, branches on the grant and the
//! subject token, and replays the shared conformance fixtures from
//! `spec/test-fixtures/token-exchange`. That exercises the full round trip —
//! form encoding, the client-auth header, status handling, JSON parsing — end
//! to end, which the in-process unit tests approximate but do not prove over a
//! socket.
//!
//! Vectors covered: `EXCH-001` (impersonation), `EXCH-002` (delegation),
//! `EXCH-005` (`token_type: N_A`), `EXCH-006` (typed error), plus the
//! adversarial paths a mock endpoint can express — a server that ignores the
//! exchange and answers with a plain token response, and one that rejects the
//! grant outright.

use std::fs;

use rs_identity_model::{
    IdentityError, TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_JWT, TOKEN_TYPE_SAML2, TokenClient,
    TokenExchangeRequest,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FIXTURE_DIR: &str = "../spec/test-fixtures/token-exchange";
const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Reads a shared cross-language conformance fixture. Integration tests run
/// with `rust/` as the working directory.
fn fixture(name: &str) -> String {
    let path = format!("{FIXTURE_DIR}/{name}");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

/// A minimal RFC 8693 token endpoint.
///
/// It decodes the posted form and branches the way a real authorization server
/// does: an unrecognised grant is `unsupported_grant_type`, a missing
/// `subject_token` is `invalid_request`, the literal subject token `expired`
/// gets the `invalid_grant` fixture, and a delegation request (one carrying an
/// `actor_token`) gets the delegation fixture. Anything else gets
/// `success_fixture`.
struct ExchangeEndpoint {
    success_fixture: String,
}

impl Respond for ExchangeEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let form: Vec<(String, String)> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        let get = |key: &str| {
            form.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };

        if get("grant_type") != GRANT_TOKEN_EXCHANGE {
            return ResponseTemplate::new(400)
                .set_body_string(r#"{"error":"unsupported_grant_type"}"#)
                .insert_header("content-type", "application/json");
        }
        let subject = get("subject_token");
        if subject.is_empty() {
            return ResponseTemplate::new(400)
                .set_body_string(
                    r#"{"error":"invalid_request","error_description":"subject_token required"}"#,
                )
                .insert_header("content-type", "application/json");
        }
        if subject == "expired" {
            return ResponseTemplate::new(400)
                .set_body_string(fixture("exchange-error-invalid-grant.json"))
                .insert_header("content-type", "application/json");
        }
        let body = if get("actor_token").is_empty() {
            self.success_fixture.clone()
        } else {
            fixture("exchange-delegation-success.json")
        };
        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "application/json")
    }
}

/// Boots the mock endpoint on a real port, replaying `success_fixture` for a
/// well-formed impersonation exchange.
async fn exchange_endpoint(success_fixture: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ExchangeEndpoint {
            success_fixture: fixture(success_fixture),
        })
        .mount(&server)
        .await;
    server
}

fn client_for(server: &MockServer) -> TokenClient {
    TokenClient::builder()
        .client_id("exchange-client")
        .client_secret("exchange-secret")
        .token_endpoint(format!("{}/token", server.uri()))
        .allow_http(true)
        .build()
        .expect("client builds")
}

// EXCH-001: a real HTTP impersonation exchange returns the parsed issued-token
// trio (access_token, issued_token_type, token_type) plus expires_in.
#[tokio::test]
async fn integration_impersonation_exchange_over_http() {
    let server = exchange_endpoint("exchange-impersonation-success.json").await;

    let issued = client_for(&server)
        .token_exchange(
            &TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN)
                .audience("https://api.example.com")
                .scope("https://api.example.com/read"),
        )
        .await
        .expect("impersonation exchange succeeds");

    assert!(!issued.access_token.is_empty());
    assert_eq!(
        issued.issued_token_type.as_deref(),
        Some(TOKEN_TYPE_ACCESS_TOKEN)
    );
    assert_eq!(issued.token_type, "Bearer");
    assert_eq!(issued.expires_in, 3600);
    assert_eq!(
        issued.scope.as_deref(),
        Some("https://api.example.com/read")
    );
}

// EXCH-002: a delegation exchange reaches the endpoint with both tokens, and
// the server's delegation response parses. The endpoint itself distinguishes
// the two flows, so a client that dropped the actor token would get the
// impersonation body back and fail this assertion.
#[tokio::test]
async fn integration_delegation_exchange_over_http() {
    let server = exchange_endpoint("exchange-impersonation-success.json").await;

    let issued = client_for(&server)
        .token_exchange(
            &TokenExchangeRequest::new("subject.tok", TOKEN_TYPE_ACCESS_TOKEN)
                .actor_token("actor.tok", TOKEN_TYPE_JWT)
                .resource("https://backend.example.com/api"),
        )
        .await
        .expect("delegation exchange succeeds");

    // The delegation fixture's scope names both read and write; the
    // impersonation fixture names read only. Getting the former back proves the
    // actor token crossed the wire.
    assert_eq!(
        issued.scope.as_deref(),
        Some("https://api.example.com/read https://api.example.com/write"),
        "server did not see a delegation request"
    );
    assert_eq!(
        issued.issued_token_type.as_deref(),
        Some(TOKEN_TYPE_ACCESS_TOKEN)
    );
}

// EXCH-005: a non-bearer issued token comes back with token_type N_A and the
// SAML2 issued_token_type, and is accepted rather than rejected for not being
// a Bearer token (RFC 8693 §2.2.1).
#[tokio::test]
async fn integration_non_bearer_n_a_token_type() {
    let server = exchange_endpoint("exchange-n_a-token-type.json").await;

    let issued = client_for(&server)
        .token_exchange(&TokenExchangeRequest::new(
            "subject.tok",
            TOKEN_TYPE_ACCESS_TOKEN,
        ))
        .await
        .expect("an N_A exchange succeeds");

    assert_eq!(issued.token_type, "N_A");
    assert_eq!(issued.issued_token_type.as_deref(), Some(TOKEN_TYPE_SAML2));
    assert_eq!(issued.expires_in, 60);
}

// EXCH-006 (adversarial): the endpoint rejects an expired subject token with a
// real HTTP 400 and an OAuth error body; the client surfaces it as a typed
// TokenEndpoint error rather than a transport failure or an empty success.
#[tokio::test]
async fn integration_expired_subject_token_is_a_typed_error() {
    let server = exchange_endpoint("exchange-impersonation-success.json").await;

    let err = client_for(&server)
        .token_exchange(&TokenExchangeRequest::new(
            "expired",
            TOKEN_TYPE_ACCESS_TOKEN,
        ))
        .await
        .expect_err("an expired subject token must fail");

    match err {
        IdentityError::TokenEndpoint {
            error,
            description,
            status,
            ..
        } => {
            assert_eq!(error, "invalid_grant");
            assert!(
                description.is_some_and(|d| d.contains("subject_token")),
                "error_description should explain the rejection"
            );
            assert_eq!(status, 400);
        }
        other => panic!("expected a typed TokenEndpoint error, got {other:?}"),
    }
}

// Adversarial: a server that answers the exchange with an ordinary token
// response — a 200 with no issued_token_type — is non-conformant
// (RFC 8693 §2.2 REQUIRES it). The client must reject it rather than hand back
// a TokenResponse whose issued type is silently unknown.
#[tokio::test]
async fn integration_success_without_issued_token_type_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"access_token":"plain.tok","token_type":"Bearer"}"#)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let err = client_for(&server)
        .token_exchange(&TokenExchangeRequest::new(
            "subject.tok",
            TOKEN_TYPE_ACCESS_TOKEN,
        ))
        .await
        .expect_err("a response without issued_token_type must fail");

    match err {
        IdentityError::Http(message) => assert!(message.contains("issued_token_type"), "{message}"),
        other => panic!("expected Http naming issued_token_type, got {other:?}"),
    }
}

// Adversarial: a server that answers the exchange with a 200 that omits
// token_type. It is REQUIRED by RFC 6749 §5.1 and listed in
// spec/vectors/token-exchange.json required_fields, and it deserializes to an
// empty string, so the client must reject the response rather than hand back a
// token whose type is silently blank.
#[tokio::test]
async fn integration_success_without_token_type_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!(
                    r#"{{"access_token":"issued.tok","issued_token_type":"{TOKEN_TYPE_ACCESS_TOKEN}"}}"#
                ))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let err = client_for(&server)
        .token_exchange(&TokenExchangeRequest::new(
            "subject.tok",
            TOKEN_TYPE_ACCESS_TOKEN,
        ))
        .await
        .expect_err("a response without token_type must fail");

    match err {
        // "missing token_type", not "token_type": the latter is also satisfied
        // by the "is missing issued_token_type" message the adjacent check
        // produces, so it would not tell the two apart.
        IdentityError::Http(message) => {
            assert!(message.contains("missing token_type"), "{message}");
        }
        other => panic!("expected Http naming token_type, got {other:?}"),
    }
}

// Adversarial: a server that does not implement the grant at all answers
// unsupported_grant_type; the client surfaces the code rather than masking it.
#[tokio::test]
async fn integration_unsupported_grant_is_surfaced() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            // A server that recognises no grant at all, whatever it is sent.
            ResponseTemplate::new(400)
                .set_body_string(r#"{"error":"unsupported_grant_type"}"#)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    let err = client_for(&server)
        .token_exchange(&TokenExchangeRequest::new(
            "subject.tok",
            TOKEN_TYPE_ACCESS_TOKEN,
        ))
        .await
        .expect_err("an unsupported grant must fail");

    match err {
        IdentityError::TokenEndpoint { error, status, .. } => {
            assert_eq!(error, "unsupported_grant_type");
            assert_eq!(status, 400);
        }
        other => panic!("expected TokenEndpoint, got {other:?}"),
    }
}

// EXCH-003: the exported TOKEN_TYPE_* constants are exactly the six URIs the
// shared fixture declares, in the same order. This is the check that stops the
// Rust constants drifting from the cross-language contract — the Go reference
// asserts the identical thing against the identical fixture.
#[test]
fn token_type_constants_match_the_shared_fixture() {
    #[derive(serde::Deserialize)]
    struct TokenTypeUris {
        token_type_uris: Vec<String>,
    }

    let declared: TokenTypeUris =
        serde_json::from_str(&fixture("token-type-uris.json")).expect("parse token-type-uris");
    assert_eq!(
        declared.token_type_uris,
        rs_identity_model::TOKEN_TYPE_URIS.to_vec(),
        "exported token type URIs drifted from spec/test-fixtures"
    );
}
