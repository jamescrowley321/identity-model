//! Shared HTTP client construction for identity-model's fetch clients.
//!
//! Every client that builds its own default `reqwest::Client` — discovery,
//! JWKS, token, and UserInfo — does so through [`secure_client`] so they share
//! one hardened default: a redirect policy that follows ordinary redirects but
//! **refuses any hop that downgrades the transport from `https` to `http`**. A
//! malicious or misconfigured server must not be able to `3xx` a secure request
//! onto a plaintext URL, where a bearer token, discovery document, or JWK Set
//! could be observed or tampered with (issue #22). Redirects are bounded to
//! [`MAX_REDIRECTS`] hops, matching reqwest's default limit (which a custom
//! policy would otherwise replace).
//!
//! A caller who supplies their own client via a `*Builder::http_client` opts
//! out of this default and is responsible for their own redirect policy.

use std::error::Error;
use std::fmt;

use reqwest::redirect::Policy;
use reqwest::{Client, Url};

/// Maximum number of redirect hops followed before erroring. Matches reqwest's
/// default limit, which the custom policy replaces.
const MAX_REDIRECTS: usize = 10;

/// Builds the hardened default [`reqwest::Client`] shared by the fetch clients.
///
/// Panics only if the underlying TLS backend fails to initialise, matching the
/// behaviour of [`reqwest::Client::new`] / [`reqwest::Client::default`].
pub(crate) fn secure_client() -> Client {
    Client::builder()
        .redirect(no_downgrade_policy())
        .build()
        .expect("build identity-model HTTP client")
}

/// A redirect policy that refuses an `https` → `http` downgrade and bounds the
/// redirect chain to [`MAX_REDIRECTS`] hops.
fn no_downgrade_policy() -> Policy {
    Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(RedirectBlocked::TooManyRedirects);
        }
        if is_tls_downgrade(attempt.previous(), attempt.url()) {
            return attempt.error(RedirectBlocked::TlsDowngrade);
        }
        attempt.follow()
    })
}

/// Reports whether following `next` from the most recent URL in `previous`
/// would downgrade the transport from `https` to `http`. An upgrade
/// (`http` → `https`) and any same-scheme hop are allowed.
fn is_tls_downgrade(previous: &[Url], next: &Url) -> bool {
    matches!(previous.last(), Some(prev) if prev.scheme() == "https" && next.scheme() == "http")
}

/// Why the redirect policy refused to follow a hop. Surfaced to the caller as
/// the source of the resulting `reqwest` error.
#[derive(Debug)]
enum RedirectBlocked {
    /// The redirect target downgraded the transport from `https` to `http`.
    TlsDowngrade,
    /// The redirect chain exceeded [`MAX_REDIRECTS`] hops.
    TooManyRedirects,
}

impl fmt::Display for RedirectBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsDowngrade => {
                f.write_str("refusing to follow an https->http redirect (TLS downgrade)")
            }
            Self::TooManyRedirects => write!(f, "too many redirects (limit {MAX_REDIRECTS})"),
        }
    }
}

impl Error for RedirectBlocked {}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("valid url")
    }

    // #22: an https origin redirecting to an http target is a downgrade.
    #[test]
    fn detects_https_to_http_downgrade() {
        let previous = [url("https://issuer.example.com/a")];
        assert!(is_tls_downgrade(
            &previous,
            &url("http://issuer.example.com/b")
        ));
    }

    // Same-scheme hops and an http->https upgrade are not downgrades.
    #[test]
    fn allows_same_scheme_and_upgrade() {
        let https = [url("https://issuer.example.com/a")];
        assert!(!is_tls_downgrade(
            &https,
            &url("https://issuer.example.com/b")
        ));

        let http = [url("http://localhost/a")];
        assert!(!is_tls_downgrade(&http, &url("http://localhost/b")));
        // http -> https is an upgrade, never blocked.
        assert!(!is_tls_downgrade(&http, &url("https://localhost/b")));
    }

    // With no prior hop there is nothing to downgrade from.
    #[test]
    fn no_previous_hop_is_not_a_downgrade() {
        assert!(!is_tls_downgrade(&[], &url("http://issuer.example.com/a")));
    }

    // The hardened client builds successfully (TLS backend initialises).
    #[test]
    fn secure_client_builds() {
        let _ = secure_client();
    }

    // A same-scheme (http -> http) redirect is still followed: the downgrade
    // guard must not disable ordinary redirect following.
    #[tokio::test]
    async fn follows_same_scheme_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dest = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&dest)
            .await;

        let start = MockServer::start().await;
        let location = format!("{}/final", dest.uri());
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", location.as_str()))
            .mount(&start)
            .await;

        let resp = secure_client()
            .get(format!("{}/start", start.uri()))
            .send()
            .await
            .expect("request succeeds");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }
}
