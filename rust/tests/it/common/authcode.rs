//! Headless authorization-code driver for node-oidc-provider's
//! `devInteractions`: a minimal cookie jar and a manual redirect follower, so
//! the login + consent legs run with a plain HTTP client and no browser.
//!
//! Only the fixture provider has `devInteractions`; callers detect a real
//! browser login UI (a non-redirect page outside `/interaction/`) and skip.
//!
//! The jar is scoped to the origin of the first request: cookies are stored
//! from, and sent to, that origin only, so a redirect off the provider never
//! carries its session cookies with it. The callback is recognised by exact
//! origin + path against `redirect_uri`, not by string prefix.

use std::collections::HashMap;

/// Absorbs `Set-Cookie` name=value pairs into `store`; deletions (empty value)
/// are removed. Path/domain attributes are ignored — everything in the flow
/// shares the fixture origin.
pub fn absorb_cookies(store: &mut HashMap<String, String>, resp: &reqwest::Response) {
    for sc in resp.headers().get_all(reqwest::header::SET_COOKIE) {
        let Ok(s) = sc.to_str() else { continue };
        let Some(pair) = s.split(';').next() else {
            continue;
        };
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            store.remove(name.trim());
        } else {
            store.insert(name.trim().to_string(), value.to_string());
        }
    }
}

/// Renders `store` as a `Cookie` header value.
pub fn cookie_header(store: &HashMap<String, String>) -> String {
    store
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Follows a redirect chain manually, stopping when a `Location` targets the
/// (unserved) `redirect_uri`. Returns `(final_url, status, Some(callback_url))`
/// when the callback is reached, `(final_url, status, None)` on a non-redirect
/// page. Error statuses are returned, not raised — the caller decides whether
/// a 4xx means "no headless UI" (skip) or a real failure.
///
/// Cookies are only attached to, and only absorbed from, requests on the same
/// origin as the first hop; a redirect to any other origin is followed bare.
pub async fn follow_to_callback(
    client: &reqwest::Client,
    cookies: &mut HashMap<String, String>,
    mut request: reqwest::RequestBuilder,
    redirect_uri: &str,
) -> Result<(url::Url, reqwest::StatusCode, Option<String>), String> {
    let callback = url::Url::parse(redirect_uri).map_err(|e| format!("parse redirect_uri: {e}"))?;
    let mut jar_origin: Option<url::Origin> = None;
    for _hop in 0..10 {
        let mut req = request.build().map_err(|e| format!("build request: {e}"))?;
        let current = req.url().clone();
        let origin = jar_origin.get_or_insert_with(|| current.origin()).clone();
        let same_origin = current.origin() == origin;
        if same_origin && !cookies.is_empty() {
            let value = cookie_header(cookies)
                .parse()
                .map_err(|e| format!("cookie header: {e}"))?;
            req.headers_mut().insert(reqwest::header::COOKIE, value);
        }
        let resp = client
            .execute(req)
            .await
            .map_err(|e| format!("request {current} failed: {e}"))?;
        if same_origin {
            absorb_cookies(cookies, &resp);
        }
        let status = resp.status();
        if !status.is_redirection() {
            return Ok((current, status, None));
        }
        let loc = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| format!("redirect without Location at {current}"))?;
        let next = current
            .join(loc)
            .map_err(|e| format!("resolve redirect {loc:?}: {e}"))?;
        if next.origin() == callback.origin() && next.path() == callback.path() {
            return Ok((current, status, Some(next.into())));
        }
        request = client.get(next);
    }
    Err("too many redirects (>10)".into())
}
