//! Shared client-authentication and HTTP-form helpers for the OAuth 2.0
//! endpoint clients (token, introspection, and — as the Extended tier lands —
//! revocation and token exchange).
//!
//! Every credential-bearing form POST reuses the same pieces: HTTP Basic
//! credential encoding (RFC 6749 §2.3.1), `application/x-www-form-urlencoded`
//! value encoding, a size-capped response reader (a memory-exhaustion DoS
//! guard), a single-line body snippet for diagnostics, and the typed OAuth 2.0
//! error body (RFC 6749 §5.2) shared by every endpoint's error path. Keeping one
//! implementation here means the clients cannot drift apart on client-auth
//! behaviour.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::{IdentityError, Result};

/// Caps a response body read into memory (a memory-exhaustion DoS guard). OAuth
/// endpoint responses are small.
pub(crate) const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// A typed OAuth 2.0 error response body (RFC 6749 §5.2), decoded from a non-2xx
/// endpoint reply before mapping to [`IdentityError::TokenEndpoint`].
#[derive(serde::Deserialize)]
pub(crate) struct OAuthErrorBody {
    /// The RFC 6749 §5.2 `error` code, e.g. `invalid_client`.
    #[serde(default)]
    pub error: String,
    /// The human-readable `error_description`, if present.
    #[serde(default)]
    pub error_description: Option<String>,
    /// The `error_uri` pointing at documentation, if present.
    #[serde(default)]
    pub error_uri: Option<String>,
}

/// Builds an HTTP Basic `Authorization` header value from `client_id` and
/// `client_secret` (RFC 6749 §2.3.1).
///
/// RFC 6749 §2.3.1 requires the credentials to be form-urlencoded before the
/// Basic base64 encoding so reserved characters survive; `reqwest`'s
/// `basic_auth` does NOT url-encode, so the header is built manually to match
/// the RFC and the Go reference.
pub(crate) fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
    let credentials = format!(
        "{}:{}",
        form_urlencode(client_id),
        form_urlencode(client_secret)
    );
    format!("Basic {}", BASE64_STANDARD.encode(credentials))
}

/// `application/x-www-form-urlencoded` encoding of a single value
/// (RFC 6749 §2.3.1).
pub(crate) fn form_urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reads a response body in chunks, rejecting one that exceeds
/// [`MAX_BODY_BYTES`] before it is fully buffered.
pub(crate) async fn read_capped_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| IdentityError::Http(format!("read response body: {e}")))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(IdentityError::Http(format!(
                "response body exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Returns a short, single-line view of an unexpected response body for error
/// messages.
pub(crate) fn body_snippet(body: &[u8]) -> String {
    const MAX: usize = 200;
    let text = String::from_utf8_lossy(body);
    let text = text.trim().replace('\n', " ");
    if text.chars().count() > MAX {
        format!("{}…", text.chars().take(MAX).collect::<String>())
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6749 §2.3.1: Basic credentials with reserved characters are
    // form-urlencoded before the base64 encoding.
    #[test]
    fn basic_auth_header_urlencodes_credentials() {
        let header = basic_auth_header("id with space", "p@ss:word");
        let expected = format!(
            "Basic {}",
            BASE64_STANDARD.encode("id+with+space:p%40ss%3Aword")
        );
        assert_eq!(header, expected);
    }

    // Unreserved credentials pass through unchanged; the pair joins with a colon.
    #[test]
    fn basic_auth_header_plain_credentials() {
        let header = basic_auth_header("client-1", "s3cr3t");
        assert_eq!(
            header,
            format!("Basic {}", BASE64_STANDARD.encode("client-1:s3cr3t"))
        );
    }

    #[test]
    fn form_urlencode_encodes_reserved_and_space() {
        assert_eq!(form_urlencode("a b"), "a+b");
        assert_eq!(form_urlencode("p@ss:word/1"), "p%40ss%3Aword%2F1");
        assert_eq!(form_urlencode("unreserved-._~"), "unreserved-._~");
    }

    #[test]
    fn body_snippet_trims_and_truncates() {
        assert_eq!(body_snippet(b"  hello\nworld  "), "hello world");
        let long = "x".repeat(250);
        let snip = body_snippet(long.as_bytes());
        assert!(snip.ends_with('…'));
        assert_eq!(snip.chars().count(), 201); // 200 chars + the ellipsis
    }
}
