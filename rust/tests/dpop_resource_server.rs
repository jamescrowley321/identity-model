//! End-to-end DPoP check: a real HTTP resource server that enforces DPoP,
//! exercised by a real client over a TCP socket.
//!
//! `tests/dpop.rs` asserts each RFC 9449 rule in isolation. This file asserts they
//! compose into the property DPoP exists for: **a stolen access token is useless
//! without the private key it was bound to**. That property is not visible in any
//! single unit assertion, because it emerges from the proof signature, the
//! `cnf.jkt` comparison, and the `htm`/`htu`/`ath` bindings all holding at once.
//!
//! The server is a few lines of `std::net` rather than a mock: the proof and the
//! bound token travel as real HTTP headers, so a bug in how the proof is
//! serialized or how the `Authorization` scheme is chosen shows up here and not
//! only in a hand-built string. It also documents the division of responsibility
//! the `verify_proof` docs describe — the library verifies the proof, the caller
//! compares the thumbprint to `cnf.jkt` — by implementing the caller's half.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs_identity_model::{
    DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, verify_proof,
};

/// How the resource server answered a request.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The proof verified and the token was bound to the proof's key.
    Accepted,
    /// Rejected, carrying the reason for diagnostics.
    Rejected(String),
}

/// A minimal DPoP-enforcing resource server (RFC 9449 §7). Serves `requests`
/// connections, then returns.
fn serve(
    listener: TcpListener,
    port: u16,
    expected_jkt: String,
    bound_token: String,
    requests: usize,
) {
    for stream in listener.incoming().take(requests) {
        let mut stream = stream.expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));

        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or("/").to_string();

        let (mut proof, mut authorization) = (String::new(), String::new());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).expect("header") == 0 || line == "\r\n" {
                break;
            }
            let Some(colon) = line.find(':') else {
                continue;
            };
            let value = line[colon + 1..].trim().to_string();
            match line[..colon].to_ascii_lowercase().as_str() {
                "dpop" => proof = value,
                "authorization" => authorization = value,
                _ => {}
            }
        }

        let body = match authorization.strip_prefix("DPoP ") {
            // RFC 9449 §7: a DPoP-bound token MUST be presented with the DPoP
            // scheme. Accepting it as Bearer would drop the sender constraint
            // entirely, so the scheme is checked before the proof.
            None => "rejected: a DPoP-bound token requires the DPoP scheme".to_string(),
            Some(presented) => {
                let uri = format!("http://127.0.0.1:{port}{path}");
                match verify_proof(
                    &proof,
                    &method,
                    &uri,
                    &DpopVerifyOptions::new().access_token(presented),
                ) {
                    // The proof is valid; now the caller's half of the contract —
                    // is the presented token bound to *this* key?
                    Ok(verified) if verified.thumbprint == expected_jkt => {
                        if presented == bound_token {
                            "accepted".to_string()
                        } else {
                            "rejected: unknown access token".to_string()
                        }
                    }
                    Ok(verified) => format!(
                        "rejected: cnf.jkt names another key (proof key {})",
                        verified.thumbprint
                    ),
                    Err(e) => format!("rejected: {e}"),
                }
            }
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
        stream.flush().expect("flush");
    }
}

/// Sends one request and reports how the server answered.
fn call(port: u16, method: &str, path: &str, proof: &str, authorization: &str) -> Outcome {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         DPoP: {proof}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    BufReader::new(stream)
        .read_to_string(&mut response)
        .expect("read response");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    if body == "accepted" {
        Outcome::Accepted
    } else {
        Outcome::Rejected(body)
    }
}

/// Asserts a rejection whose reason mentions `expected`, so the test pins *why*
/// the request failed rather than merely that it did — a rejection for the wrong
/// reason would otherwise pass.
fn assert_rejected_because(outcome: Outcome, expected: &str) {
    match outcome {
        Outcome::Rejected(reason) => assert!(
            reason.contains(expected),
            "rejected for the wrong reason: wanted {expected:?}, got {reason:?}"
        ),
        Outcome::Accepted => panic!("expected a rejection mentioning {expected:?}, got acceptance"),
    }
}

/// DPOP-005/DPOP-006/DPOP-008 composed: a DPoP-bound token is usable by the
/// client that holds the key and by nobody else.
///
/// The attacker in cases 2 and 3 holds the access token in full — this is the
/// post-theft world DPoP is designed for — and still cannot use it.
#[test]
fn a_bound_token_is_useless_without_its_key() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("client key");
    let attacker = DpopKey::generate(DpopAlgorithm::Es256).expect("attacker key");
    let token = "bound-access-token-value";
    let jkt = key.thumbprint().expect("thumbprint");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn({
        let (jkt, token) = (jkt.clone(), token.to_string());
        move || serve(listener, port, jkt, token, 8)
    });

    let uri = format!("http://127.0.0.1:{port}/protectedresource");
    let bearer_of = |t: &str| format!("DPoP {t}");
    let proof_for = |k: &DpopKey, method: &str, uri: &str| {
        k.proof(method, uri, &DpopProofOptions::new().access_token(token))
            .expect("build proof")
    };

    // 1. The legitimate holder of the key succeeds.
    let good = proof_for(&key, "GET", &uri);
    assert_eq!(
        call(port, "GET", "/protectedresource", &good, &bearer_of(token)),
        Outcome::Accepted,
        "the client that holds the bound key must be served"
    );

    // 2. The central property: an attacker with the stolen token but their own
    // key is refused, because cnf.jkt names the victim's key.
    assert_rejected_because(
        call(
            port,
            "GET",
            "/protectedresource",
            &proof_for(&attacker, "GET", &uri),
            &bearer_of(token),
        ),
        "cnf.jkt names another key",
    );

    // 2b. The subtler version of the same attack, and the one signature
    // verification exists for: the attacker copies the *victim's* public jwk out of
    // a proof they observed, so the thumbprint matches `cnf.jkt` and the check in
    // case 2 no longer helps — but signs with their own key, because the victim's
    // private key is the one thing they do not have. Only the signature check
    // stands between them and the resource.
    let forged = {
        let theirs = attacker
            .proof("GET", &uri, &DpopProofOptions::new().access_token(token))
            .expect("attacker proof");
        let mut parts = theirs.split('.');
        let header_b64 = parts.next().expect("header");
        let payload_b64 = parts.next().expect("payload");
        let signature = parts.next().expect("signature");
        let mut header: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(header_b64)
                .expect("header base64url"),
        )
        .expect("header JSON");
        // Swap in the victim's public coordinates, which are public by design.
        let victim = key.public_jwk();
        header["jwk"]["x"] = serde_json::Value::from(victim.x);
        header["jwk"]["y"] = serde_json::Value::from(victim.y);
        format!(
            "{}.{payload_b64}.{signature}",
            URL_SAFE_NO_PAD.encode(header.to_string())
        )
    };
    assert_rejected_because(
        call(
            port,
            "GET",
            "/protectedresource",
            &forged,
            &bearer_of(token),
        ),
        "\"signature\"",
    );

    // 3. An attacker who also steals a proof cannot retarget it: htm and htu bind
    // the proof to one method and one URI.
    assert_rejected_because(
        call(port, "POST", "/protectedresource", &good, &bearer_of(token)),
        "\"htm\"",
    );
    assert_rejected_because(
        call(port, "GET", "/admin", &good, &bearer_of(token)),
        "\"htu\"",
    );

    // 4. RFC 9449 §7 / DPOP-008: the bound token must not be accepted under the
    // Bearer scheme, even with a perfectly valid proof attached.
    assert_rejected_because(
        call(
            port,
            "GET",
            "/protectedresource",
            &good,
            &format!("Bearer {token}"),
        ),
        "requires the DPoP scheme",
    );

    // 5. A token-request proof (no ath) does not authorize a resource request:
    // without the ath binding a proof minted for the token endpoint could be
    // replayed at the resource server.
    let no_ath = key
        .proof("GET", &uri, &DpopProofOptions::new())
        .expect("build proof");
    assert_rejected_because(
        call(
            port,
            "GET",
            "/protectedresource",
            &no_ath,
            &bearer_of(token),
        ),
        "\"ath\"",
    );

    // 6. A missing proof is refused rather than treated as absent-and-therefore-fine.
    assert_rejected_because(
        call(port, "GET", "/protectedresource", "", &bearer_of(token)),
        "rejected",
    );

    server.join().expect("server thread");
}
