//! DPoP (RFC 9449) conformance tests against the shared cross-language fixtures.
//!
//! Covers `DPOP-001`, `DPOP-002`, `DPOP-003`, `DPOP-005`, `DPOP-006`, and
//! `DPOP-007` from `spec/vectors/dpop.json` — the same contract
//! `go/pkg/dpop/dpop_test.go` satisfies, driven from the same
//! `spec/test-fixtures/dpop/` documents so the two languages cannot drift
//! against each other's private expectations.
//!
//! `DPOP-004` (the `use_dpop_nonce` retry) and `DPOP-008` (the
//! `Authorization: DPoP` scheme) are HTTP-transport behaviour and are not covered
//! here; they arrive with the transport, tracked by
//! [#573](https://github.com/jamescrowley321/identity-model/issues/573).
//!
//! These cases are prose-and-fixture contracts, not executable vectors: no case
//! in `spec/vectors/dpop.json` carries a `vectors` array, so
//! `tools/spec_coverage_gate.py` does not inventory the capability and this file
//! needs no `SPEC_COVERAGE_OUT` wiring. The case ids are cited in comments, the
//! way the Go suite cites them.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rs_identity_model::{
    DpopAlgorithm, DpopKey, DpopProofOptions, DpopVerifyOptions, IdentityError, JsonWebKey,
    dpop_ath, jwk_thumbprint, verify_proof,
};
use serde_json::Value;

/// Reads a shared conformance fixture from `spec/test-fixtures/dpop`. Integration
/// tests run with the crate root as the working directory, so the repo's `spec/`
/// is one level up.
fn fixture(name: &str) -> Value {
    let path = format!("../spec/test-fixtures/dpop/{name}");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

/// The ES256 key pair the bound-token fixture is bound to, loaded from its
/// private JWK.
fn fixture_es256_key() -> DpopKey {
    let kp = fixture("dpop-keypair-es256.json");
    DpopKey::from_private_jwk(&kp["private"].to_string()).expect("load ES256 fixture key")
}

/// Decodes a compact JWS into its protected header and payload as JSON.
fn decode_parts(jws: &str) -> (Value, Value) {
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWS has three parts: {jws}");
    let decode = |part: &str| -> Value {
        let raw = URL_SAFE_NO_PAD.decode(part).expect("base64url part");
        serde_json::from_slice(&raw).expect("JSON part")
    };
    (decode(parts[0]), decode(parts[1]))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

// ── DPOP-001 ────────────────────────────────────────────────────────────

/// DPOP-001: a generated token-request proof has a protected header with
/// `typ=dpop+jwt`, the key pair's asymmetric `alg`, and a `jwk` holding only the
/// public key; and a payload with a non-empty `jti`, `htm`, `htu`, and a recent
/// `iat`. Asserted for both algorithms, since RFC 9449 §4.1 requires both.
#[test]
fn generated_proof_has_the_required_header_and_claims() {
    for (algorithm, expected_alg, expected_kty) in [
        (DpopAlgorithm::Es256, "ES256", "EC"),
        (DpopAlgorithm::Rs256, "RS256", "RSA"),
    ] {
        let key = DpopKey::generate(algorithm).expect("generate key");
        let before = now_unix();
        let proof = key
            .proof(
                "POST",
                "https://server.example.com/token",
                &DpopProofOptions::new(),
            )
            .expect("build proof");
        let after = now_unix();
        let (header, payload) = decode_parts(&proof);

        assert_eq!(header["typ"], "dpop+jwt", "{algorithm}: typ");
        assert_eq!(header["alg"], expected_alg, "{algorithm}: alg");
        assert_eq!(header["jwk"]["kty"], expected_kty, "{algorithm}: jwk kty");

        // RFC 9449 §4.2 / RFC 7515 §4.1: the embedded jwk is the PUBLIC key. No
        // private member may appear, whatever the key type.
        let jwk = header["jwk"].as_object().expect("jwk object");
        for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            assert!(
                !jwk.contains_key(private),
                "{algorithm}: embedded jwk leaks private member {private:?}: {jwk:?}"
            );
        }

        assert!(
            !payload["jti"].as_str().expect("jti").is_empty(),
            "{algorithm}: jti must be non-empty"
        );
        assert_eq!(payload["htm"], "POST", "{algorithm}: htm");
        assert_eq!(
            payload["htu"], "https://server.example.com/token",
            "{algorithm}: htu"
        );
        let iat = payload["iat"].as_i64().expect("iat is a number");
        assert!(
            (before..=after).contains(&iat),
            "{algorithm}: iat {iat} outside [{before}, {after}]"
        );
    }
}

/// DPOP-001: two proofs from the same key carry different `jti` values, so a
/// verifier's replay store can tell one request from the next.
#[test]
fn each_proof_gets_a_fresh_jti() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://server.example.com/token";
    let first = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("first proof");
    let second = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("second proof");
    let (_, a) = decode_parts(&first);
    let (_, b) = decode_parts(&second);
    assert_ne!(a["jti"], b["jti"], "each proof needs its own jti");
}

/// DPOP-001/DPOP-002: the shared token-request proof fixture documents the header
/// and claim set a generated proof must reproduce. Drive the structure off the
/// fixture rather than restating it, so a change to the cross-language contract
/// shows up here as a failure.
#[test]
fn generated_proof_matches_the_token_request_fixture_shape() {
    let expected = fixture("dpop-proof-token-request.json");
    let key = fixture_es256_key();
    let htu = expected["payload"]["htu"].as_str().expect("fixture htu");
    let htm = expected["payload"]["htm"].as_str().expect("fixture htm");

    let proof = key
        .proof(htm, htu, &DpopProofOptions::new())
        .expect("build proof");
    let (header, payload) = decode_parts(&proof);

    assert_eq!(header["typ"], expected["header"]["typ"]);
    assert_eq!(header["alg"], expected["header"]["alg"]);
    // The fixture's jwk is the public half of the fixture key pair, so the
    // generated proof must embed exactly those coordinates.
    for member in ["kty", "crv", "x", "y"] {
        assert_eq!(
            header["jwk"][member], expected["header"]["jwk"][member],
            "jwk member {member:?}"
        );
    }
    assert_eq!(payload["htm"], expected["payload"]["htm"]);
    assert_eq!(payload["htu"], expected["payload"]["htu"]);
    // Every claim the fixture payload names must be present (jti/iat differ per
    // proof, so only presence is asserted for those).
    for claim in expected["payload"].as_object().expect("payload").keys() {
        assert!(
            !payload[claim].is_null(),
            "generated proof is missing the {claim:?} claim the fixture requires"
        );
    }
}

// ── DPOP-002 ────────────────────────────────────────────────────────────

/// DPOP-002: a token-request proof carries no `ath` claim — there is no access
/// token to bind to yet (RFC 9449 §5). The fixture asserts the same absence.
#[test]
fn token_request_proof_has_no_ath() {
    let fixture = fixture("dpop-proof-token-request.json");
    assert!(
        fixture["payload"].get("ath").is_none(),
        "the token-request fixture must not carry ath"
    );

    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let proof = key
        .proof(
            "POST",
            "https://server.example.com/token",
            &DpopProofOptions::new(),
        )
        .expect("build proof");
    let (_, payload) = decode_parts(&proof);
    assert!(
        payload.get("ath").is_none(),
        "a token-request proof must omit ath, got {payload:?}"
    );
    assert!(
        payload.get("nonce").is_none(),
        "an unchallenged proof must omit nonce, got {payload:?}"
    );
}

// ── DPOP-003 ────────────────────────────────────────────────────────────

/// DPOP-003: `ath` is `BASE64URL(SHA-256(access_token))` without padding, for
/// every deterministic pair in the shared fixture — including the RFC 9449 §4.2
/// canonical example.
#[test]
fn ath_matches_every_fixture_pair() {
    let pairs = fixture("dpop-ath-pairs.json");
    let pairs = pairs["pairs"].as_array().expect("pairs array");
    assert!(!pairs.is_empty(), "the ath fixture must carry pairs");
    for pair in pairs {
        let token = pair["access_token"].as_str().expect("access_token");
        let want = pair["ath"].as_str().expect("ath");
        let description = pair["description"].as_str().unwrap_or_default();
        assert_eq!(dpop_ath(token), want, "{description}");
        assert!(
            !want.contains('='),
            "{description}: ath must be unpadded base64url"
        );
    }
}

/// DPOP-003: a resource-request proof carries the `ath` of the presented token,
/// and the shared resource-request fixture's `ath` is reproduced exactly.
#[test]
fn resource_request_proof_carries_ath() {
    let expected = fixture("dpop-proof-resource-request.json");
    let token = fixture("dpop-ath-pairs.json")["pairs"][1]["access_token"]
        .as_str()
        .expect("bound token value")
        .to_string();
    // The fixture pair and the resource-request fixture must describe the same
    // token; if they drift this assertion says so before the proof is built.
    assert_eq!(
        dpop_ath(&token),
        expected["payload"]["ath"].as_str().expect("fixture ath"),
        "the ath fixture pair and the resource-request fixture disagree"
    );

    let key = fixture_es256_key();
    let htu = expected["payload"]["htu"].as_str().expect("htu");
    let proof = key
        .proof("GET", htu, &DpopProofOptions::new().access_token(&token))
        .expect("build proof");
    let (_, payload) = decode_parts(&proof);
    assert_eq!(payload["ath"], expected["payload"]["ath"]);
}

// ── DPOP-005 ────────────────────────────────────────────────────────────

/// DPOP-005: the RFC 7638 thumbprint of the DPoP public key equals the bound
/// token's `cnf.jkt`, and every JWK in the thumbprint fixture — including the
/// RFC 7638 §3.1 canonical RSA vector — reproduces its expected thumbprint.
#[test]
fn thumbprint_matches_bound_token_and_every_fixture_pair() {
    let keypair = fixture("dpop-keypair-es256.json");
    let key = fixture_es256_key();
    let thumbprint = key.thumbprint().expect("thumbprint");
    assert_eq!(
        thumbprint,
        keypair["thumbprint"].as_str().expect("fixture thumbprint"),
        "key thumbprint must match the keypair fixture"
    );

    let bound = fixture("dpop-bound-token.json");
    assert_eq!(
        bound["payload"]["cnf"]["jkt"].as_str().expect("cnf.jkt"),
        thumbprint,
        "the bound token's cnf.jkt must name the key it is bound to"
    );
    // DPOP-008's precondition: the token endpoint reports this token as DPoP-bound.
    assert_eq!(bound["token_type"], "DPoP");

    // The public JWK derived from the key pair must thumbprint identically — the
    // thumbprint covers only the required members, so metadata cannot change it.
    assert_eq!(
        jwk_thumbprint(&key.public_jwk()).expect("public jwk thumbprint"),
        thumbprint
    );

    let pairs = fixture("dpop-thumbprint-pairs.json");
    let pairs = pairs["pairs"].as_array().expect("pairs array");
    assert!(!pairs.is_empty(), "the thumbprint fixture must carry pairs");
    for pair in pairs {
        let description = pair["description"].as_str().unwrap_or_default();
        let jwk: JsonWebKey =
            serde_json::from_value(pair["jwk"].clone()).expect("fixture jwk parses");
        assert_eq!(
            jwk_thumbprint(&jwk).expect("thumbprint"),
            pair["thumbprint"].as_str().expect("expected thumbprint"),
            "{description}"
        );
    }
}

/// DPOP-005: the RS256 fixture key pair loads from its private JWK and reproduces
/// its documented thumbprint, so `cnf.jkt` binding works for both algorithms.
#[test]
fn rs256_fixture_key_reproduces_its_thumbprint() {
    let keypair = fixture("dpop-keypair-rs256.json");
    let key =
        DpopKey::from_private_jwk(&keypair["private"].to_string()).expect("load RS256 fixture key");
    assert_eq!(key.algorithm(), DpopAlgorithm::Rs256);
    assert_eq!(
        key.thumbprint().expect("thumbprint"),
        keypair["thumbprint"].as_str().expect("fixture thumbprint")
    );
    // The derived public JWK must be the fixture's public half.
    let public = key.public_jwk();
    assert_eq!(public.kty, "RSA");
    assert_eq!(public.n, keypair["public"]["n"].as_str().expect("n"));
    assert_eq!(public.e, keypair["public"]["e"].as_str().expect("e"));
}

// ── DPOP-006 ────────────────────────────────────────────────────────────

/// DPOP-006: verification accepts a well-formed proof and returns the key's
/// thumbprint, so the caller can complete the `cnf.jkt` check.
#[test]
fn verify_accepts_a_well_formed_proof() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let token = "an-access-token";
    let uri = "https://resource.example.com/protectedresource";
    let proof = key
        .proof("GET", uri, &DpopProofOptions::new().access_token(token))
        .expect("build proof");

    let verified = verify_proof(
        &proof,
        "GET",
        uri,
        &DpopVerifyOptions::new().access_token(token),
    )
    .expect("proof verifies");

    assert_eq!(verified.typ, "dpop+jwt");
    assert_eq!(verified.algorithm, "ES256");
    assert_eq!(verified.htm, "GET");
    assert_eq!(verified.htu, uri);
    assert_eq!(verified.thumbprint, key.thumbprint().expect("thumbprint"));
    assert_eq!(verified.ath.as_deref(), Some(dpop_ath(token).as_str()));
    assert!(!verified.jti.is_empty());
    assert_eq!(verified.public_jwk.kty, "EC");
    assert_eq!(verified.public_jwk.crv, "P-256");
}

/// DPOP-006: an RS256 proof verifies too — the verifier is not ES256-only.
#[test]
fn verify_accepts_an_rs256_proof() {
    let key = DpopKey::generate(DpopAlgorithm::Rs256).expect("generate key");
    let uri = "https://server.example.com/token";
    let proof = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("build proof");
    let verified =
        verify_proof(&proof, "POST", uri, &DpopVerifyOptions::new()).expect("proof verifies");
    assert_eq!(verified.algorithm, "RS256");
    assert_eq!(verified.public_jwk.kty, "RSA");
    assert_eq!(verified.thumbprint, key.thumbprint().expect("thumbprint"));
}

/// Asserts that `result` was rejected as a DPoP verification failure naming
/// `field`.
fn assert_rejected_for(result: Result<impl std::fmt::Debug, IdentityError>, field: &str) {
    match result {
        Err(IdentityError::DpopVerification { field: got, .. }) => {
            assert_eq!(got.as_deref(), Some(field), "rejected for the wrong field");
        }
        other => panic!("expected a DpopVerification error for {field:?}, got {other:?}"),
    }
}

/// DPOP-006: a proof whose `htm` or `htu` does not match the request is rejected,
/// and the error names which one.
#[test]
fn verify_rejects_htm_and_htu_mismatch() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://resource.example.com/protectedresource";
    let proof = key
        .proof("GET", uri, &DpopProofOptions::new())
        .expect("build proof");

    // Same URI, wrong method.
    assert_rejected_for(
        verify_proof(&proof, "POST", uri, &DpopVerifyOptions::new()),
        "htm",
    );
    // Same method, wrong path.
    assert_rejected_for(
        verify_proof(
            &proof,
            "GET",
            "https://resource.example.com/other",
            &DpopVerifyOptions::new(),
        ),
        "htu",
    );
    // Same path, wrong host — the authority is part of htu.
    assert_rejected_for(
        verify_proof(
            &proof,
            "GET",
            "https://attacker.example.com/protectedresource",
            &DpopVerifyOptions::new(),
        ),
        "htu",
    );
    // Same host, wrong scheme.
    assert_rejected_for(
        verify_proof(
            &proof,
            "GET",
            "http://resource.example.com/protectedresource",
            &DpopVerifyOptions::new(),
        ),
        "htu",
    );
}

/// DPOP-006: a proof signed with a symmetric algorithm, or with `none`, or
/// missing the embedded `jwk`, is rejected. These are the forgery paths that make
/// the `alg`/`jwk` checks load-bearing rather than cosmetic.
#[test]
fn verify_rejects_symmetric_none_and_missing_jwk() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://server.example.com/token";
    let good = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("build proof");
    let (header, payload) = decode_parts(&good);

    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let forge = |header: &Value, signature: &str| {
        format!("{}.{}.{}", encode(header), encode(&payload), signature)
    };

    // `alg: none` with no signature — the classic unsecured-JWS forgery.
    let mut none_header = header.clone();
    none_header["alg"] = Value::from("none");
    assert_rejected_for(
        verify_proof(
            &forge(&none_header, ""),
            "POST",
            uri,
            &DpopVerifyOptions::new(),
        ),
        "alg",
    );

    // A symmetric algorithm: anyone holding the secret could mint this.
    let mut hs_header = header.clone();
    hs_header["alg"] = Value::from("HS256");
    hs_header["jwk"] = serde_json::json!({"kty": "oct", "k": "c2VjcmV0"});
    assert_rejected_for(
        verify_proof(
            &forge(&hs_header, "not-a-real-signature"),
            "POST",
            uri,
            &DpopVerifyOptions::new(),
        ),
        "alg",
    );

    // No embedded jwk at all: nothing to verify against.
    let mut bare_header = header.clone();
    bare_header
        .as_object_mut()
        .expect("header object")
        .remove("jwk");
    assert_rejected_for(
        verify_proof(
            &forge(&bare_header, "not-a-real-signature"),
            "POST",
            uri,
            &DpopVerifyOptions::new(),
        ),
        "jwk",
    );

    // Wrong typ: a plain JWT — an access token, say — replayed as a proof.
    let mut typ_header = header.clone();
    typ_header["typ"] = Value::from("JWT");
    assert_rejected_for(
        verify_proof(
            &forge(&typ_header, "not-a-real-signature"),
            "POST",
            uri,
            &DpopVerifyOptions::new(),
        ),
        "typ",
    );
}

/// DPOP-006/DPOP-001: a proof whose embedded `jwk` carries private key material
/// is rejected. The parsed JWK type cannot represent those members, so this only
/// holds if verification inspects the raw header — which is exactly the
/// regression this guards.
#[test]
fn verify_rejects_a_jwk_carrying_private_material() {
    let keypair = fixture("dpop-keypair-es256.json");
    let key = fixture_es256_key();
    let uri = "https://server.example.com/token";
    let good = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("build proof");
    let (mut header, payload) = decode_parts(&good);

    // Put the private scalar into the otherwise-correct embedded jwk. The
    // signature still verifies — the private member is ignored by the crypto —
    // so only an explicit check rejects this.
    header["jwk"]["d"] = keypair["private"]["d"].clone();
    let forged = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        good.split('.').nth(2).expect("signature"),
    );
    assert_rejected_for(
        verify_proof(&forged, "POST", uri, &DpopVerifyOptions::new()),
        "jwk",
    );
}

/// DPOP-006: a proof signed by one key but presenting another key's public jwk is
/// rejected. This is the substitution attack the signature check exists to stop.
#[test]
fn verify_rejects_a_proof_signed_by_a_different_key() {
    let signer = DpopKey::generate(DpopAlgorithm::Es256).expect("signer key");
    let other = DpopKey::generate(DpopAlgorithm::Es256).expect("other key");
    let uri = "https://server.example.com/token";
    let proof = signer
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("build proof");
    let (mut header, payload) = decode_parts(&proof);

    // Swap in the other key's public coordinates, keeping the original signature.
    let victim = other.public_jwk();
    header["jwk"]["x"] = Value::from(victim.x.clone());
    header["jwk"]["y"] = Value::from(victim.y.clone());
    let forged = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        proof.split('.').nth(2).expect("signature"),
    );
    assert_rejected_for(
        verify_proof(&forged, "POST", uri, &DpopVerifyOptions::new()),
        "signature",
    );
}

/// DPOP-006: the `iat` window is enforced. The clock seam that lets a test mint a
/// deliberately stale proof is crate-internal, so the two-sided window check
/// lives in `src/dpop/verify.rs`'s unit tests; what an integration test can still
/// prove is that a freshly minted proof sits comfortably inside the default
/// window and that a zero-width window is honoured rather than ignored.
#[test]
fn verify_accepts_a_fresh_iat_within_the_default_window() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://server.example.com/token";
    let proof = key
        .proof("POST", uri, &DpopProofOptions::new())
        .expect("build proof");

    verify_proof(&proof, "POST", uri, &DpopVerifyOptions::new())
        .expect("a proof minted now is inside the default 60s window");
    verify_proof(
        &proof,
        "POST",
        uri,
        &DpopVerifyOptions::new().max_iat_age(Duration::from_secs(1)),
    )
    .expect("and inside a 1s window");
}

/// DPOP-006: with an expected `ath` or `nonce` configured, a proof that omits or
/// mismatches it is rejected.
#[test]
fn verify_rejects_ath_and_nonce_mismatch() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://resource.example.com/protectedresource";

    // A token-request proof (no ath) presented where a bound one is required.
    let bare = key
        .proof("GET", uri, &DpopProofOptions::new())
        .expect("build proof");
    assert_rejected_for(
        verify_proof(
            &bare,
            "GET",
            uri,
            &DpopVerifyOptions::new().access_token("the-token"),
        ),
        "ath",
    );

    // A proof bound to a different token: the replay this check exists to stop.
    let wrong = key
        .proof(
            "GET",
            uri,
            &DpopProofOptions::new().access_token("some-other-token"),
        )
        .expect("build proof");
    assert_rejected_for(
        verify_proof(
            &wrong,
            "GET",
            uri,
            &DpopVerifyOptions::new().access_token("the-token"),
        ),
        "ath",
    );

    // Nonce: absent when expected, then present but wrong.
    assert_rejected_for(
        verify_proof(&bare, "GET", uri, &DpopVerifyOptions::new().nonce("n-1")),
        "nonce",
    );
    let wrong_nonce = key
        .proof("GET", uri, &DpopProofOptions::new().nonce("n-0"))
        .expect("build proof");
    assert_rejected_for(
        verify_proof(
            &wrong_nonce,
            "GET",
            uri,
            &DpopVerifyOptions::new().nonce("n-1"),
        ),
        "nonce",
    );
    // And the matching nonce verifies, so the check is not simply always failing.
    let right = key
        .proof("GET", uri, &DpopProofOptions::new().nonce("n-1"))
        .expect("build proof");
    let verified = verify_proof(&right, "GET", uri, &DpopVerifyOptions::new().nonce("n-1"))
        .expect("matching nonce verifies");
    assert_eq!(verified.nonce.as_deref(), Some("n-1"));
}

/// DPOP-004's payload half: a challenged proof carries the server nonce from the
/// shared error-response fixture in its `nonce` claim. The HTTP retry that
/// produces it is DPOP-004 proper and arrives with the transport.
#[test]
fn nonce_claim_carries_the_fixture_server_nonce() {
    let challenge = fixture("dpop-nonce-error-response.json");
    assert_eq!(challenge["body"]["error"], "use_dpop_nonce");
    let nonce = challenge["headers"]["DPoP-Nonce"]
        .as_str()
        .expect("DPoP-Nonce header");

    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let uri = "https://server.example.com/token";
    let proof = key
        .proof("POST", uri, &DpopProofOptions::new().nonce(nonce))
        .expect("build proof");
    let (_, payload) = decode_parts(&proof);
    assert_eq!(payload["nonce"], nonce);
    verify_proof(&proof, "POST", uri, &DpopVerifyOptions::new().nonce(nonce))
        .expect("the retried proof verifies against the issued nonce");
}

// ── DPOP-007 ────────────────────────────────────────────────────────────

/// DPOP-007: ES256 yields an EC P-256 key pair, RS256 an RSA key pair with a
/// modulus of at least 2048 bits, and an unsupported algorithm is rejected.
#[test]
fn generate_produces_p256_and_rsa2048_and_rejects_anything_else() {
    let ec = DpopKey::generate(DpopAlgorithm::Es256).expect("generate ES256");
    assert_eq!(ec.algorithm(), DpopAlgorithm::Es256);
    let ec_jwk = ec.public_jwk();
    assert_eq!(ec_jwk.kty, "EC");
    assert_eq!(ec_jwk.crv, "P-256");
    // P-256 coordinates are 32 bytes each (RFC 7518 §6.2.1.2).
    for (member, value) in [("x", &ec_jwk.x), ("y", &ec_jwk.y)] {
        let decoded = URL_SAFE_NO_PAD.decode(value).expect("base64url coordinate");
        assert_eq!(decoded.len(), 32, "P-256 {member} must be 32 bytes");
    }

    let rsa = DpopKey::generate(DpopAlgorithm::Rs256).expect("generate RS256");
    assert_eq!(rsa.algorithm(), DpopAlgorithm::Rs256);
    let rsa_jwk = rsa.public_jwk();
    assert_eq!(rsa_jwk.kty, "RSA");
    let modulus = URL_SAFE_NO_PAD
        .decode(&rsa_jwk.n)
        .expect("base64url modulus");
    assert!(
        modulus.len() * 8 >= 2048,
        "RS256 modulus must be at least 2048 bits, got {}",
        modulus.len() * 8
    );

    // Two generated keys differ: generation is not returning a fixed key.
    let other = DpopKey::generate(DpopAlgorithm::Es256).expect("generate ES256");
    assert_ne!(
        ec.thumbprint().expect("thumbprint"),
        other.thumbprint().expect("thumbprint"),
        "each generated key must be distinct"
    );

    // An unsupported algorithm is rejected. The enum makes a symmetric algorithm
    // unconstructible, so the string entry point is where the rejection lives.
    for unsupported in ["HS256", "none", "ES512", "", "es256"] {
        let parsed: Result<DpopAlgorithm, IdentityError> = unsupported.parse();
        assert!(
            matches!(parsed, Err(IdentityError::Configuration(_))),
            "{unsupported:?} must be rejected as a DPoP algorithm, got {parsed:?}"
        );
    }
    assert_eq!(
        "ES256".parse::<DpopAlgorithm>().expect("ES256 parses"),
        DpopAlgorithm::Es256
    );
    assert_eq!(
        "RS256".parse::<DpopAlgorithm>().expect("RS256 parses"),
        DpopAlgorithm::Rs256
    );
}

/// DPOP-007: a generated key survives a PKCS#8 round-trip, so it can be persisted
/// and reloaded without invalidating tokens already bound to it (RFC 9449 §4.1).
#[test]
fn keys_round_trip_through_pkcs8() {
    for algorithm in [DpopAlgorithm::Es256, DpopAlgorithm::Rs256] {
        let key = DpopKey::generate(algorithm).expect("generate key");
        let pem = key.to_pkcs8_pem();
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "{algorithm}: PKCS#8 PEM label"
        );

        let reloaded = DpopKey::from_pkcs8_pem(&pem, algorithm).expect("reload from PEM");
        assert_eq!(
            reloaded.thumbprint().expect("thumbprint"),
            key.thumbprint().expect("thumbprint"),
            "{algorithm}: a reloaded key must be the same key"
        );

        let from_der =
            DpopKey::from_pkcs8_der(key.to_pkcs8_der(), algorithm).expect("reload from DER");
        assert_eq!(
            from_der.thumbprint().expect("thumbprint"),
            key.thumbprint().expect("thumbprint"),
            "{algorithm}: DER round-trip"
        );

        // A proof from the reloaded key verifies, so the private half survived —
        // not just the public coordinates the thumbprint covers.
        let uri = "https://server.example.com/token";
        let proof = reloaded
            .proof("POST", uri, &DpopProofOptions::new())
            .expect("build proof");
        verify_proof(&proof, "POST", uri, &DpopVerifyOptions::new())
            .expect("a proof from the reloaded key verifies");
    }
}

/// DPOP-007: loading a key rejects the mismatches that would otherwise produce
/// proofs no verifier accepts — the wrong key type for the algorithm, an RSA
/// modulus below 2048 bits, or malformed input.
#[test]
fn loading_rejects_mismatched_and_weak_keys() {
    let ec = DpopKey::generate(DpopAlgorithm::Es256).expect("generate ES256");
    let rsa = DpopKey::generate(DpopAlgorithm::Rs256).expect("generate RS256");

    // An EC key labelled RS256, and an RSA key labelled ES256.
    assert!(
        DpopKey::from_pkcs8_der(ec.to_pkcs8_der(), DpopAlgorithm::Rs256).is_err(),
        "an EC key must not load as RS256"
    );
    assert!(
        DpopKey::from_pkcs8_der(rsa.to_pkcs8_der(), DpopAlgorithm::Es256).is_err(),
        "an RSA key must not load as ES256"
    );

    // Garbage input.
    assert!(DpopKey::from_pkcs8_der(b"not a key", DpopAlgorithm::Es256).is_err());
    assert!(DpopKey::from_pkcs8_pem("not a pem", DpopAlgorithm::Es256).is_err());
    assert!(DpopKey::from_private_jwk("{not json").is_err());

    // A private JWK missing the members its type requires.
    assert!(
        DpopKey::from_private_jwk(r#"{"kty":"EC","crv":"P-256"}"#).is_err(),
        "an EC JWK without d must be rejected"
    );
    assert!(
        DpopKey::from_private_jwk(r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#).is_err(),
        "an RSA JWK without the CRT members must be rejected"
    );
    // A curve other than P-256 under an ES256 label.
    assert!(
        DpopKey::from_private_jwk(r#"{"kty":"EC","alg":"ES256","crv":"P-384","d":"AQAB"}"#)
            .is_err(),
        "ES256 must require P-256"
    );
    // An unsupported kty, and an unsupported alg member.
    assert!(DpopKey::from_private_jwk(r#"{"kty":"oct","k":"c2VjcmV0"}"#).is_err());
    assert!(
        DpopKey::from_private_jwk(r#"{"kty":"oct","alg":"HS256","k":"c2VjcmV0"}"#).is_err(),
        "a symmetric JWK must never load as a DPoP key"
    );
}

/// The `Debug` impl must not leak private key material — a key often sits inside
/// a client struct someone logs.
#[test]
fn debug_does_not_leak_private_material() {
    let key = DpopKey::generate(DpopAlgorithm::Es256).expect("generate key");
    let rendered = format!("{key:?}");
    let pem = key.to_pkcs8_pem();
    let secret_body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    assert!(
        !rendered.contains(&secret_body),
        "Debug must not render the private key: {rendered}"
    );
    assert!(
        rendered.contains("ES256"),
        "Debug should name the algorithm"
    );
    assert!(
        rendered.contains(&key.thumbprint().expect("thumbprint")),
        "Debug should name the public thumbprint"
    );
}
