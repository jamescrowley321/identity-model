//! The shared `../spec/test-fixtures/validation` signing material.
//!
//! Integration tests run with the crate root (`rust/`) as the working
//! directory, so the repo's `spec/` is one level up. The RS256 key is loaded in
//! its PKCS#1 DER form so that signing needs no `rsa` crate
//! (RUSTSEC-2023-0071); `kid=test-key-1` matches `jwks.json`.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rs_identity_model::JsonWebKey;
use serde_json::Value;

pub const FIXTURE_DIR: &str = "../spec/test-fixtures/validation";
pub const FIXTURE_KID: &str = "test-key-1";

/// Reads a file from [`FIXTURE_DIR`].
pub fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURE_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

/// The RS256 signing key from the shared fixture, so a test signs with the same
/// material as the Python and Go suites.
pub fn signing_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&read_fixture("signing-key.pkcs1.der"))
}

/// The public verification key that matches [`signing_key`], resolved from the
/// JWKS fixture.
pub fn public_key() -> JsonWebKey {
    let jwks: Value =
        serde_json::from_slice(&read_fixture("jwks.json")).expect("parse jwks fixture");
    serde_json::from_value(jwks["keys"][0].clone()).expect("deserialize fixture key")
}

/// The current time as POSIX seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// Mints an RS256 token (`kid=test-key-1`) carrying `claims`, signed with
/// [`signing_key`].
pub fn mint(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(FIXTURE_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign token")
}
