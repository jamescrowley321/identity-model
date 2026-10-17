//! Minimum strength for token verification keys (#952).
//!
//! RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an RSA key of 2048 bits or
//! larger, and FAPI 2.0 Security Profile §5.4.1 requires at least 224 bits for
//! elliptic curve keys. The floor is checked on the JWK resolved to verify a
//! token, before it becomes a [`jsonwebtoken::DecodingKey`], so the rule is the
//! same in Python, Go and Rust (`spec/vectors/validation.json` JWT-014).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::jwks::JsonWebKey;
use crate::{IdentityError, Result};

/// The smallest RSA modulus, in bits, accepted for verification (RFC 7518 §3.3).
pub const MIN_RSA_KEY_BITS: usize = 2048;

/// The smallest EC key, in bits, accepted for verification (FAPI 2.0 Security
/// Profile §5.4.1).
pub const MIN_EC_KEY_BITS: usize = 224;

/// Rejects an RSA or EC verification key below the floor with
/// [`IdentityError::WeakKey`].
///
/// RSA strength is the bit length of the modulus `n`; EC strength is 8 times
/// the octet length of the `x` coordinate, which RFC 7518 §6.2.1.2 requires to
/// be the full coordinate size for the curve. `OKP` keys (fixed size) and `oct`
/// keys have no floor, and material that doesn't decode is left to key
/// conversion.
pub(super) fn check_key_strength(key: &JsonWebKey) -> Result<()> {
    let (bits, min_bits) = match key.kty.as_str() {
        "RSA" => match URL_SAFE_NO_PAD.decode(&key.n) {
            Ok(n) => (bit_length(&n), MIN_RSA_KEY_BITS),
            Err(_) => return Ok(()),
        },
        "EC" => match URL_SAFE_NO_PAD.decode(&key.x) {
            Ok(x) => (x.len() * 8, MIN_EC_KEY_BITS),
            Err(_) => return Ok(()),
        },
        _ => return Ok(()),
    };
    if bits < min_bits {
        return Err(IdentityError::WeakKey {
            kid: key.kid.clone(),
            kty: key.kty.clone(),
            bits,
            min_bits,
        });
    }
    Ok(())
}

/// The bit length of a big-endian unsigned integer, ignoring leading zero
/// octets.
fn bit_length(bytes: &[u8]) -> usize {
    match bytes.iter().position(|&b| b != 0) {
        Some(first) => (bytes.len() - first - 1) * 8 + (8 - bytes[first].leading_zeros() as usize),
        None => 0,
    }
}
