"""
Minimum strength for token verification keys.

RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an RSA key of 2048 bits or larger,
and FAPI 2.0 Security Profile §5.4.1 requires at least 224 bits for elliptic
curve keys. The floor is checked on the JWK selected to verify a token, before
it is converted to a crypto key, so the same rule applies in Python, Go and
Rust whichever curves the crypto backend knows (``spec/vectors/validation.json``
JWT-014).
"""

from __future__ import annotations

from base64 import urlsafe_b64decode
import binascii

from ..exceptions import WeakKeyException


MIN_RSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 224


def _decode_member(value: object) -> bytes | None:
    """Decode a base64url JWK member, or ``None`` when it doesn't decode.

    A member that doesn't decode is left for key conversion to reject.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        # Decoding ignores padding beyond what the input needs, so "==" pads
        # any unpadded base64url member (RFC 7515 §2).
        return urlsafe_b64decode(value + "==")
    except (binascii.Error, ValueError):
        return None


def _key_bits(jwk: dict) -> tuple[int, int] | None:
    """Return ``(bits, min_bits)`` for a key type with a floor, else ``None``.

    RSA strength is the bit length of the modulus ``n``. EC strength is 8 times
    the octet length of the ``x`` coordinate, which RFC 7518 §6.2.1.2 requires
    to be the full coordinate size for the curve. OKP keys (fixed size) and
    ``oct`` keys have no floor.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _decode_member(jwk.get("n"))
        if n is None:
            return None
        return int.from_bytes(n).bit_length(), MIN_RSA_KEY_BITS
    if kty == "EC":
        x = _decode_member(jwk.get("x"))
        if x is None:
            return None
        return len(x) * 8, MIN_EC_KEY_BITS
    return None


def enforce_key_strength(jwk: dict) -> None:
    """Reject a verification key below the RSA or EC strength floor.

    Args:
        jwk: The JWK mapping chosen to verify a token.

    Raises:
        WeakKeyException: If an RSA key is under 2048 bits or an EC key under
            224 bits.
    """
    measured = _key_bits(jwk)
    if measured is None:
        return
    bits, min_bits = measured
    if bits < min_bits:
        kty = jwk["kty"]
        raise WeakKeyException(
            f"{kty} verification key is {bits} bits; at least {min_bits} required",
            kid=jwk.get("kid"),
            kty=kty,
            bits=bits,
            min_bits=min_bits,
        )


__all__ = [
    "MIN_EC_KEY_BITS",
    "MIN_RSA_KEY_BITS",
    "enforce_key_strength",
]
