"""
Minimum strength for token verification keys.

RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an RSA key of 2048 bits or larger,
FAPI 2.0 Security Profile §5.4.1 requires at least 224 bits for elliptic
curve keys, and RFC 7518 §3.2 requires an HMAC key at least as long as the
hash output (256, 384 or 512 bits for HS256, HS384 or HS512). The floor is checked on the JWK selected to verify a token, before
it is converted to a crypto key, so the same rule applies in Python, Go and
Rust whichever curves the crypto backend knows (``spec/vectors/validation.json``
JWT-014).
"""

from __future__ import annotations

import binascii

from jwt.utils import base64url_decode

from ..exceptions import WeakKeyException


MIN_RSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 224
MIN_HMAC_KEY_BITS: dict[str, int] = {"HS256": 256, "HS384": 384, "HS512": 512}


def _decode_member(value: object) -> bytes | None:
    """Decode a base64url JWK member, or ``None`` when it doesn't decode.

    Decodes with PyJWT's own decoder, so the floor measures exactly the octets
    key conversion turns into the verification key. A member that doesn't
    decode, or decodes to nothing, is left for key conversion to reject.
    """
    # PyJWT accepts bytes members as well as str, so both are measured.
    if not isinstance(value, (str, bytes)):
        return None
    try:
        decoded = base64url_decode(value)
    except (binascii.Error, ValueError):
        return None
    return decoded or None


def _hmac_key_bits(jwk: dict, alg: str | None) -> tuple[int, int] | None:
    """Return ``(bits, min_bits)`` for an ``oct`` key used with HS256/384/512."""
    min_bits = MIN_HMAC_KEY_BITS.get(alg) if isinstance(alg, str) else None
    k = _decode_member(jwk.get("k"))
    if min_bits is None or k is None:
        return None
    return len(k) * 8, min_bits


def _key_bits(jwk: dict, alg: str | None) -> tuple[int, int] | None:
    """Return ``(bits, min_bits)`` for a key type with a floor, else ``None``.

    RSA strength is the bit length of the modulus ``n``. EC strength is 8 times
    the octet length of the ``x`` coordinate, which RFC 7518 §6.2.1.2 requires
    to be the full coordinate size for the curve. ``oct`` strength is 8 times
    the octet length of ``k``; its floor depends on the HS* *alg* it is used
    with. OKP keys (fixed size) have no floor.
    """
    kty = jwk.get("kty")
    if kty == "oct":
        return _hmac_key_bits(jwk, alg)
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


def enforce_key_strength(jwk: dict, alg: str | None = None) -> None:
    """Reject a verification key below its strength floor.

    Args:
        jwk: The JWK mapping chosen to verify a token.
        alg: The algorithm the key is used with. It sets the floor for an
            ``oct`` (HMAC) key; RSA and EC floors do not depend on it.

    Raises:
        WeakKeyException: If an RSA key is under 2048 bits, an EC key under
            224 bits, or an ``oct`` key used with HS256/384/512 is shorter
            than 256/384/512 bits.
    """
    measured = _key_bits(jwk, alg)
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
    "MIN_HMAC_KEY_BITS",
    "MIN_RSA_KEY_BITS",
    "enforce_key_strength",
]
