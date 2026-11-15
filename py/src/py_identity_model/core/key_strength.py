"""
Minimum strength for verification and signing keys.

RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an RSA key of 2048 bits or larger,
FAPI 2.0 Security Profile §5.4.1 requires at least 224 bits for elliptic
curve keys, and RFC 7518 §3.2 requires an HMAC key at least as long as the
hash output (256, 384 or 512 bits for HS256, HS384 or HS512). The floor is checked on the JWK selected to verify a token, before
it is converted to a crypto key, so the same rule applies in Python, Go and
Rust whichever curves the crypto backend knows (``spec/vectors/validation.json``
JWT-014). The same floor is checked on a private key before the library signs
with it (request objects, client assertions).
"""

from __future__ import annotations

import binascii

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import get_default_algorithms
from jwt.exceptions import PyJWTError
from jwt.utils import base64url_decode

from ..exceptions import WeakKeyException, WeakSigningKeyError


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
    """Return ``(bits, min_bits)`` for an ``oct`` key used with HS256/384/512.

    A missing, empty or undecodable ``k`` measures 0 bits: key conversion
    accepts an empty HMAC secret, so it must not skip the floor.
    """
    min_bits = MIN_HMAC_KEY_BITS.get(alg) if isinstance(alg, str) else None
    if min_bits is None:
        return None
    k = _decode_member(jwk.get("k"))
    return (len(k) * 8 if k is not None else 0), min_bits


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


def load_signing_key(private_key: object, algorithm: str) -> object | None:
    """Return the key PyJWT signs with for *private_key* and *algorithm*.

    Uses PyJWT's own key preparation, so the floor measures exactly the key
    that would sign. ``None`` when *algorithm* is unknown or PyJWT can't
    prepare the key; signing then fails in PyJWT with its own error.
    """
    algorithm_impl = get_default_algorithms().get(algorithm)
    if algorithm_impl is None:
        return None
    try:
        return algorithm_impl.prepare_key(private_key)
    except (PyJWTError, ValueError, TypeError, UnsupportedAlgorithm):
        return None


def enforce_signing_key_strength(private_key: object, algorithm: str) -> None:
    """Refuse to sign with an RSA key below the strength floor.

    Only RSA needs a check: PyJWT binds each ``ES*`` algorithm to its curve
    (P-256 and up), so no EC signing key is under :data:`MIN_EC_KEY_BITS`, and
    OKP keys have a fixed size.

    Args:
        private_key: The signing key as passed to the signing helper (PEM
            ``str``/``bytes`` or a ``cryptography`` key).
        algorithm: The JWS ``alg`` it will sign with.

    Raises:
        WeakSigningKeyError: If the key is an RSA key under 2048 bits.
    """
    key = load_signing_key(private_key, algorithm)
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < MIN_RSA_KEY_BITS:
        raise WeakSigningKeyError(
            kty="RSA", bits=key.key_size, min_bits=MIN_RSA_KEY_BITS
        )


__all__ = [
    "MIN_EC_KEY_BITS",
    "MIN_HMAC_KEY_BITS",
    "MIN_RSA_KEY_BITS",
    "enforce_key_strength",
    "enforce_signing_key_strength",
    "load_signing_key",
]
