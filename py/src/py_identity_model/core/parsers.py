"""
Parsing functions for py-identity-model.

This module contains parsing logic used by both sync and async implementations.
"""

import copy
import warnings

from jwt import get_unverified_header

from ..exceptions import (
    AmbiguousKeyException,
    KeyAlgorithmMismatchException,
    KeyNotFoundException,
    TokenValidationException,
)
from ..logging_config import logger
from .models import JsonWebKey, JsonWebKeyParameterNames


_ALG_TO_KTY: dict[str, str] = {
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA",
    "PS384": "RSA",
    "PS512": "RSA",
    "ES256": "EC",
    "ES384": "EC",
    "ES512": "EC",
    "ES256K": "EC",
    "EdDSA": "OKP",
    "Ed25519": "OKP",
    "Ed448": "OKP",
    # Symmetric algorithms map to the "oct" key type. Listing them lets the
    # consistency check reject an HS* header presented against an asymmetric
    # (RSA/EC/OKP) JWK — the classic algorithm-confusion vector (RFC 8725
    # §2.1/§3.1) — while still allowing a legitimate HS256 token signed with a
    # shared-secret "oct" key (OIDC id_token_signed_response_alg=HS256).
    "HS256": "oct",
    "HS384": "oct",
    "HS512": "oct",
}


def _reject_non_string_alg(jwt_alg: object) -> None:
    """Reject a non-string ``alg`` header with a typed exception.

    PyJWT's get_unverified_header type-checks only ``kid`` and ``crit``, so an
    ``alg`` of ``1`` would otherwise raise an untyped AttributeError from the
    string handling below (F-01: the PyIdentityModelException contract).
    """
    if jwt_alg is not None and not isinstance(jwt_alg, str):
        raise TokenValidationException(
            "Invalid 'alg' header: expected a string",
            token_part="header",
            details={"alg_type": type(jwt_alg).__name__},
        )


def _validate_key_alg_consistency(
    key: JsonWebKey,
    jwt_alg: str | None,
) -> None:
    """Validate that a JWK's key type is consistent with the JWT algorithm.

    Prevents algorithm confusion attacks where an attacker substitutes
    a key of one type (e.g. EC) to verify a token signed with a different
    algorithm family (e.g. RS256).

    Raises:
        KeyAlgorithmMismatchException: If the key declares a different alg.
        TokenValidationException: If the key type does not match the algorithm.
    """
    _reject_non_string_alg(jwt_alg)
    if not jwt_alg:
        return

    # RFC 8725 §3.2: never verify a signed token with the "none" algorithm on a
    # key-based path. Reject with a typed exception before PyJWK is constructed —
    # otherwise the no-kid branch hands "none" to PyJWK and raises an untyped
    # NotImplementedError, breaking the PyIdentityModelException contract (F-01).
    if jwt_alg.lower() == "none":
        raise TokenValidationException(
            "Algorithm 'none' is not permitted for signed-token validation",
            token_part="header",
            details={"kid": key.kid, "alg": jwt_alg},
        )

    expected_kty = _ALG_TO_KTY.get(jwt_alg)
    if expected_kty and key.kty != expected_kty:
        raise TokenValidationException(
            f"Key type '{key.kty}' is incompatible with algorithm '{jwt_alg}' "
            f"(expected key type '{expected_kty}')",
            token_part="header",
            details={"kid": key.kid, "kty": key.kty, "alg": jwt_alg},
        )

    # If the key declares an alg, it must match the JWT header exactly
    if key.alg and key.alg != jwt_alg:
        raise KeyAlgorithmMismatchException(
            f"Key algorithm '{key.alg}' does not match JWT algorithm '{jwt_alg}'",
            token_part="header",
            details={"kid": key.kid, "key_alg": key.alg, "jwt_alg": jwt_alg},
        )


def extract_kid_from_jwt(jwt: str) -> str | None:
    """
    Extract the 'kid' (key ID) from a JWT header without verification.

    Args:
        jwt: The JWT token string

    Returns:
        str | None: The key ID from the JWT header, or None if not present
    """
    headers = get_unverified_header(jwt)
    return headers.get("kid")


def extract_jwt_header_fields(jwt: str) -> tuple[str | None, str | None]:
    """
    Extract 'kid' and 'alg' from a JWT header without verification.

    Args:
        jwt: The JWT token string

    Returns:
        tuple: (kid, alg) — either may be None if not present
    """
    headers = get_unverified_header(jwt)
    return headers.get("kid"), headers.get("alg")


# ============================================================================
# JWKS Parsing
# ============================================================================


def jwks_from_dict(keys_dict: dict) -> JsonWebKey:
    """
    Parse a JWKS dictionary into a JsonWebKey object.

    Args:
        keys_dict: Dictionary containing JWK parameters

    Returns:
        JsonWebKey: Parsed JWK object
    """
    return JsonWebKey(
        # Required parameter
        kty=keys_dict.get("kty") or "",
        # Optional parameters for all keys
        use=keys_dict.get("use"),
        key_ops=keys_dict.get("key_ops"),
        alg=keys_dict.get("alg"),
        kid=keys_dict.get("kid"),
        # Optional JWK parameters
        x5u=keys_dict.get("x5u"),
        x5c=keys_dict.get("x5c"),
        x5t=keys_dict.get("x5t"),
        x5t_s256=keys_dict.get(JsonWebKeyParameterNames.X5T_S256.value),
        # Parameters for Elliptic Curve Keys
        crv=keys_dict.get("crv"),
        x=keys_dict.get("x"),
        y=keys_dict.get("y"),
        d=keys_dict.get("d"),
        # Parameters for RSA Keys
        n=keys_dict.get("n"),
        e=keys_dict.get("e"),
        p=keys_dict.get("p"),
        q=keys_dict.get("q"),
        dp=keys_dict.get("dp"),
        dq=keys_dict.get("dq"),
        qi=keys_dict.get("qi"),
        oth=keys_dict.get("oth"),
        # Parameters for Symmetric Keys
        k=keys_dict.get("k"),
    )


def is_signing_key(key: JsonWebKey) -> bool:
    """Return True when *key* may verify a signature.

    Per RFC 7517 §4.2 a key whose ``use`` is ``sig`` or absent is a signing
    key; any other ``use`` (``enc``, or a URI) is not, so the key is never
    used to verify a signature, whether named by ``kid`` or not.
    """
    return key.use in (None, "sig")


def _key_not_found(kid: str | None, keys: list[JsonWebKey]) -> KeyNotFoundException:
    """Build the error for a token no signing key in *keys* can verify."""
    available_kids = [k.kid for k in keys if k.kid and is_signing_key(k)]
    message = (
        f"No matching kid found: {kid}"
        if kid is not None
        else "JWT has no kid header and JWKS contains no signing key"
    )
    return KeyNotFoundException(message, kid=kid, available_kids=available_kids)


def _no_kid_candidates(
    keys: list[JsonWebKey],
    jwt_alg: str | None,
) -> list[JsonWebKey]:
    """Narrow a JWK Set to the keys that could verify a token with no ``kid``.

    Rejects ``alg=none`` first, so that refusal never depends on how many
    keys the set happens to hold.

    Raises:
        KeyNotFoundException: If the set holds no signing key.
        TokenValidationException: If ``jwt_alg`` is ``none``.
    """
    _reject_non_string_alg(jwt_alg)
    if jwt_alg and jwt_alg.lower() == "none":
        raise TokenValidationException(
            "Algorithm 'none' is not permitted for signed-token validation",
            token_part="header",
            details={"alg": jwt_alg},
        )

    # RFC 7517 §4.2: only signing keys (use="sig" or omitted) may verify.
    signing_keys = [k for k in keys if is_signing_key(k)]
    if not signing_keys:
        raise _key_not_found(None, keys)

    if len(signing_keys) > 1 and jwt_alg:
        # RFC 7517 §4.4: a key that declares a different ``alg`` cannot
        # verify this token, so it must not make the choice ambiguous.
        alg_filtered = [k for k in signing_keys if k.alg in (None, jwt_alg)]
        if alg_filtered:
            signing_keys = alg_filtered

        # Further filter by key type matching the JWT algorithm
        expected_kty = _ALG_TO_KTY.get(jwt_alg)
        if expected_kty:
            kty_filtered = [k for k in signing_keys if k.kty == expected_kty]
            if kty_filtered:
                signing_keys = kty_filtered

    return signing_keys


def find_key_by_kid(
    kid: str | None,
    keys: list[JsonWebKey],
    jwt_alg: str | None = None,
) -> tuple[dict, str]:
    """
    Find a public key from JWKS by key ID and return it with algorithm.

    This is the core key lookup logic shared by sync and async implementations.

    Only signing keys (``use`` absent or ``sig``, RFC 7517 §4.2) are
    considered: a ``use: enc`` key is never returned, so a ``kid`` naming one
    is key-not-found.

    When the JWT has no ``kid`` header (OIDC Core Section 10.1 lets the OP omit
    it when its JWK Set holds a single key), the signing keys are narrowed,
    while more than one remains, to keys whose ``alg`` is absent or equals the
    header ``alg`` and whose ``kty`` matches it. Exactly one remaining key is
    used; more than one raises :class:`AmbiguousKeyException`, and none
    raises :class:`KeyNotFoundException`.

    Args:
        kid: The key ID from the JWT header
        keys: List of JsonWebKey objects from JWKS
        jwt_alg: The algorithm from the JWT header, used for key type filtering
            when ``kid`` is absent

    Returns:
        tuple: (public_key_dict, algorithm)

    Raises:
        AmbiguousKeyException: If ``kid`` is absent and more than one key
            could verify the token
        KeyNotFoundException: If no signing key matches ``kid``, or ``kid``
            is absent and the set holds no signing key
        TokenValidationException: If no keys are available
    """
    if not keys:
        raise TokenValidationException("No keys available in JWKS response")

    if kid is None:
        signing_keys = _no_kid_candidates(keys, jwt_alg)

        if len(signing_keys) == 1:
            logger.warning(
                "JWT has no kid header; using the single signing key from JWKS"
            )
            public_key = signing_keys[0]
            _validate_key_alg_consistency(public_key, jwt_alg)
            alg = public_key.alg if public_key.alg else (jwt_alg or "RS256")
            return public_key.as_dict(), alg
        raise AmbiguousKeyException(
            "JWT has no kid header and JWKS contains multiple signing keys; "
            "cannot determine which key to use",
            available_kids=[k.kid for k in signing_keys if k.kid],
            key_count=len(signing_keys),
        )

    filtered_keys = [k for k in keys if k.kid == kid and is_signing_key(k)]
    if not filtered_keys:
        raise _key_not_found(kid, keys)

    public_key = filtered_keys[0]
    _validate_key_alg_consistency(public_key, jwt_alg)
    # Prefer the key's declared alg; otherwise fall back to the JWT header alg
    # (already checked for key-type consistency above) so non-RS256 tokens
    # (PS256, ES256, EdDSA, ...) signed by a JWKS key that omits ``alg`` are not
    # forced onto the RS256 default and wrongly rejected. Mirrors the no-kid
    # single-key branch above.
    alg = public_key.alg if public_key.alg else (jwt_alg or "RS256")
    return public_key.as_dict(), alg


def get_public_key_from_jwk(jwt: str, keys: list[JsonWebKey]) -> JsonWebKey:
    """
    Find the public key from JWKS that matches the JWT's kid.

    As in :func:`find_key_by_kid`, only signing keys are considered. When the
    JWT has no ``kid`` header, the key is the single signing key left after
    narrowing by ``alg`` and ``kty``.

    Args:
        jwt: The JWT token
        keys: List of JsonWebKey objects from JWKS

    Returns:
        JsonWebKey: The matching key

    Raises:
        AmbiguousKeyException: If ``kid`` is absent and more than one key
            could verify the token
        KeyNotFoundException: If no signing key matches
    """
    warnings.warn(
        "get_public_key_from_jwk is deprecated and will be removed in a future "
        "version. Use find_key_by_kid() instead, which returns (key_dict, alg) "
        "without mutating the original key.",
        DeprecationWarning,
        stacklevel=2,
    )

    headers = get_unverified_header(jwt)
    kid = headers.get("kid")
    logger.debug(f"Looking for key with kid: {kid}")

    if kid is None:
        jwt_alg = headers.get("alg")
        signing_keys = _no_kid_candidates(keys, jwt_alg)

        if len(signing_keys) == 1:
            logger.warning(
                "JWT has no kid header; using the single signing key from JWKS"
            )
            key = copy.deepcopy(signing_keys[0])
            _validate_key_alg_consistency(key, jwt_alg)
            if not key.alg:
                key.alg = jwt_alg
            return key
        raise AmbiguousKeyException(
            "JWT has no kid header and JWKS contains multiple signing keys; "
            "cannot determine which key to use",
            available_kids=[k.kid for k in signing_keys if k.kid],
            key_count=len(signing_keys),
        )

    filtered_keys = [k for k in keys if k.kid == kid and is_signing_key(k)]
    if not filtered_keys:
        error = _key_not_found(kid, keys)
        logger.error(
            f"No matching kid found. Requested: {kid}, "
            f"Available: {error.details['available_kids']}",
        )
        raise error

    key = copy.deepcopy(filtered_keys[0])
    jwt_alg = headers.get("alg")
    _validate_key_alg_consistency(key, jwt_alg)
    if not key.alg:
        key.alg = jwt_alg

    logger.debug(f"Found matching key with kid: {kid}, alg: {key.alg}")
    return key


__all__ = [
    "extract_jwt_header_fields",
    "extract_kid_from_jwt",
    "find_key_by_kid",
    "is_signing_key",
    "jwks_from_dict",
]
