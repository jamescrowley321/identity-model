"""
Parsing functions for py-identity-model.

This module contains parsing logic used by both sync and async implementations.
"""

import copy
import warnings

from jwt import get_unverified_header

from ..exceptions import TokenValidationException
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


def _validate_key_alg_consistency(
    key: JsonWebKey,
    jwt_alg: str | None,
) -> None:
    """Validate that a JWK's key type is consistent with the JWT algorithm.

    Prevents algorithm confusion attacks where an attacker substitutes
    a key of one type (e.g. EC) to verify a token signed with a different
    algorithm family (e.g. RS256).

    Raises:
        TokenValidationException: If the key type does not match the algorithm.
    """
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
        raise TokenValidationException(
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


def find_key_by_kid(
    kid: str | None,
    keys: list[JsonWebKey],
    jwt_alg: str | None = None,
) -> tuple[dict, str]:
    """
    Find a public key from JWKS by key ID and return it with algorithm.

    This is the core key lookup logic shared by sync and async implementations.

    Per OIDC Core Section 10.1, when the JWT has no ``kid`` header and the JWKS
    contains exactly one key, the RP MUST use that key.  When JWKS has multiple
    keys and no ``kid``, filter by ``use`` and ``kty`` to find a unique match.

    Args:
        kid: The key ID from the JWT header
        keys: List of JsonWebKey objects from JWKS
        jwt_alg: The algorithm from the JWT header, used for key type filtering
            when ``kid`` is absent

    Returns:
        tuple: (public_key_dict, algorithm)

    Raises:
        TokenValidationException: If no keys available or no matching key found
    """
    if not keys:
        raise TokenValidationException("No keys available in JWKS response")

    if kid is None:
        # Per RFC 7517 §4.2, filter to signing keys (use="sig" or use omitted)
        signing_keys = [k for k in keys if k.use in (None, "sig")]
        if not signing_keys:
            signing_keys = keys  # Fall back to all keys if none marked for signing

        # Further filter by key type matching the JWT algorithm
        if len(signing_keys) > 1 and jwt_alg:
            expected_kty = _ALG_TO_KTY.get(jwt_alg)
            if expected_kty:
                kty_filtered = [k for k in signing_keys if k.kty == expected_kty]
                if kty_filtered:
                    signing_keys = kty_filtered

        if len(signing_keys) == 1:
            logger.warning(
                "JWT has no kid header; using the single signing key from JWKS"
            )
            public_key = signing_keys[0]
            _validate_key_alg_consistency(public_key, jwt_alg)
            alg = public_key.alg if public_key.alg else (jwt_alg or "RS256")
            return public_key.as_dict(), alg
        raise TokenValidationException(
            "JWT has no kid header and JWKS contains multiple signing keys; "
            "cannot determine which key to use",
            token_part="header",
            details={
                "available_kids": [k.kid for k in signing_keys if k.kid],
                "key_count": len(signing_keys),
            },
        )

    filtered_keys = [k for k in keys if k.kid == kid]
    if not filtered_keys:
        available_kids = [k.kid for k in keys if k.kid]
        raise TokenValidationException(
            f"No matching kid found: {kid}",
            token_part="header",
            details={"kid": kid, "available_kids": available_kids},
        )

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

    Per OIDC Core Section 10.1, when the JWT has no ``kid`` header and the JWKS
    contains exactly one key, that key is used.

    Args:
        jwt: The JWT token
        keys: List of JsonWebKey objects from JWKS

    Returns:
        JsonWebKey: The matching key

    Raises:
        TokenValidationException: If no matching key is found
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
        # Per RFC 7517 §4.2, filter to signing keys (use="sig" or use omitted)
        signing_keys = [k for k in keys if k.use in (None, "sig")]
        if not signing_keys:
            signing_keys = keys  # Fall back to all keys if none marked for signing

        # Further filter by key type matching the JWT algorithm
        jwt_alg = headers.get("alg")
        if len(signing_keys) > 1 and jwt_alg:
            expected_kty = _ALG_TO_KTY.get(jwt_alg)
            if expected_kty:
                kty_filtered = [k for k in signing_keys if k.kty == expected_kty]
                if kty_filtered:
                    signing_keys = kty_filtered

        if len(signing_keys) == 1:
            logger.warning(
                "JWT has no kid header; using the single signing key from JWKS"
            )
            key = copy.deepcopy(signing_keys[0])
            _validate_key_alg_consistency(key, jwt_alg)
            if not key.alg:
                key.alg = jwt_alg
            return key
        raise TokenValidationException(
            "JWT has no kid header and JWKS contains multiple signing keys; "
            "cannot determine which key to use",
            token_part="header",
            details={
                "available_kids": [k.kid for k in signing_keys if k.kid],
                "key_count": len(signing_keys),
            },
        )

    filtered_keys = list(filter(lambda x: x.kid == kid, keys))
    if not filtered_keys:
        available_kids = [k.kid for k in keys if k.kid]
        logger.error(
            f"No matching kid found. Requested: {kid}, Available: {available_kids}",
        )
        raise TokenValidationException(
            f"No matching kid found: {kid}",
            token_part="header",
            details={"kid": kid, "available_kids": available_kids},
        )

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
    "jwks_from_dict",
]
