"""
JWT helper functions for py-identity-model.

This module contains JWT-related operations used by both sync and async implementations.
"""

from jwt import PyJWK, decode
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)

from ..exceptions import (
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)
from ..logging_config import logger
from .models import JsonWebKey


# Options that MUST NOT be disabled — these are core security checks.
# Setting them to True is allowed (redundant but safe).
_ENFORCED_VERIFICATION_OPTIONS: frozenset[str] = frozenset(
    {
        "verify_signature",
        "verify_exp",
        "verify_nbf",
        "verify_iat",
    }
)


def _sanitize_options(options: dict | None) -> dict | None:
    """Validate caller-supplied PyJWT decode options.

    Prevents callers from disabling core security checks via the options
    pass-through.  ``verify_signature``, ``verify_exp``, ``verify_nbf``,
    and ``verify_iat`` must never be set to ``False``.

    Args:
        options: Caller-supplied decode options, or None.

    Returns:
        The options dict (unmodified) if all values are safe, or None.

    Raises:
        ConfigurationException: If any enforced option is set to False.
    """
    if options is None:
        return None

    for key in _ENFORCED_VERIFICATION_OPTIONS:
        if key in options and not options[key]:
            raise ConfigurationException(
                f"Security option '{key}' cannot be disabled. "
                f"JWT {key.removeprefix('verify_')} verification is always enforced."
            )

    return options


def _normalize_verification_key(key: dict | JsonWebKey) -> dict:
    """Normalize a verification key into a PyJWK-safe JWK mapping.

    Accepts both the typed :class:`~py_identity_model.core.models.JsonWebKey`
    returned by ``get_jwks`` / ``jwks_from_dict`` and a plain JWK ``dict``. This
    closes the round-trip gap where the typed key handed *out* of ``get_jwks``
    could not be fed back *in* to ``validate_token`` (``TokenValidationConfig.key``),
    which raised ``AttributeError: 'JsonWebKey' object has no attribute 'get'``
    inside PyJWT.

    Members whose value is ``None`` are dropped. PyJWT's ``Algorithm.from_jwk``
    decides public-vs-private by key *name presence* (``"d" in obj``), not value,
    so a public JWK carrying a null-valued private member — e.g.
    ``{"kty": "RSA", "n": ..., "e": ..., "d": None}``, as produced by a naive
    dataclass-to-dict conversion — would be routed into private-key construction
    and raise ``TypeError: Expected a string value``. Stripping ``None`` members
    (the value-based test :meth:`JsonWebKey.has_private_key` already uses) makes
    the conversion safe regardless of how the caller built the mapping. A genuine
    private key is untouched: its private members hold real values, never ``None``.

    Raises:
        ConfigurationException: If ``key`` is neither a ``JsonWebKey`` nor a dict.
    """
    if isinstance(key, JsonWebKey):
        # as_dict() maps Python field names back to RFC 7517 member names and
        # already omits None-valued members.
        return key.as_dict()
    if isinstance(key, dict):
        return {k: v for k, v in key.items() if v is not None}
    raise ConfigurationException(
        f"Verification key must be a JsonWebKey or a JWK dict, got {type(key).__name__}"
    )


def _get_pyjwk(key_data: dict, algorithm: str | None) -> PyJWK:
    """
    Construct a PyJWK from key data.

    Args:
        key_data: JWK mapping (already normalized via
            :func:`_normalize_verification_key`).
        algorithm: Algorithm to use

    Returns:
        PyJWK instance
    """
    return PyJWK(key_data, algorithm)


def _decode_jwt(  # noqa: PLR0913  # JWT validation requires these params
    jwt: str,
    key_data: dict,
    algorithms: list[str],
    audience: str | None,
    issuer: str | list[str] | None,
    options: dict | None,
    leeway: float | None = None,
) -> dict:
    """
    Internal JWT decoding.

    Args:
        jwt: The JWT token
        key_data: Key dictionary
        algorithms: Allowed algorithms
        audience: Expected audience
        issuer: Expected issuer (string or list for multi-issuer)
        options: Decode options
        leeway: Clock skew tolerance in seconds

    Returns:
        Decoded claims
    """
    pyjwk = _get_pyjwk(key_data, algorithms[0] if algorithms else None)

    kwargs: dict = {
        "audience": audience,
        "algorithms": algorithms,
        "issuer": issuer,
        "options": options,
        "leeway": leeway if leeway is not None else 0,
    }

    return decode(jwt, pyjwk, **kwargs)


def decode_and_validate_jwt(  # noqa: PLR0913  # RFC 7519 §7.2 validation requires these params
    jwt: str,
    key: dict | JsonWebKey,
    algorithms: list[str],
    audience: str | None,
    issuer: str | list[str] | None,
    options: dict | None,
    leeway: float | None = None,
    subject: str | None = None,
) -> dict:
    """
    Decode and validate JWT with proper exception handling.

    Args:
        jwt: The JWT token to decode
        key: The public key to use for verification — a :class:`JsonWebKey`
            (as returned by ``get_jwks``) or a plain JWK dict. ``None``-valued
            members are ignored, so a public key is never misread as private.
        algorithms: List of allowed algorithms
        audience: Expected audience
        issuer: Expected issuer (single string or list for multi-tenant)
        options: Additional validation options
        leeway: Clock skew tolerance in seconds for exp/nbf claims
        subject: Expected ``sub`` claim.  Validated after decoding.

    Returns:
        Decoded token claims

    Raises:
        TokenExpiredException: If token has expired
        InvalidAudienceException: If audience is invalid
        InvalidIssuerException: If issuer is invalid
        SignatureVerificationException: If signature is invalid
        TokenValidationException: For other token validation errors
    """
    try:
        # Guard against empty algorithms on direct API calls
        if not algorithms:
            raise ConfigurationException("algorithms must not be empty")

        # Guard against empty issuer list on direct API calls
        if isinstance(issuer, list) and len(issuer) == 0:
            raise ConfigurationException(
                "issuer must not be an empty list; omit or set to None to skip issuer validation"
            )

        # Sanitize options — block attempts to disable core security checks
        sanitized_options = _sanitize_options(options)

        # Accept a typed JsonWebKey or a plain JWK dict, and drop None-valued
        # members so a public key is never misread as private (see
        # _normalize_verification_key).
        normalized_key = _normalize_verification_key(key)

        decoded = _decode_jwt(
            jwt,
            normalized_key,
            algorithms,
            audience,
            issuer,
            sanitized_options,
            leeway=leeway,
        )

        # Validate subject claim (PyJWT doesn't do this natively)
        if subject is not None and decoded.get("sub") != subject:
            raise TokenValidationException(
                "Invalid subject: token sub does not match expected value",
                token_part="payload",
            )

        return decoded
    except TokenValidationException:
        raise
    except ExpiredSignatureError as e:
        logger.error(f"Token has expired: {e!s}")
        raise TokenExpiredException(
            "Token has expired",
            details={"error": str(e)},
        ) from e
    except InvalidAudienceError as e:
        logger.error(f"Invalid audience: {e!s}")
        raise InvalidAudienceException(
            "Invalid audience",
            details={"error": str(e)},
        ) from e
    except InvalidIssuerError as e:
        logger.error(f"Invalid issuer: {e!s}")
        raise InvalidIssuerException("Invalid issuer", details={"error": str(e)}) from e
    except InvalidSignatureError as e:
        logger.error(f"Invalid signature: {e!s}")
        raise SignatureVerificationException(
            "Invalid signature",
            details={"error": str(e)},
        ) from e
    except InvalidTokenError as e:
        logger.error(f"Invalid token: {e!s}")
        raise TokenValidationException(
            f"Invalid token: {e!s}",
            details={"error": str(e)},
        ) from e


__all__ = [
    "decode_and_validate_jwt",
]
