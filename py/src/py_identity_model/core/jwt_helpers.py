"""
JWT helper functions for py-identity-model.

This module contains JWT-related operations used by both sync and async implementations.
"""

from jwt import PyJWK, decode, get_unverified_header
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKError,
)

from ..exceptions import (
    ConfigurationException,
    InvalidAudienceException,
    InvalidIssuerException,
    KeyAlgorithmMismatchException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)
from ..logging_config import logger
from .key_strength import enforce_key_strength
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


def _reject_disabled(options: dict, key: str, reason: str) -> None:
    if key in options and not options[key]:
        raise ConfigurationException(
            f"Security option '{key}' cannot be disabled {reason}."
        )


def _sanitize_options(
    options: dict | None,
    audience: str | None,
    issuer: str | list[str] | None,
) -> dict | None:
    """Validate caller-supplied PyJWT decode options.

    Prevents callers from disabling core security checks via the options
    pass-through:

    * ``verify_signature``, ``verify_exp``, ``verify_nbf`` and ``verify_iat``
      can never be ``False``.
    * ``verify_aud`` cannot be ``False`` when an ``audience`` is configured,
      and ``verify_iss`` cannot be ``False`` when an ``issuer`` is configured
      or discovered.
    * ``require`` must be a list, tuple or set of claim-name strings. It can
      only add required claims.

    Args:
        options: Caller-supplied decode options, or None.
        audience: The audience the token is checked against, or None.
        issuer: The issuer(s) the token is checked against (configured or
            from discovery), or None.

    Returns:
        The options dict (unmodified) if all values are safe, or None.

    Raises:
        ConfigurationException: If an option would disable a check.
    """
    if options is None:
        return None

    for key in _ENFORCED_VERIFICATION_OPTIONS:
        _reject_disabled(options, key, "; it is always enforced")
    if audience is not None:
        _reject_disabled(options, "verify_aud", "while an audience is configured")
    if issuer is not None:
        _reject_disabled(options, "verify_iss", "while an issuer is configured")

    if "require" in options:
        required = options["require"]
        if not isinstance(required, (list, tuple, set, frozenset)) or not all(
            isinstance(claim, str) for claim in required
        ):
            raise ConfigurationException(
                "Option 'require' must be a list of claim names."
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


def _select_key_algorithm(jwt: str, key_data: dict, algorithms: list[str]) -> str:
    """Pick the one algorithm the verification key is used with.

    RFC 8725 §3.1: the caller specifies a set of algorithms, and each key is
    used with exactly one. The key is bound to the token's header ``alg`` when
    that is in *algorithms*, so every algorithm in the set is usable; a key
    that declares ``alg`` must declare that one (RFC 7517 §4.4), and the key
    type must fit it, which key conversion checks. A header ``alg`` outside
    the set is left for decoding to reject.

    Raises:
        KeyAlgorithmMismatchException: If the key declares an ``alg`` other
            than the token's.
        InvalidTokenError: If the JOSE header cannot be read.
    """
    header_alg = get_unverified_header(jwt).get("alg")
    key_alg = key_data.get("alg")
    if not isinstance(header_alg, str) or header_alg not in algorithms:
        # Decoding rejects the unlisted alg; the binding does not matter.
        return key_alg or algorithms[0]
    if key_alg and key_alg != header_alg:
        raise KeyAlgorithmMismatchException(
            f"Key algorithm '{key_alg}' does not match JWT algorithm '{header_alg}'",
            token_part="header",
            details={
                "kid": key_data.get("kid"),
                "key_alg": key_alg,
                "jwt_alg": header_alg,
            },
        )
    return header_alg


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

    Raises:
        WeakKeyException: If the key is under the strength floor for the
            algorithm it is bound to.
    """
    key_algorithm = _select_key_algorithm(jwt, key_data, algorithms)

    # RFC 7518 §3.2/§3.3 / FAPI 2.0 SP §5.4.1: refuse a weak key before it is
    # used to verify anything.
    enforce_key_strength(key_data, key_algorithm)

    pyjwk = _get_pyjwk(key_data, key_algorithm)

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
        WeakKeyException: If ``key`` is an RSA key under 2048 bits, an EC
            key under 224 bits, or an ``oct`` key shorter than the HS* hash
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
        sanitized_options = _sanitize_options(options, audience, issuer)

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
    except (InvalidKeyError, PyJWKError) as e:
        # The key is malformed or does not fit the token's alg (e.g. an RSA
        # key, ES256 header).
        logger.error(f"Key cannot verify the token: {e!s}")
        raise TokenValidationException(
            "Key cannot verify the token",
            token_part="header",
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
