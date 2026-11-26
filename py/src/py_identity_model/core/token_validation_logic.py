"""
Core token validation business logic (sync/async agnostic).

This module contains the shared validation logic used by both sync and async
implementations to reduce code duplication.
"""

import inspect

from jwt import PyJWTError, get_unverified_header

from ..core.jwt_helpers import (
    decode_and_validate_jwt,
)
from ..core.jwt_signing import DEFAULT_ALLOWED_ALGORITHMS
from ..core.models import (
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
    JwksErrorKind,
    JwksResponse,
    TokenValidationConfig,
)
from ..core.parsers import extract_jwt_header_fields
from ..exceptions import (
    AccessTokenTypeError,
    AccessTokenTypeErrorKind,
    ConfigurationException,
    DiscoveryException,
    DiscoveryHTTPSRequiredError,
    DiscoveryIssuerMismatchError,
    DiscoveryMissingFieldsError,
    DiscoveryParseError,
    DiscoveryValidationError,
    InvalidIssuerException,
    JwksException,
    JwksValidationError,
    PyIdentityModelException,
    SignatureVerificationException,
    TokenValidationErrorKind,
    TokenValidationException,
)
from ..logging_config import logger
from ..logging_utils import redact_token


_DISCOVERY_FAILURE_TYPES: dict[DiscoveryErrorKind, type[PyIdentityModelException]] = {
    DiscoveryErrorKind.INVALID_JSON: DiscoveryParseError,
    DiscoveryErrorKind.INVALID_DOCUMENT: DiscoveryValidationError,
    DiscoveryErrorKind.HTTPS_REQUIRED: DiscoveryHTTPSRequiredError,
    DiscoveryErrorKind.INVALID_CONFIGURATION: ConfigurationException,
}


def discovery_failure(
    disco_doc_response: DiscoveryDocumentResponse,
) -> PyIdentityModelException:
    """The typed exception for a failed discovery response.

    The response's ``error_kind`` picks the type:

    - ``UNEXPECTED_STATUS``, ``NETWORK_ERROR``, ``UNEXPECTED_ERROR`` (or no
      kind): :class:`DiscoveryException`, a ``NetworkException`` carrying the
      ``status_code``. The provider is unavailable.
    - ``INVALID_JSON``: :class:`DiscoveryParseError`.
    - ``MISSING_FIELDS``: :class:`DiscoveryMissingFieldsError`.
    - ``ISSUER_MISMATCH``: :class:`DiscoveryIssuerMismatchError`.
    - ``INVALID_DOCUMENT``: :class:`DiscoveryValidationError`.
    - ``HTTPS_REQUIRED``: :class:`DiscoveryHTTPSRequiredError`.
    - ``INVALID_CONFIGURATION``: :class:`ConfigurationException`.
    """
    kind = disco_doc_response.error_kind
    message = disco_doc_response.error or "Discovery document request failed"
    if kind is DiscoveryErrorKind.MISSING_FIELDS:
        return DiscoveryMissingFieldsError(message, disco_doc_response.missing_fields)
    if kind is DiscoveryErrorKind.ISSUER_MISMATCH:
        return DiscoveryIssuerMismatchError(
            disco_doc_response.requested_issuer or "",
            disco_doc_response.returned_issuer or "",
        )
    exception_type = _DISCOVERY_FAILURE_TYPES.get(kind) if kind is not None else None
    if exception_type is None:
        return DiscoveryException(message, status_code=disco_doc_response.status_code)
    return exception_type(message)


#: What :func:`validate_disco_response`, :func:`validate_jwks_uri` and
#: :func:`validate_jwks_response` raise for a provider that is unavailable or
#: serves an invalid document. Request functions that fetch discovery after
#: their own request (signed introspection) let these propagate unchanged.
DISCOVERY_AND_JWKS_FAILURES: tuple[type[PyIdentityModelException], ...] = (
    DiscoveryException,
    DiscoveryValidationError,
    JwksException,
    JwksValidationError,
)


def validate_disco_response(
    disco_doc_response: DiscoveryDocumentResponse,
) -> None:
    """
    Validate discovery document response.

    Args:
        disco_doc_response: Discovery document response to validate

    Raises:
        DiscoveryException: If the document could not be fetched (a
            ``NetworkException``).
        DiscoveryValidationError: If the fetched document is invalid.
        ConfigurationException: If a URL or policy check failed.
    """
    if not disco_doc_response.is_successful:
        logger.error(f"Discovery failed: {disco_doc_response.error}")
        raise discovery_failure(disco_doc_response)


def validate_jwks_uri(
    disco_doc_response: DiscoveryDocumentResponse,
) -> str:
    """Validate and return jwks_uri from a discovery document response.

    Args:
        disco_doc_response: A successful discovery document response.

    Returns:
        The non-empty jwks_uri string.

    Raises:
        DiscoveryMissingFieldsError: If jwks_uri is missing or empty.
    """
    if not disco_doc_response.jwks_uri:
        raise DiscoveryMissingFieldsError(
            "Discovery document missing jwks_uri", ("jwks_uri",)
        )
    return disco_doc_response.jwks_uri


def jwks_failure(jwks_response: JwksResponse) -> PyIdentityModelException:
    """The typed exception for a failed JWKS response.

    ``INVALID_JSON`` and ``INVALID_DOCUMENT`` give
    :class:`JwksValidationError`; ``INVALID_CONFIGURATION`` gives
    :class:`ConfigurationException`; any other kind (or none) gives
    :class:`JwksException`, a ``NetworkException`` carrying the
    ``status_code``.
    """
    kind = jwks_response.error_kind
    message = jwks_response.error or "JWKS request failed"
    if kind in (JwksErrorKind.INVALID_JSON, JwksErrorKind.INVALID_DOCUMENT):
        return JwksValidationError(message)
    if kind is JwksErrorKind.INVALID_CONFIGURATION:
        return ConfigurationException(message)
    return JwksException(message, status_code=jwks_response.status_code)


def validate_jwks_response(jwks_response: JwksResponse) -> None:
    """
    Validate JWKS response.

    Args:
        jwks_response: JWKS response to validate

    Raises:
        JwksException: If the JWK Set could not be fetched (a
            ``NetworkException``).
        JwksValidationError: If the fetched JWK Set is unusable or has no
            keys.
        ConfigurationException: If the JWKS URL failed a URL or policy check.
    """
    if not jwks_response.is_successful:
        logger.error(f"JWKS fetch failed: {jwks_response.error}")
        raise jwks_failure(jwks_response)

    if not jwks_response.keys:
        error_msg = "No keys available in JWKS response"
        logger.error(error_msg)
        raise JwksValidationError(error_msg)


def keep_signature_verdict_on_failed_refresh(jwks_response: JwksResponse) -> None:
    """Raise the signature failure if the retry's JWKS refresh failed.

    The token already failed verification with the cached keys, so an
    unavailable JWKS endpoint does not change the verdict: it stays a
    :class:`SignatureVerificationException`, with the fetch failure as its
    cause, rather than becoming a provider outage.
    """
    if not jwks_response.is_successful:
        logger.warning(
            f"JWKS refresh failed after a signature failure: {jwks_response.error}"
        )
        raise SignatureVerificationException(
            "Signature verification failed; JWKS refresh failed"
        ) from jwks_failure(jwks_response)


_EMPTY_ALGORITHMS_MESSAGE = (
    "TokenValidationConfig.algorithms must not be empty; "
    "None allows DEFAULT_ALLOWED_ALGORITHMS"
)


def validate_config_for_manual_validation(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token configuration for manual validation (non-discovery mode).

    ``algorithms=None`` is valid: the token's ``alg`` must then be in
    ``DEFAULT_ALLOWED_ALGORITHMS``, as in discovery mode.

    Args:
        token_validation_config: Token validation configuration

    Raises:
        ConfigurationException: If the key is missing or ``algorithms`` is an
            empty list
    """
    if not token_validation_config.key:
        raise ConfigurationException(
            "TokenValidationConfig.key is required",
        )
    _reject_empty_algorithms(token_validation_config)


def _reject_empty_algorithms(token_validation_config: TokenValidationConfig) -> None:
    if token_validation_config.algorithms is not None and (
        not token_validation_config.algorithms
    ):
        raise ConfigurationException(_EMPTY_ALGORITHMS_MESSAGE)


def _require_allowed_alg(alg: object, allowed: list[str]) -> str:
    """Return *alg* if it is one of *allowed*; raise otherwise."""
    if not isinstance(alg, str) or alg not in allowed:
        raise TokenValidationException(
            f"Algorithm '{alg}' is not in the allowed algorithms",
            token_part="header",
            details={"alg": alg, "allowed": list(allowed)},
            validation_kind=(
                TokenValidationErrorKind.ALGORITHM_NONE
                if isinstance(alg, str) and alg.lower() == "none"
                else TokenValidationErrorKind.ALGORITHM
            ),
        )
    return alg


def resolve_algorithms(
    jwt: str,
    algorithms: list[str] | None,
) -> list[str]:
    """Return the algorithms to verify *jwt* with.

    An explicit list is returned unchanged. ``None`` pins verification to the
    token's header ``alg``, which must be in ``DEFAULT_ALLOWED_ALGORITHMS``.
    That set has no HMAC algorithm, so a public key is never used as an HMAC
    secret (RFC 8725 §2.1).

    Raises:
        MalformedTokenException: If *algorithms* is ``None`` and *jwt* is not
            a well-formed compact JWS.
        TokenValidationException: If *algorithms* is ``None`` and the header
            ``alg`` is not in the default set.
    """
    if algorithms is not None:
        return algorithms
    _, alg = extract_jwt_header_fields(jwt)
    return [_require_allowed_alg(alg, sorted(DEFAULT_ALLOWED_ALGORITHMS))]


def _enforce_allowed_issuers(
    effective_issuer: str | list[str] | None,
    allowed_issuers: list[str],
) -> None:
    """Fail closed unless every issuer used to validate the token is approved.

    Multi-tenant spoofing defence (Epic 16 R.9 / audit RT-SPOOF-F1). In discovery
    mode the ``effective_issuer`` is whatever issuer the caller passed for
    discovery, so the idiomatic middleware pattern (read ``iss`` from the untrusted
    token, pass it as the issuer, validate) lets an attacker stand up their
    own tenant, mint a validly-signed token, and pass — only the app's own
    ``iss``->authz mapping would stop it. Pinning an approved issuer set rejects
    the discovery result *before* it is trusted. Configured but unresolvable ->
    fail closed rather than skip the check.

    Raises:
        InvalidIssuerException: If the effective issuer is not in ``allowed_issuers``
            (or no issuer could be resolved to check).
    """
    allowed = set(allowed_issuers)
    if isinstance(effective_issuer, str):
        candidates = [effective_issuer]
    elif effective_issuer:
        candidates = list(effective_issuer)
    else:
        candidates = []
    if not candidates:
        raise InvalidIssuerException(
            "allowed_issuers is configured but no issuer was resolved to check "
            "against; refusing to validate without a pinned issuer",
            details={"allowed_issuers": sorted(allowed)},
        )
    for iss in candidates:
        if iss not in allowed:
            raise InvalidIssuerException(
                f"Issuer '{iss}' is not in the configured allowed_issuers",
                details={"issuer": iss, "allowed_issuers": sorted(allowed)},
            )


def _require_discovery_issuer_listed(
    discovery_issuer: str | list[str],
    token_issuers: list[str],
) -> None:
    """Refuse a discovery document whose issuer ``token_issuers`` does not name.

    ``token_issuers`` says which ``iss`` values one provider's keys may sign.
    Without this, a caller that builds the discovery address from the token's
    ``iss`` would accept a token signed by any provider's keys and carrying a
    listed ``iss``.

    Raises:
        InvalidIssuerException: If the discovery issuer is not in
            *token_issuers*.
    """
    if discovery_issuer not in token_issuers:
        raise InvalidIssuerException(
            "The discovery document's issuer is not in token_issuers; add it, "
            "or pin it as the single entry of allowed_issuers",
            details={
                "issuer": discovery_issuer,
                "token_issuers": sorted(token_issuers),
            },
        )


_MEDIA_TYPE_PREFIX = "application/"


def reject_non_access_token_type(jwt: str) -> None:
    """Reject a JWT whose ``typ`` header names a kind other than an access token.

    RFC 9701 §8.1: resource servers "MUST therefore check the typ JWT header
    value of received JWT-encoded access tokens". The ``typ`` values of
    :class:`AccessTokenTypeErrorKind` are rejected, compared case-insensitively
    and with or without the ``application/`` prefix (RFC 7515 §4.1.9). Any
    other ``typ``, such as ``at+jwt`` or ``JWT``, or none, passes. A header
    that cannot be read passes here and fails when the token is decoded.

    Raises:
        AccessTokenTypeError: If ``typ`` names another JWT kind.
    """
    try:
        typ = get_unverified_header(jwt).get("typ")
    except PyJWTError:
        return
    if not isinstance(typ, str):
        return
    media_type = typ.lower().removeprefix(_MEDIA_TYPE_PREFIX)
    try:
        kind = AccessTokenTypeErrorKind(media_type)
    except ValueError:
        return
    raise AccessTokenTypeError(kind)


def decode_with_config(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    issuer: str | list[str] | None = None,
    *,
    accept_token_issuers: bool = False,
) -> dict:
    """
    Decode and validate JWT using the token validation configuration.

    Args:
        jwt: The JWT token to decode
        token_validation_config: Token validation configuration with a key set.
            ``algorithms=None`` means ``DEFAULT_ALLOWED_ALGORITHMS``.
        issuer: Optional issuer override (from discovery document)
        accept_token_issuers: With a discovery issuer, check ``iss`` against
            ``token_validation_config.token_issuers`` when that is set,
            instead of the discovery issuer. For access tokens only: an ID
            Token or Logout Token must carry the OP's own issuer (OIDC Core
            §3.1.3.7 step 2, Back-Channel Logout 1.0 §2.6).

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If the key is missing or ``algorithms`` is an
            empty list
    """
    if not token_validation_config.key:
        raise ConfigurationException("Token validation configuration must have a key")
    _reject_empty_algorithms(token_validation_config)

    # Warn when discovery issuer overrides a user-supplied multi-issuer list
    if issuer is not None and isinstance(token_validation_config.issuer, list):
        logger.warning(
            "Discovery issuer overrides configured multi-issuer list; "
            "multi-issuer is not supported in discovery mode"
        )

    token_issuers = (
        token_validation_config.token_issuers
        if issuer is not None and accept_token_issuers
        else None
    )

    # Multi-tenant issuer pinning (OPT-IN): only when the caller sets
    # allowed_issuers. When it is None (the default) this is skipped entirely and
    # discovery stays authoritative — default behaviour is unchanged. When set,
    # the issuer used to validate the token (the discovery issuer in disco mode,
    # else the configured issuer) MUST be in the approved set, checked before
    # decode so an attacker's own tenant is rejected before the discovery result
    # is trusted (audit RT-SPOOF-F1).
    if token_validation_config.allowed_issuers is not None:
        effective_issuer = (
            issuer if issuer is not None else token_validation_config.issuer
        )
        _enforce_allowed_issuers(
            effective_issuer, token_validation_config.allowed_issuers
        )
    elif issuer is not None and token_issuers:
        _require_discovery_issuer_listed(issuer, token_issuers)

    if token_issuers is not None:
        expected_issuer: str | list[str] | None = token_issuers
    elif issuer is not None:
        expected_issuer = issuer
    else:
        expected_issuer = token_validation_config.issuer

    return decode_and_validate_jwt(
        jwt=jwt,
        key=token_validation_config.key,
        algorithms=resolve_algorithms(jwt, token_validation_config.algorithms),
        audience=token_validation_config.audience,
        issuer=expected_issuer,
        options=token_validation_config.options,
        leeway=token_validation_config.leeway,
        subject=token_validation_config.subject,
    )


def validate_claims(
    decoded_token: dict,
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate claims using custom sync validator if provided.

    Args:
        decoded_token: Decoded token claims
        token_validation_config: Token validation configuration

    Raises:
        TokenValidationException: If claims validation fails
    """
    if token_validation_config.claims_validator:
        try:
            token_validation_config.claims_validator(decoded_token)
        except TokenValidationException as e:
            # A validator that rejected via ClaimsValidationError (or any
            # TokenValidationException) already carries a structured reason. Log
            # it server-side (parity with the generic branch below) and
            # propagate it unwrapped rather than flattening the reason.
            logger.info("Claims validation rejected the token: %s", e)
            raise
        except Exception as e:
            logger.error(f"Claims validation failed: {e!s}")
            raise TokenValidationException(
                f"Claims validation failed: {e!s}",
                token_part="payload",
                details={"error": str(e)},
            ) from e


async def validate_async_claims(
    decoded_token: dict,
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate claims using custom validator if provided (supports both sync and async).

    This function handles both synchronous and asynchronous claims validators,
    making it suitable for use in async contexts where the validator type is unknown.

    Args:
        decoded_token: Decoded token claims
        token_validation_config: Token validation configuration

    Raises:
        TokenValidationException: If claims validation fails
    """
    if token_validation_config.claims_validator:
        try:
            if inspect.iscoroutinefunction(token_validation_config.claims_validator):
                await token_validation_config.claims_validator(decoded_token)
            else:
                token_validation_config.claims_validator(decoded_token)
        except TokenValidationException as e:
            # Preserve a ClaimsValidationError's structured reason (see the sync
            # path); log it server-side, then propagate unwrapped. Only
            # non-library exceptions are wrapped generically.
            logger.info("Claims validation rejected the token: %s", e)
            raise
        except Exception as e:
            logger.error(f"Claims validation failed: {e!s}")
            raise TokenValidationException(
                f"Claims validation failed: {e!s}",
                token_part="payload",
                details={"error": str(e)},
            ) from e


def build_resolved_config(
    original_config: TokenValidationConfig,
    key_dict: dict,
    alg: str,
) -> TokenValidationConfig:
    """Build a resolved TokenValidationConfig with a discovered key and algorithm.

    This avoids repeating the full constructor call whenever the validation
    pipeline resolves a signing key from JWKS.

    Args:
        original_config: The caller-supplied validation config.
        key_dict: The JWK dict selected from the JWKS response.
        alg: The signing algorithm resolved from the key or JWT header.

    Returns:
        A new TokenValidationConfig with the resolved key and algorithm.

    Raises:
        TokenValidationException: If the resolved algorithm is not in the
            caller's ``algorithms``, or in ``DEFAULT_ALLOWED_ALGORITHMS`` when
            ``algorithms`` is ``None``.
    """
    # The resolved alg equals the JWT header alg whenever the header carries
    # one (find_key_by_kid rejects a key whose alg differs), and decode pins
    # verification to [alg], so this membership check gates the header alg.
    _require_allowed_alg(
        alg,
        sorted(DEFAULT_ALLOWED_ALGORITHMS)
        if original_config.algorithms is None
        else original_config.algorithms,
    )
    return TokenValidationConfig(
        perform_disco=original_config.perform_disco,
        key=key_dict,
        audience=original_config.audience,
        algorithms=[alg],
        issuer=original_config.issuer,
        subject=original_config.subject,
        options=original_config.options,
        claims_validator=original_config.claims_validator,
        require_https=original_config.require_https,
        leeway=original_config.leeway,
        # Propagate the issuer allowlist so the disco/retry paths (which validate
        # via this resolved config) still enforce issuer pinning.
        allowed_issuers=original_config.allowed_issuers,
        token_issuers=original_config.token_issuers,
        # Preserve the injected discovery policy so a resolved config stays a
        # faithful copy of the caller's config.
        discovery_policy=original_config.discovery_policy,
        required_binding=original_config.required_binding,
        dpop=original_config.dpop,
    )


def log_validation_start(
    jwt: str, token_validation_config: TokenValidationConfig
) -> None:
    """
    Log validation start information.

    Args:
        jwt: The JWT token (will be redacted in logs)
        token_validation_config: Token validation configuration
    """
    logger.info(f"Starting token validation, token: {redact_token(jwt)}")
    logger.debug(
        f"Validation config - perform_disco: {token_validation_config.perform_disco}, "
        f"audience: {token_validation_config.audience}",
    )


def log_validation_success(decoded_token: dict) -> None:
    """
    Log successful validation.

    Args:
        decoded_token: The decoded token claims
    """
    logger.info(
        f"Token validation successful, subject: {'[present]' if 'sub' in decoded_token else '[absent]'}",
    )
    logger.debug(f"Decoded token claims: {list(decoded_token.keys())}")


__all__ = [
    "DISCOVERY_AND_JWKS_FAILURES",
    "build_resolved_config",
    "decode_with_config",
    "discovery_failure",
    "jwks_failure",
    "keep_signature_verdict_on_failed_refresh",
    "log_validation_start",
    "log_validation_success",
    "resolve_algorithms",
    "validate_async_claims",
    "validate_claims",
    "validate_config_for_manual_validation",
    "validate_disco_response",
    "validate_jwks_response",
    "validate_jwks_uri",
]
