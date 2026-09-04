"""
Core token validation business logic (sync/async agnostic).

This module contains the shared validation logic used by both sync and async
implementations to reduce code duplication.
"""

import inspect

from ..core.jwt_helpers import decode_and_validate_jwt
from ..core.models import (
    DiscoveryDocumentResponse,
    JwksResponse,
    TokenValidationConfig,
)
from ..exceptions import (
    ConfigurationException,
    InvalidIssuerException,
    TokenValidationException,
)
from ..logging_config import logger
from ..logging_utils import redact_token


def validate_disco_response(
    disco_doc_response: DiscoveryDocumentResponse,
) -> None:
    """
    Validate discovery document response.

    Args:
        disco_doc_response: Discovery document response to validate

    Raises:
        TokenValidationException: If discovery response is not successful
    """
    if not disco_doc_response.is_successful:
        error_msg = disco_doc_response.error or "Discovery document request failed"
        logger.error(f"Discovery failed: {error_msg}")
        raise TokenValidationException(error_msg)


def validate_jwks_uri(
    disco_doc_response: DiscoveryDocumentResponse,
) -> str:
    """Validate and return jwks_uri from a discovery document response.

    Args:
        disco_doc_response: A successful discovery document response.

    Returns:
        The non-empty jwks_uri string.

    Raises:
        ConfigurationException: If jwks_uri is missing or empty.
    """
    if not disco_doc_response.jwks_uri:
        raise ConfigurationException("Discovery document missing jwks_uri")
    return disco_doc_response.jwks_uri


def validate_jwks_response(jwks_response: JwksResponse) -> None:
    """
    Validate JWKS response.

    Args:
        jwks_response: JWKS response to validate

    Raises:
        TokenValidationException: If JWKS response is not successful or has no keys
    """
    if not jwks_response.is_successful:
        error_msg = jwks_response.error or "JWKS request failed"
        logger.error(f"JWKS fetch failed: {error_msg}")
        raise TokenValidationException(error_msg)

    if not jwks_response.keys:
        error_msg = "No keys available in JWKS response"
        logger.error(error_msg)
        raise TokenValidationException(error_msg)


def validate_config_for_manual_validation(
    token_validation_config: TokenValidationConfig,
) -> None:
    """
    Validate token configuration for manual validation (non-discovery mode).

    Args:
        token_validation_config: Token validation configuration

    Raises:
        ConfigurationException: If required configuration is missing
    """
    if not token_validation_config.key:
        raise ConfigurationException(
            "TokenValidationConfig.key is required",
        )
    if not token_validation_config.algorithms:
        raise ConfigurationException(
            "TokenValidationConfig.algorithms is required",
        )


def _enforce_allowed_issuers(
    effective_issuer: str | list[str] | None,
    allowed_issuers: list[str],
) -> None:
    """Fail closed unless every issuer used to validate the token is approved.

    Multi-tenant spoofing defence (Epic 16 R.9 / audit RT-SPOOF-F1). In discovery
    mode the ``effective_issuer`` is whatever discovery document the caller pointed
    at, so the idiomatic middleware pattern (read ``iss`` from the untrusted token,
    build ``disco_doc_address`` from it, validate) lets an attacker stand up their
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


def decode_with_config(
    jwt: str,
    token_validation_config: TokenValidationConfig,
    issuer: str | list[str] | None = None,
) -> dict:
    """
    Decode and validate JWT using the token validation configuration.

    Args:
        jwt: The JWT token to decode
        token_validation_config: Token validation configuration with key and algorithms set
        issuer: Optional issuer override (from discovery document)

    Returns:
        dict: Decoded token claims

    Raises:
        TokenValidationException: If token validation fails
        ConfigurationException: If key or algorithms are missing
    """
    if not token_validation_config.key or not token_validation_config.algorithms:
        raise ConfigurationException(
            "Token validation configuration must have key and algorithms set"
        )

    # Warn when discovery issuer overrides a user-supplied multi-issuer list
    if issuer is not None and isinstance(token_validation_config.issuer, list):
        logger.warning(
            "Discovery issuer overrides configured multi-issuer list; "
            "multi-issuer is not supported in discovery mode"
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

    return decode_and_validate_jwt(
        jwt=jwt,
        key=token_validation_config.key,
        algorithms=token_validation_config.algorithms,
        audience=token_validation_config.audience,
        issuer=issuer if issuer is not None else token_validation_config.issuer,
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
        alg: The signing algorithm declared by the key.

    Returns:
        A new TokenValidationConfig with the resolved key and algorithm.
    """
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
        # Preserve the injected discovery policy so a resolved config stays a
        # faithful copy of the caller's config.
        discovery_policy=original_config.discovery_policy,
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
    "build_resolved_config",
    "decode_with_config",
    "log_validation_start",
    "log_validation_success",
    "validate_async_claims",
    "validate_claims",
    "validate_config_for_manual_validation",
    "validate_disco_response",
    "validate_jwks_response",
    "validate_jwks_uri",
]
