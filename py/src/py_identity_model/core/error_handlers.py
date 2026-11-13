"""
Shared error handling logic for HTTP requests.

This module provides common error handling patterns used by both
sync and async implementations.
"""

import httpx

from ..exceptions import (
    ConfigurationException,
    DiscoveryHTTPSRequiredError,
    DiscoveryIssuerMismatchError,
    DiscoveryMissingFieldsError,
    DiscoveryParseError,
    DiscoveryValidationError,
    NetworkException,
)
from ..logging_config import logger
from .models import (
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenResponse,
    ClientDeleteResponse,
    ClientRegistrationResponse,
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
    JwksErrorKind,
    JwksResponse,
    PushedAuthorizationResponse,
    RefreshTokenResponse,
    TokenIntrospectionResponse,
    TokenRevocationResponse,
    UserInfoResponse,
)


def raise_configuration_error(e: Exception) -> None:
    """Re-raise *e* if it is a :class:`ConfigurationException`.

    A request the caller misconfigured (for example a ``client_auth_method``
    whose credential is missing) is a programming error, not a protocol
    outcome, so request functions raise it instead of returning a failed
    response.
    """
    if isinstance(e, ConfigurationException):
        raise e


def _discovery_validation_failure(
    e: DiscoveryValidationError,
) -> DiscoveryDocumentResponse:
    """The failed response for a discovery document that failed validation."""
    logger.error(str(e))
    if isinstance(e, DiscoveryMissingFieldsError):
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=str(e),
            error_kind=DiscoveryErrorKind.MISSING_FIELDS,
            missing_fields=e.fields,
        )
    if isinstance(e, DiscoveryIssuerMismatchError):
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=str(e),
            error_kind=DiscoveryErrorKind.ISSUER_MISMATCH,
            requested_issuer=e.requested,
            returned_issuer=e.returned,
        )
    return DiscoveryDocumentResponse(
        is_successful=False,
        error=str(e),
        error_kind=(
            DiscoveryErrorKind.INVALID_JSON
            if isinstance(e, DiscoveryParseError)
            else DiscoveryErrorKind.INVALID_DOCUMENT
        ),
    )


def handle_discovery_error(e: Exception) -> DiscoveryDocumentResponse:
    """
    Handle errors during discovery document requests.

    The failed response's ``error_kind`` is chosen by the exception's type.

    Args:
        e: Exception that occurred

    Returns:
        DiscoveryDocumentResponse: Error response
    """
    if isinstance(e, ConfigurationException):
        logger.error(str(e))
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=str(e),
            error_kind=(
                DiscoveryErrorKind.HTTPS_REQUIRED
                if isinstance(e, DiscoveryHTTPSRequiredError)
                else DiscoveryErrorKind.INVALID_CONFIGURATION
            ),
        )

    if isinstance(e, DiscoveryValidationError):
        return _discovery_validation_failure(e)

    if isinstance(e, NetworkException):
        # A blocked redirect (check_no_redirect) is an unexpected 3xx status.
        logger.error(str(e))
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=str(e),
            error_kind=DiscoveryErrorKind.UNEXPECTED_STATUS,
            status_code=e.status_code,
        )

    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during discovery document request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
            error_kind=DiscoveryErrorKind.NETWORK_ERROR,
        )

    error_msg = f"Unexpected error during discovery document request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return DiscoveryDocumentResponse(
        is_successful=False,
        error=error_msg,
        error_kind=DiscoveryErrorKind.UNEXPECTED_ERROR,
    )


def handle_jwks_error(e: Exception) -> JwksResponse:
    """
    Handle errors during JWKS requests.

    The failed response's ``error_kind`` is chosen by the exception's type.

    Args:
        e: Exception that occurred

    Returns:
        JwksResponse: Error response
    """
    if isinstance(e, ConfigurationException):
        error_msg = f"Invalid JWKS endpoint URL: {e!s}"
        logger.error(error_msg)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
            error_kind=JwksErrorKind.INVALID_CONFIGURATION,
        )

    if isinstance(e, NetworkException):
        # A blocked redirect (check_no_redirect) is an unexpected 3xx status.
        logger.error(str(e))
        return JwksResponse(
            is_successful=False,
            error=str(e),
            error_kind=JwksErrorKind.UNEXPECTED_STATUS,
            status_code=e.status_code,
        )

    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during JWKS request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
            error_kind=JwksErrorKind.NETWORK_ERROR,
        )

    error_msg = f"Unhandled exception during JWKS request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return JwksResponse(
        is_successful=False,
        error=error_msg,
        error_kind=JwksErrorKind.UNEXPECTED_ERROR,
    )


def handle_token_error(e: Exception) -> ClientCredentialsTokenResponse:
    """
    Handle errors during token requests.

    Args:
        e: Exception that occurred

    Returns:
        ClientCredentialsTokenResponse: Error response
    """
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientCredentialsTokenResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unexpected error during token request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return ClientCredentialsTokenResponse(
        is_successful=False,
        error=error_msg,
    )


def handle_auth_code_token_error(
    e: Exception,
) -> AuthorizationCodeTokenResponse:
    """Handle errors during authorization code token exchange."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during authorization code token exchange: {e!s}"
        logger.error(error_msg, exc_info=True)
        return AuthorizationCodeTokenResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during authorization code token exchange: {e!s}"
    logger.error(error_msg, exc_info=True)
    return AuthorizationCodeTokenResponse(is_successful=False, error=error_msg)


def handle_refresh_token_error(e: Exception) -> RefreshTokenResponse:
    """Handle errors during refresh token requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token refresh: {e!s}"
        logger.error(error_msg, exc_info=True)
        return RefreshTokenResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token refresh: {e!s}"
    logger.error(error_msg, exc_info=True)
    return RefreshTokenResponse(is_successful=False, error=error_msg)


def handle_introspection_error(
    e: Exception,
) -> TokenIntrospectionResponse:
    """Handle errors during token introspection requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token introspection: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenIntrospectionResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token introspection: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenIntrospectionResponse(is_successful=False, error=error_msg)


def handle_revocation_error(e: Exception) -> TokenRevocationResponse:
    """Handle errors during token revocation requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token revocation: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenRevocationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token revocation: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenRevocationResponse(is_successful=False, error=error_msg)


def handle_par_error(e: Exception) -> PushedAuthorizationResponse:
    """Handle errors during pushed authorization requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during PAR: {e!s}"
        logger.error(error_msg, exc_info=True)
        return PushedAuthorizationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during PAR: {e!s}"
    logger.error(error_msg, exc_info=True)
    return PushedAuthorizationResponse(is_successful=False, error=error_msg)


def handle_registration_error(e: Exception) -> ClientRegistrationResponse:
    """Handle errors during dynamic client registration/management requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during client registration: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientRegistrationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during client registration: {e!s}"
    logger.error(error_msg, exc_info=True)
    return ClientRegistrationResponse(is_successful=False, error=error_msg)


def handle_client_delete_error(e: Exception) -> ClientDeleteResponse:
    """Handle errors during client delete requests (RFC 7592 Section 2.3)."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during client delete: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientDeleteResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during client delete: {e!s}"
    logger.error(error_msg, exc_info=True)
    return ClientDeleteResponse(is_successful=False, error=error_msg)


def handle_userinfo_error(e: Exception) -> UserInfoResponse:
    """
    Handle errors during UserInfo requests.

    Args:
        e: Exception that occurred

    Returns:
        UserInfoResponse: Error response
    """
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during UserInfo request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return UserInfoResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unexpected error during UserInfo request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return UserInfoResponse(
        is_successful=False,
        error=error_msg,
    )


__all__ = [
    "handle_auth_code_token_error",
    "handle_client_delete_error",
    "handle_discovery_error",
    "handle_introspection_error",
    "handle_jwks_error",
    "handle_par_error",
    "handle_registration_error",
    "handle_revocation_error",
    "handle_token_error",
    "handle_userinfo_error",
    "raise_configuration_error",
]
