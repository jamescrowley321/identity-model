"""
Shared error handling logic for HTTP requests.

This module provides common error handling patterns used by both
sync and async implementations.
"""

import httpx

from ..exceptions import (
    ConfigurationException,
    DiscoveryException,
    DiscoveryHTTPSRequiredError,
    DiscoveryMissingFieldsError,
    DiscoveryParseError,
)
from ..logging_config import logger
from .models import (
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenResponse,
    ClientDeleteResponse,
    ClientRegistrationResponse,
    DiscoveryDocumentResponse,
    JwksResponse,
    PushedAuthorizationResponse,
    RefreshTokenResponse,
    TokenIntrospectionResponse,
    TokenRevocationResponse,
    UserInfoResponse,
)


def handle_discovery_error(e: Exception) -> DiscoveryDocumentResponse:
    """
    Handle errors during discovery document requests.

    Args:
        e: Exception that occurred

    Returns:
        DiscoveryDocumentResponse: Error response
    """
    if isinstance(e, ConfigurationException):
        # Wrap configuration exceptions for backwards compatibility
        if "issuer" in str(e).lower():
            error_msg = f"Invalid issuer: {e!s}"
        elif "url" in str(e).lower():
            error_msg = f"Invalid endpoint URL: {e!s}"
        else:
            error_msg = str(e)
        logger.error(error_msg)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
            error_code=(
                "https_required"
                if isinstance(e, DiscoveryHTTPSRequiredError)
                else "configuration"
            ),
        )

    if isinstance(e, DiscoveryException):
        # Wrap discovery exceptions for backwards compatibility
        if "parameter" in str(e).lower() and "subject" not in str(e).lower():
            error_msg = f"Missing required parameters: {e!s}"
        elif "subject" in str(e).lower() or "response_type" in str(e).lower():
            error_msg = f"Invalid parameter values: {e!s}"
        else:
            error_msg = str(e)
        logger.error(error_msg)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
            error_code=(
                "parse"
                if isinstance(e, DiscoveryParseError)
                else "missing_fields"
                if isinstance(e, DiscoveryMissingFieldsError)
                else "validation"
            ),
            missing_fields=e.fields
            if isinstance(e, DiscoveryMissingFieldsError)
            else (),
        )

    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during discovery document request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DiscoveryDocumentResponse(
            is_successful=False,
            error=error_msg,
            error_code="network",
        )

    error_msg = f"Unexpected error during discovery document request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return DiscoveryDocumentResponse(
        is_successful=False,
        error=error_msg,
        error_code="unexpected",
    )


def handle_jwks_error(e: Exception) -> JwksResponse:
    """
    Handle errors during JWKS requests.

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
        )

    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during JWKS request: {e!s}"
        logger.error(error_msg, exc_info=True)
        return JwksResponse(
            is_successful=False,
            error=error_msg,
        )

    error_msg = f"Unhandled exception during JWKS request: {e!s}"
    logger.error(error_msg, exc_info=True)
    return JwksResponse(
        is_successful=False,
        error=error_msg,
    )


def handle_token_error(e: Exception) -> ClientCredentialsTokenResponse:
    """
    Handle errors during token requests.

    Args:
        e: Exception that occurred

    Returns:
        ClientCredentialsTokenResponse: Error response
    """
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
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during authorization code token exchange: {e!s}"
        logger.error(error_msg, exc_info=True)
        return AuthorizationCodeTokenResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during authorization code token exchange: {e!s}"
    logger.error(error_msg, exc_info=True)
    return AuthorizationCodeTokenResponse(is_successful=False, error=error_msg)


def handle_refresh_token_error(e: Exception) -> RefreshTokenResponse:
    """Handle errors during refresh token requests."""
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
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token introspection: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenIntrospectionResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token introspection: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenIntrospectionResponse(is_successful=False, error=error_msg)


def handle_revocation_error(e: Exception) -> TokenRevocationResponse:
    """Handle errors during token revocation requests."""
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token revocation: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenRevocationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token revocation: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenRevocationResponse(is_successful=False, error=error_msg)


def handle_par_error(e: Exception) -> PushedAuthorizationResponse:
    """Handle errors during pushed authorization requests."""
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during PAR: {e!s}"
        logger.error(error_msg, exc_info=True)
        return PushedAuthorizationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during PAR: {e!s}"
    logger.error(error_msg, exc_info=True)
    return PushedAuthorizationResponse(is_successful=False, error=error_msg)


def handle_registration_error(e: Exception) -> ClientRegistrationResponse:
    """Handle errors during dynamic client registration/management requests."""
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during client registration: {e!s}"
        logger.error(error_msg, exc_info=True)
        return ClientRegistrationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during client registration: {e!s}"
    logger.error(error_msg, exc_info=True)
    return ClientRegistrationResponse(is_successful=False, error=error_msg)


def handle_client_delete_error(e: Exception) -> ClientDeleteResponse:
    """Handle errors during client delete requests (RFC 7592 Section 2.3)."""
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
]
