"""
Shared business logic for token client operations.

This module contains the common processing logic used by both sync and async
token client implementations, reducing code duplication.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from ..oidc_constants import TokenResponse
from .client_assertion import apply_private_key_jwt
from .client_auth import basic_auth_credentials
from .dpop import create_dpop_proof
from .error_handlers import (
    handle_auth_code_token_error,
    handle_refresh_token_error,
    handle_token_error,
)
from .models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenErrorKind,
)
from .mtls import apply_mtls_client_auth
from .response_processors import (
    parse_auth_code_token_response,
    parse_refresh_token_response,
    parse_token_response,
)


def log_token_request(request: ClientCredentialsTokenRequest) -> None:
    """Log token request."""
    logger.info(
        f"Requesting client credentials token from {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}, Scope: {request.scope}")


def log_token_status(status_code: int) -> None:
    """Log token response status code."""
    logger.debug(f"Token request status code: {status_code}")


def log_token_success(token_response: ClientCredentialsTokenResponse) -> None:
    """Log successful token fetch."""
    if token_response.is_successful and token_response.token:
        logger.info("Client credentials token request successful")
        logger.debug(
            f"Token type: {token_response.token.get('token_type')}, "
            f"Expires in: {token_response.token.get('expires_in')} seconds",
        )


def prepare_token_request_data(
    request: ClientCredentialsTokenRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for a token request.

    Returns:
        ``(data, headers, auth)`` where *auth* is the HTTP Basic tuple for
        ``client_secret`` authentication, or ``None`` when ``private_key_jwt``
        is used (the assertion is carried in the body).
    """
    params: dict[str, str] = {"grant_type": "client_credentials"}
    if request.scope is not None:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth: tuple[str, str] | None = None
    if request.private_key_jwt is not None:
        apply_private_key_jwt(
            params,
            request.private_key_jwt,
            client_id=request.client_id,
            default_audience=request.address,
        )
    elif request.mtls is not None:
        # RFC 8705 §2: mTLS client auth — certificate is presented at the TLS
        # layer, client_id goes in the body, no Authorization header.
        apply_mtls_client_auth(params, client_id=request.client_id)
    elif request.client_secret is not None:
        # ``is not None`` (not truthiness) mirrors the auth-code/refresh
        # branches so an empty-string secret is handled identically here.
        auth = basic_auth_credentials(request.client_id, request.client_secret)
    else:
        params["client_id"] = request.client_id

    return params, headers, auth


def process_token_response(
    response: httpx.Response,
) -> ClientCredentialsTokenResponse:
    """
    Process token response.

    Args:
        response: HTTP response from token endpoint

    Returns:
        ClientCredentialsTokenResponse with parsed token or error
    """
    log_token_status(response.status_code)

    try:
        # Parse response using shared logic
        token_response = parse_token_response(response)
        log_token_success(token_response)
        return token_response
    except Exception as e:
        return handle_token_error(e)


# ============================================================================
# Authorization Code Token Exchange
# ============================================================================


def log_auth_code_token_request(
    request: AuthorizationCodeTokenRequest,
) -> None:
    """Log authorization code token exchange request."""
    logger.info(
        f"Exchanging authorization code at {redact_url(request.address)}",
    )
    logger.debug(f"Client ID: {request.client_id}")


def prepare_auth_code_token_request_data(
    request: AuthorizationCodeTokenRequest,
    dpop_nonce: str | None = None,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for auth code exchange.

    Args:
        request: The authorization code token exchange request.
        dpop_nonce: Server-provided DPoP nonce to embed in the proof when the
            request is DPoP-bound and a prior ``use_dpop_nonce`` challenge was
            returned (RFC 9449 §8).

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": request.code,
        "redirect_uri": request.redirect_uri,
    }
    if request.code_verifier is not None:
        params["code_verifier"] = request.code_verifier
    if request.scope is not None:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if request.dpop_key is not None:
        # RFC 9449: bind the issued tokens to the client's key. The token-
        # endpoint proof carries no ``ath`` (that is reserved for resource-
        # server requests, which hash the access token).
        headers["DPoP"] = create_dpop_proof(
            request.dpop_key, "POST", request.address, nonce=dpop_nonce
        )

    auth: tuple[str, str] | None = None
    if request.private_key_jwt is not None:
        # RFC 7523: private_key_jwt assertion in body, no auth header.
        apply_private_key_jwt(
            params,
            request.private_key_jwt,
            client_id=request.client_id,
            default_audience=request.address,
        )
    elif request.mtls is not None:
        # RFC 8705 §2: mTLS client auth — certificate is presented at the TLS
        # layer, client_id goes in the body, no Authorization header.
        apply_mtls_client_auth(params, client_id=request.client_id)
    elif request.client_secret is not None:
        # RFC 6749 §2.3.1: use Basic auth for confidential clients;
        # client_id is carried in the auth header, not the body.
        auth = basic_auth_credentials(request.client_id, request.client_secret)
    else:
        # Public client: include client_id in the request body
        params["client_id"] = request.client_id

    return params, headers, auth


def dpop_token_type_error(token: object) -> str | None:
    """Why a DPoP-bound request's token response is not ``token_type=DPoP``.

    RFC 9449 §5: a DPoP-bound access token is issued with ``token_type``
    ``DPoP``; a server that ignored the proof returns ``Bearer``.  Token types
    compare case-insensitively (RFC 6749 §7.1).

    Returns:
        ``None`` when ``token_type`` is ``DPoP``, otherwise the error message.
    """
    token_type = (
        token.get(TokenResponse.TOKEN_TYPE.value) if isinstance(token, dict) else None
    )
    expected = TokenResponse.DPOP_TOKEN_TYPE.value
    if isinstance(token_type, str) and token_type.casefold() == expected.casefold():
        return None
    return (
        f"Expected token_type {expected!r} for a DPoP-bound request, got "
        f"{token_type!r} (RFC 9449 §5)"
    )


def process_auth_code_token_response(
    response: httpx.Response,
    *,
    require_dpop_token_type: bool = False,
) -> AuthorizationCodeTokenResponse:
    """Process authorization code token exchange response.

    With *require_dpop_token_type*, a successful response whose
    ``token_type`` is not ``DPoP`` fails with
    :attr:`TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH`.
    """
    log_token_status(response.status_code)

    try:
        token_response = parse_auth_code_token_response(response)
        if require_dpop_token_type and token_response.is_successful:
            error = dpop_token_type_error(token_response.token)
            if error is not None:
                logger.warning(error)
                return AuthorizationCodeTokenResponse(
                    is_successful=False,
                    error=error,
                    error_kind=TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH,
                )
        if token_response.is_successful and token_response.token:
            logger.info("Authorization code token exchange successful")
        return token_response
    except Exception as e:
        return handle_auth_code_token_error(e)


# ============================================================================
# Refresh Token Grant
# ============================================================================


def log_refresh_token_request(request: RefreshTokenRequest) -> None:
    """Log refresh token request."""
    logger.info("Refreshing token at %s", redact_url(request.address))
    logger.debug("Client ID: %s", request.client_id)


def prepare_refresh_token_request_data(
    request: RefreshTokenRequest,
    dpop_nonce: str | None = None,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for refresh grant.

    Args:
        request: The refresh token request.
        dpop_nonce: Server-provided DPoP nonce to embed in the proof after a
            ``use_dpop_nonce`` challenge (RFC 9449 §8).
    """
    params: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": request.refresh_token,
    }
    if request.scope is not None:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if request.dpop_key is not None:
        # RFC 9449 §5: the refreshed access token stays bound to the key.  A
        # token-endpoint proof carries no ``ath``.
        headers["DPoP"] = create_dpop_proof(
            request.dpop_key, "POST", request.address, nonce=dpop_nonce
        )

    auth: tuple[str, str] | None = None
    if request.private_key_jwt is not None:
        # RFC 7523: private_key_jwt assertion in body, no auth header.
        apply_private_key_jwt(
            params,
            request.private_key_jwt,
            client_id=request.client_id,
            default_audience=request.address,
        )
    elif request.mtls is not None:
        # RFC 8705 §2: mTLS client auth — certificate is presented at the TLS
        # layer, client_id goes in the body, no Authorization header.
        apply_mtls_client_auth(params, client_id=request.client_id)
    elif request.client_secret is not None:
        # RFC 6749 §2.3.1: use Basic auth for confidential clients;
        # client_id is carried in the auth header, not the body.
        auth = basic_auth_credentials(request.client_id, request.client_secret)
    else:
        # Public client: include client_id in the request body
        params["client_id"] = request.client_id

    return params, headers, auth


def process_refresh_token_response(
    response: httpx.Response,
    *,
    require_dpop_token_type: bool = False,
) -> RefreshTokenResponse:
    """Process refresh token grant response.

    With *require_dpop_token_type*, a successful response whose
    ``token_type`` is not ``DPoP`` fails with
    :attr:`TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH`.
    """
    log_token_status(response.status_code)

    try:
        token_response = parse_refresh_token_response(response)
        if require_dpop_token_type and token_response.is_successful:
            error = dpop_token_type_error(token_response.token)
            if error is not None:
                logger.warning(error)
                return RefreshTokenResponse(
                    is_successful=False,
                    error=error,
                    error_kind=TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH,
                )
        if token_response.is_successful and token_response.token:
            logger.info("Token refresh successful")
        return token_response
    except Exception as e:
        return handle_refresh_token_error(e)
