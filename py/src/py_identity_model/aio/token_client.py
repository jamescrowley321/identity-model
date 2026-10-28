"""
Token client (asynchronous implementation).

This module provides asynchronous HTTP layer for OAuth 2.0 token requests.
"""

import httpx

from ..core.dpop import extract_dpop_nonce
from ..core.error_handlers import (
    handle_auth_code_token_error,
    handle_refresh_token_error,
    handle_token_error,
)
from ..core.models import (
    AuthorizationCodeTokenRequest,
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenRequest,
    ClientCredentialsTokenResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from ..core.token_client_logic import (
    log_auth_code_token_request,
    log_refresh_token_request,
    log_token_request,
    prepare_auth_code_token_request_data,
    prepare_refresh_token_request_data,
    prepare_token_request_data,
    process_auth_code_token_response,
    process_refresh_token_response,
    process_token_response,
)
from .http_client import resolve_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _request_token(
    client: httpx.AsyncClient,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """
    Request token with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Retry settings come from the client's Config.
    """
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def request_client_credentials_token(
    request: ClientCredentialsTokenRequest,
    http_client: AsyncHTTPClient | None = None,
) -> ClientCredentialsTokenResponse:
    """
    Request an access token using client credentials flow (async).

    Args:
        request: Client credentials token request
        http_client: Optional managed HTTP client.  When ``None``, uses the
            library default client.

    Returns:
        ClientCredentialsTokenResponse: Token response
    """
    log_token_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_token_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _request_token(client, request.address, params, headers, auth)
        return process_token_response(response)
    except Exception as e:
        return handle_token_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


async def request_authorization_code_token(
    request: AuthorizationCodeTokenRequest,
    http_client: AsyncHTTPClient | None = None,
) -> AuthorizationCodeTokenResponse:
    """Exchange an authorization code for tokens (async).

    Args:
        request: Authorization code token exchange request.
        http_client: Optional managed HTTP client.

    Returns:
        AuthorizationCodeTokenResponse with token dict or error.
    """
    log_auth_code_token_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_auth_code_token_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _request_token(client, request.address, params, headers, auth)
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                await response.aclose()
                params, headers, auth = prepare_auth_code_token_request_data(
                    request, dpop_nonce=nonce
                )
                response = await _request_token(
                    client, request.address, params, headers, auth
                )
        return process_auth_code_token_response(
            response, require_dpop_token_type=request.require_dpop_token_type
        )
    except Exception as e:
        return handle_auth_code_token_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


async def refresh_token(
    request: RefreshTokenRequest,
    http_client: AsyncHTTPClient | None = None,
) -> RefreshTokenResponse:
    """Refresh an OAuth 2.0 access token using a refresh token (async).

    Args:
        request: Refresh token request with refresh_token and client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        RefreshTokenResponse with new token dict or error.
    """
    log_refresh_token_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_refresh_token_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _request_token(client, request.address, params, headers, auth)
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                await response.aclose()
                params, headers, auth = prepare_refresh_token_request_data(
                    request, dpop_nonce=nonce
                )
                response = await _request_token(
                    client, request.address, params, headers, auth
                )
        return process_refresh_token_response(
            response, require_dpop_token_type=request.require_dpop_token_type
        )
    except Exception as e:
        return handle_refresh_token_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


__all__ = [
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    "refresh_token",
    "request_authorization_code_token",
    "request_client_credentials_token",
]
