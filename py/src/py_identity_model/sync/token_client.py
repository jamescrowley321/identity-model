"""
Token client (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 token requests.
"""

from collections.abc import Callable

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
    RequestParts,
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
from .http_client import resolve_http_client, retry_with_backoff
from .managed_client import HTTPClient


def _post_token(
    client: httpx.Client,
    url: str,
    prepare: Callable[[], RequestParts],
) -> httpx.Response:
    """POST one token request built by *prepare*.

    *prepare* runs on every attempt, so each one carries a freshly minted
    DPoP proof and client assertion with a new ``jti`` (RFC 9449 §11.1).
    """
    data, headers, auth = prepare()
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


# Retries on 429, 5xx and transport errors, with exponential backoff. Settings
# come from the client's HTTPConfig.
_request_token = retry_with_backoff()(_post_token)

# One attempt, never retried. The authorization code (RFC 6749 §4.1.2) and a
# rotating refresh token are single-use: if a lost response is retried, the
# server sees the credential reused and may revoke the tokens it issued.
_request_single_use_grant = retry_with_backoff(max_retries=0)(_post_token)


def request_client_credentials_token(
    request: ClientCredentialsTokenRequest,
    http_client: HTTPClient | None = None,
) -> ClientCredentialsTokenResponse:
    """
    Request an access token using client credentials flow.

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
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _request_token(
            client, request.address, lambda: prepare_token_request_data(request)
        )
        return process_token_response(response)
    except Exception as e:
        return handle_token_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


def request_authorization_code_token(
    request: AuthorizationCodeTokenRequest,
    http_client: HTTPClient | None = None,
) -> AuthorizationCodeTokenResponse:
    """Exchange an authorization code for tokens.

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
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _request_single_use_grant(
            client,
            request.address,
            lambda: prepare_auth_code_token_request_data(request),
        )
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                response.close()
                response = _request_single_use_grant(
                    client,
                    request.address,
                    lambda: prepare_auth_code_token_request_data(
                        request, dpop_nonce=nonce
                    ),
                )
        return process_auth_code_token_response(
            response, require_dpop_token_type=request.require_dpop_token_type
        )
    except Exception as e:
        return handle_auth_code_token_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


def refresh_token(
    request: RefreshTokenRequest,
    http_client: HTTPClient | None = None,
) -> RefreshTokenResponse:
    """Refresh an OAuth 2.0 access token using a refresh token.

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
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _request_single_use_grant(
            client, request.address, lambda: prepare_refresh_token_request_data(request)
        )
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                response.close()
                response = _request_single_use_grant(
                    client,
                    request.address,
                    lambda: prepare_refresh_token_request_data(
                        request, dpop_nonce=nonce
                    ),
                )
        return process_refresh_token_response(
            response, require_dpop_token_type=request.require_dpop_token_type
        )
    except Exception as e:
        return handle_refresh_token_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


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
