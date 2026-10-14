"""
UserInfo endpoint client (asynchronous implementation).

This module provides asynchronous HTTP layer for OpenID Connect UserInfo requests
per OIDC Core 1.0 Section 5.3.
"""

import httpx

from ..core.dpop import extract_dpop_nonce
from ..core.error_handlers import handle_userinfo_error
from ..core.models import UserInfoRequest, UserInfoResponse
from ..core.userinfo_logic import (
    log_userinfo_request,
    prepare_userinfo_headers,
    process_userinfo_response,
    validate_userinfo_sub,
)
from .http_client import resolve_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _request_userinfo(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
) -> httpx.Response:
    """
    Request UserInfo with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return await client.get(url, headers=headers)


async def get_userinfo(
    request: UserInfoRequest,
    http_client: AsyncHTTPClient | None = None,
) -> UserInfoResponse:
    """
    Get claims about an authenticated user from the UserInfo endpoint (async).

    Args:
        request: UserInfo request with endpoint address and access token
        http_client: Optional managed HTTP client.  When ``None``, uses the
            module-level singleton.

    Returns:
        UserInfoResponse: Response with claims (JSON) or raw JWT string
    """
    log_userinfo_request(request)
    headers = prepare_userinfo_headers(request)

    response = None
    owned_client = None
    try:
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _request_userinfo(client, request.address, headers)
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                await response.aclose()
                headers = prepare_userinfo_headers(request, dpop_nonce=nonce)
                response = await _request_userinfo(client, request.address, headers)
        result = process_userinfo_response(response)
        return validate_userinfo_sub(result, request.expected_sub)
    except Exception as e:
        return handle_userinfo_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


__all__ = [
    "UserInfoRequest",
    "UserInfoResponse",
    "get_userinfo",
]
