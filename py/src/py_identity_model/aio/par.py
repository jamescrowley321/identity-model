"""
Pushed Authorization Requests (asynchronous implementation, RFC 9126).
"""

import httpx

from ..core.dpop import extract_dpop_nonce
from ..core.error_handlers import handle_par_error
from ..core.models import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
    SignedPushedAuthorizationRequest,
)
from ..core.par_logic import (
    log_par_request,
    prepare_par_request_data,
    process_par_response,
)
from .http_client import resolve_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _push_authorization_request(
    client: httpx.AsyncClient,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make PAR request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def push_authorization_request(
    request: PushedAuthorizationRequest | SignedPushedAuthorizationRequest,
    http_client: AsyncHTTPClient | None = None,
) -> PushedAuthorizationResponse:
    """Push authorization parameters to the PAR endpoint (RFC 9126, async).

    Args:
        request: PAR request with authorization parameters, as plain form
            fields or as a signed request object.
        http_client: Optional managed HTTP client.

    Returns:
        PushedAuthorizationResponse with ``request_uri`` and ``expires_in``.
    """
    log_par_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_par_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _push_authorization_request(
            client, request.address, params, headers, auth
        )
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                await response.aclose()
                params, headers, auth = prepare_par_request_data(
                    request, dpop_nonce=nonce
                )
                response = await _push_authorization_request(
                    client, request.address, params, headers, auth
                )
        return process_par_response(response)
    except Exception as e:
        return handle_par_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


__all__ = [
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    "SignedPushedAuthorizationRequest",
    "push_authorization_request",
]
