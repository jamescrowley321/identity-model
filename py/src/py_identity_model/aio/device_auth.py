"""
Device Authorization Grant (asynchronous implementation, RFC 8628).
"""

from ..core.device_auth_logic import (
    handle_device_auth_error,
    handle_device_token_error,
    log_device_auth_request,
    log_device_token_request,
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
    process_device_auth_response,
    process_device_token_response,
)
from ..core.models import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)
from .http_client import resolve_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _request_device_auth(client, url, data, headers, auth=None):
    """Make device authorization request with retry logic (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def request_device_authorization(
    request: DeviceAuthorizationRequest,
    http_client: AsyncHTTPClient | None = None,
) -> DeviceAuthorizationResponse:
    """Request device authorization from the device authorization endpoint (RFC 8628, async).

    Args:
        request: Device authorization request with client credentials.
        http_client: Optional managed HTTP client.

    Returns:
        DeviceAuthorizationResponse with ``device_code``, ``user_code``,
        and ``verification_uri`` for user display.
    """
    log_device_auth_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_device_auth_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _request_device_auth(
            client, request.address, params, headers, auth
        )
        return process_device_auth_response(response)
    except Exception as e:
        return handle_device_auth_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


# A single attempt, never retried: RFC 8628 §3.5 leaves the wait between
# polls to the caller's loop, which must not poll faster than ``interval``.
@retry_with_backoff_async(max_retries=0)
async def _poll_device_token(client, url, data, headers, auth=None):
    """Make one device token poll request (async)."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return await client.post(url, **kwargs)


async def poll_device_token(
    request: DeviceTokenRequest,
    http_client: AsyncHTTPClient | None = None,
) -> DeviceTokenResponse:
    """Poll the token endpoint for device authorization completion (RFC 8628, async).

    Makes a single poll attempt and never retries it, so the caller's loop
    controls the polling rate (RFC 8628 §3.5). See
    :func:`py_identity_model.sync.device_auth.poll_device_token` for how to
    act on ``error_code``.

    Args:
        request: Device token request with device code.
        http_client: Optional managed HTTP client.

    Returns:
        DeviceTokenResponse with ``token`` on success or ``error_code``
        indicating poll status.
    """
    log_device_token_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_device_token_request_data(request)
        client, owned_client = resolve_async_http_client(request.mtls, http_client)
        response = await _poll_device_token(
            client, request.address, params, headers, auth
        )
        return process_device_token_response(response)
    except Exception as e:
        return handle_device_token_error(e)
    finally:
        if response is not None:
            await response.aclose()
        if owned_client is not None:
            await owned_client.aclose()


__all__ = [
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    "poll_device_token",
    "request_device_authorization",
]
