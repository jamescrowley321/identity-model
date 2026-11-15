"""
Device Authorization Grant (synchronous implementation, RFC 8628).
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
from .http_client import resolve_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _request_device_auth(client, url, data, headers, auth=None):
    """Make device authorization request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def request_device_authorization(
    request: DeviceAuthorizationRequest,
    http_client: HTTPClient | None = None,
) -> DeviceAuthorizationResponse:
    """Request device authorization from the device authorization endpoint (RFC 8628).

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
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _request_device_auth(client, request.address, params, headers, auth)
        return process_device_auth_response(response)
    except Exception as e:
        return handle_device_auth_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


# A single attempt, never retried: RFC 8628 §3.5 leaves the wait between
# polls to the caller's loop, which must not poll faster than ``interval``.
@retry_with_backoff(max_retries=0)
def _poll_device_token(client, url, data, headers, auth=None):
    """Make one device token poll request."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def poll_device_token(
    request: DeviceTokenRequest,
    http_client: HTTPClient | None = None,
) -> DeviceTokenResponse:
    """Poll the token endpoint for device authorization completion (RFC 8628).

    Makes a single poll attempt and never retries it, so the caller's loop
    controls the polling rate (RFC 8628 §3.5). Wait at least the device
    authorization response's ``interval`` (5 seconds when absent) before
    each poll, then check ``error_code`` on the response:

    - ``"authorization_pending"`` - poll again after the current interval
    - ``"slow_down"`` - add 5 seconds to the interval for this and every
      later poll, then poll again
    - any other failure (``"expired_token"``, ``"access_denied"``, other
      errors, or ``error_code`` ``None``) - stop polling. A network error
      also comes back with ``error_code`` ``None``; if you retry it, first
      lengthen the interval, e.g. by doubling it.

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
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _poll_device_token(client, request.address, params, headers, auth)
        return process_device_token_response(response)
    except Exception as e:
        return handle_device_token_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


__all__ = [
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    "poll_device_token",
    "request_device_authorization",
]
