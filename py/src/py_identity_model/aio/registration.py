"""
Dynamic Client Registration (asynchronous implementation, RFC 7591 / RFC 7592).
"""

import httpx

from ..core.error_handlers import (
    handle_client_delete_error,
    handle_registration_error,
)
from ..core.models import (
    ClientDeleteRequest,
    ClientDeleteResponse,
    ClientReadRequest,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    ClientUpdateRequest,
)
from ..core.registration_logic import (
    prepare_management_headers,
    prepare_registration_request,
    prepare_update_request,
    process_delete_response,
    process_read_response,
    process_registration_response,
    process_update_response,
)
from .http_client import get_default_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _post_registration(
    client: httpx.AsyncClient, url: str, json_body: dict, headers: dict
) -> httpx.Response:
    """POST a client registration request with retry logic (async)."""
    return await client.post(url, json=json_body, headers=headers)


@retry_with_backoff_async()
async def _get_client(
    client: httpx.AsyncClient, url: str, headers: dict
) -> httpx.Response:
    """GET a client configuration with retry logic (async)."""
    return await client.get(url, headers=headers)


@retry_with_backoff_async()
async def _put_client(
    client: httpx.AsyncClient, url: str, json_body: dict, headers: dict
) -> httpx.Response:
    """PUT an updated client configuration with retry logic (async)."""
    return await client.put(url, json=json_body, headers=headers)


@retry_with_backoff_async()
async def _delete_client(
    client: httpx.AsyncClient, url: str, headers: dict
) -> httpx.Response:
    """DELETE a client with retry logic (async)."""
    return await client.delete(url, headers=headers)


async def register_client(
    request: ClientRegistrationRequest,
    http_client: AsyncHTTPClient | None = None,
) -> ClientRegistrationResponse:
    """Register a client at the registration endpoint (RFC 7591 Section 3, async).

    Args:
        request: Registration request with client metadata.
        http_client: Optional managed HTTP client.

    Returns:
        ClientRegistrationResponse with the issued ``client_id`` and, for
        protected clients, ``registration_access_token`` /
        ``registration_client_uri`` for subsequent management (RFC 7592).
    """
    response = None
    try:
        body, headers = prepare_registration_request(request)
        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _post_registration(client, request.address, body, headers)
        return process_registration_response(response)
    except Exception as e:
        return handle_registration_error(e)
    finally:
        if response is not None:
            await response.aclose()


async def read_client(
    request: ClientReadRequest,
    http_client: AsyncHTTPClient | None = None,
) -> ClientRegistrationResponse:
    """Read a client's current configuration (RFC 7592 Section 2.1, async).

    Args:
        request: Read request targeting ``registration_client_uri``.
        http_client: Optional managed HTTP client.

    Returns:
        ClientRegistrationResponse with the current client metadata.
    """
    response = None
    try:
        headers = prepare_management_headers(request.registration_access_token)
        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _get_client(client, request.address, headers)
        return process_read_response(response)
    except Exception as e:
        return handle_registration_error(e)
    finally:
        if response is not None:
            await response.aclose()


async def update_client(
    request: ClientUpdateRequest,
    http_client: AsyncHTTPClient | None = None,
) -> ClientRegistrationResponse:
    """Update a client's configuration (RFC 7592 Section 2.2, async).

    Args:
        request: Update request with the full client metadata (including
            ``client_id``).
        http_client: Optional managed HTTP client.

    Returns:
        ClientRegistrationResponse with the persisted client metadata.
    """
    response = None
    try:
        body, headers = prepare_update_request(request)
        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _put_client(client, request.address, body, headers)
        return process_update_response(response)
    except Exception as e:
        return handle_registration_error(e)
    finally:
        if response is not None:
            await response.aclose()


async def delete_client(
    request: ClientDeleteRequest,
    http_client: AsyncHTTPClient | None = None,
) -> ClientDeleteResponse:
    """Deregister a client (RFC 7592 Section 2.3, async).

    Args:
        request: Delete request targeting ``registration_client_uri``.
        http_client: Optional managed HTTP client.

    Returns:
        ClientDeleteResponse; ``is_successful`` is ``True`` for a 204 response.
    """
    response = None
    try:
        headers = prepare_management_headers(request.registration_access_token)
        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _delete_client(client, request.address, headers)
        return process_delete_response(response)
    except Exception as e:
        return handle_client_delete_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "ClientDeleteRequest",
    "ClientDeleteResponse",
    "ClientReadRequest",
    "ClientRegistrationRequest",
    "ClientRegistrationResponse",
    "ClientUpdateRequest",
    "delete_client",
    "read_client",
    "register_client",
    "update_client",
]
