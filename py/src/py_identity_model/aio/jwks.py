"""
JWKS fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching JSON Web Key Sets.
"""

import httpx

from ..core.discovery_policy import DiscoveryPolicy, validate_url_scheme
from ..core.error_handlers import handle_jwks_error
from ..core.jwks_logic import log_jwks_request, process_jwks_response
from ..core.models import (
    JsonWebAlgorithmsKeyTypes,
    JsonWebKey,
    JsonWebKeyParameterNames,
    JwksRequest,
    JwksResponse,
)
from ..core.parsers import jwks_from_dict
from .http_client import get_default_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _fetch_jwks(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """
    Fetch JWKS with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Retry settings come from the client's Config.
    """
    return await client.get(url)


async def get_jwks(
    jwks_request: JwksRequest,
    http_client: AsyncHTTPClient | None = None,
) -> JwksResponse:
    """
    Fetch JWKS from the specified address (async).

    Args:
        jwks_request: JWKS request configuration
        http_client: Optional managed HTTP client.  When ``None``, uses the
            library default client.

    Returns:
        JwksResponse: JWKS response with keys
    """
    log_jwks_request(jwks_request)
    response = None
    try:
        # Pre-flight: validate URL scheme BEFORE making the HTTP request to
        # prevent ftp://, file://, etc. and (per policy) plaintext HTTP to
        # non-loopback hosts. JWKS validation is part of the public API and
        # accepts caller-supplied URLs, so we cannot rely on the discovery
        # document's scheme check having already vetted the address.
        policy = jwks_request.policy or DiscoveryPolicy()
        validate_url_scheme(jwks_request.address, policy)

        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _fetch_jwks(client, jwks_request.address)
        return process_jwks_response(response, client.config)
    except Exception as e:
        return handle_jwks_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    "get_jwks",
    "jwks_from_dict",
]
