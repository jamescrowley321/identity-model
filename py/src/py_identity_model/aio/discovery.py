"""
Discovery document fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.discovery_logic import (
    log_discovery_request,
    process_discovery_response,
)
from ..core.discovery_policy import DiscoveryPolicy, validate_url_scheme
from ..core.error_handlers import handle_discovery_error
from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
)
from .http_client import get_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _fetch_discovery_document(
    client: httpx.AsyncClient, url: str
) -> httpx.Response:
    """
    Fetch discovery document with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return await client.get(url)


async def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
    http_client: AsyncHTTPClient | None = None,
) -> DiscoveryDocumentResponse:
    """
    Fetch discovery document from the specified address (async).

    Args:
        disco_doc_req: Discovery document request configuration
        http_client: Optional managed HTTP client.  When ``None``, uses the
            module-level singleton.

    Returns:
        DiscoveryDocumentResponse: Discovery document response
    """
    log_discovery_request(disco_doc_req)
    response = None
    try:
        # Pre-flight: validate URL scheme BEFORE making the HTTP request
        # to prevent sending plaintext requests to non-loopback hosts
        policy = disco_doc_req.policy or DiscoveryPolicy()
        validate_url_scheme(disco_doc_req.address, policy)

        client = http_client.client if http_client else get_async_http_client()
        response = await _fetch_discovery_document(client, disco_doc_req.address)
        return process_discovery_response(response, policy)
    except Exception as e:
        return handle_discovery_error(e)
    finally:
        if response is not None:
            await response.aclose()


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "DiscoveryErrorKind",
    "get_discovery_document",
]
