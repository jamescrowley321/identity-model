"""
Discovery document fetching (asynchronous implementation).

This module provides asynchronous HTTP layer for fetching OpenID Connect discovery documents.
"""

import httpx

from ..core.discovery_logic import (
    log_discovery_request,
    process_discovery_response,
)
from ..core.discovery_policy import (
    DiscoveryPolicy,
    discovery_document_url,
    validate_url_scheme,
)
from ..core.error_handlers import handle_discovery_error
from ..core.models import (
    DiscoveryDocumentRequest,
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
)
from .http_client import get_default_async_http_client, retry_with_backoff_async
from .managed_client import AsyncHTTPClient


@retry_with_backoff_async()
async def _fetch_discovery_document(
    client: httpx.AsyncClient, url: str
) -> httpx.Response:
    """
    Fetch discovery document with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Retry settings come from the client's HTTPConfig.
    """
    return await client.get(url)


async def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
    http_client: AsyncHTTPClient | None = None,
) -> DiscoveryDocumentResponse:
    """
    Fetch the discovery document for the requested issuer (async).

    Args:
        disco_doc_req: Discovery document request: the issuer, and the
            policy whose ``location`` selects the URL built from it
        http_client: Optional managed HTTP client.  When ``None``, uses the
            library default client.

    Returns:
        DiscoveryDocumentResponse: Discovery document response
    """
    response = None
    try:
        # Pre-flight: build the URL from the issuer and validate its scheme
        # BEFORE making the HTTP request, so a bad issuer or a plaintext
        # request to a non-loopback host never goes out.
        policy = disco_doc_req.policy or DiscoveryPolicy()
        url = discovery_document_url(disco_doc_req.issuer, policy.location)
        log_discovery_request(url)
        validate_url_scheme(url, policy)

        client = (
            http_client if http_client is not None else get_default_async_http_client()
        )
        response = await _fetch_discovery_document(client, url)
        return process_discovery_response(
            response, policy, requested_issuer=disco_doc_req.issuer
        )
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
