"""
Discovery document fetching (synchronous implementation).

This module provides synchronous HTTP layer for fetching OpenID Connect discovery documents.
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
from .http_client import get_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _fetch_discovery_document(client: httpx.Client, url: str) -> httpx.Response:
    """
    Fetch discovery document with retry logic.

    Automatically retries on 429 (rate limiting) and 5xx errors with
    exponential backoff. Configuration is read from environment variables.
    """
    return client.get(url)


def get_discovery_document(
    disco_doc_req: DiscoveryDocumentRequest,
    http_client: HTTPClient | None = None,
) -> DiscoveryDocumentResponse:
    """
    Fetch discovery document from the specified address.

    Args:
        disco_doc_req: Discovery document request configuration
        http_client: Optional managed HTTP client.  When ``None``, uses the
            thread-local default.

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

        client = http_client.client if http_client else get_http_client()
        response = _fetch_discovery_document(client, disco_doc_req.address)
        return process_discovery_response(
            response, policy, requested_address=disco_doc_req.address
        )
    except Exception as e:
        return handle_discovery_error(e)
    finally:
        if response is not None:
            response.close()


__all__ = [
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "DiscoveryErrorKind",
    "get_discovery_document",
]
