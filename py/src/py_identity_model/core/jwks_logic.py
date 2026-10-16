"""
Shared business logic for JWKS operations.

This module contains the common processing logic used by both sync and async
JWKS implementations, reducing code duplication.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..logging_config import logger
from ..logging_utils import redact_url
from .error_handlers import handle_jwks_error
from .response_processors import parse_jwks_response


if TYPE_CHECKING:
    import httpx

    from .config import Config
    from .models import JwksRequest, JwksResponse


def log_jwks_request(jwks_request: JwksRequest) -> None:
    """Log JWKS request."""
    logger.info(f"Fetching JWKS from {redact_url(jwks_request.address)}")


def log_jwks_status(status_code: int) -> None:
    """Log JWKS response status code."""
    logger.debug(f"JWKS request status code: {status_code}")


def log_jwks_success(jwks_response: JwksResponse) -> None:
    """Log successful JWKS fetch."""
    if jwks_response.is_successful and jwks_response.keys:
        logger.info(f"JWKS fetched successfully, found {len(jwks_response.keys)} keys")
        logger.debug(
            f"Key IDs: {[k.kid for k in jwks_response.keys if k.kid is not None]}",
        )


def process_jwks_response(response: httpx.Response, config: Config) -> JwksResponse:
    """
    Process JWKS response.

    Args:
        response: HTTP response from JWKS endpoint
        config: The client's configuration (JWKS size and key-count limits)

    Returns:
        JwksResponse with parsed keys or error
    """
    log_jwks_status(response.status_code)

    try:
        # Parse response using shared logic
        jwks_response = parse_jwks_response(response, config)
        log_jwks_success(jwks_response)
        return jwks_response
    except Exception as e:
        return handle_jwks_error(e)
