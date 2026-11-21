"""
Token revocation business logic (RFC 7009).

Shared helpers for preparing revocation requests and processing responses.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_auth import apply_client_auth
from .models import TokenRevocationRequest, TokenRevocationResponse


def log_revocation_request(request: TokenRevocationRequest) -> None:
    """Log token revocation request."""
    logger.info(f"Revoking token at {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")
    if request.token_type_hint is not None:
        logger.debug(f"Token type hint: {request.token_type_hint}")


def prepare_revocation_request_data(
    request: TokenRevocationRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for revocation.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {"token": request.token}
    if request.token_type_hint is not None:
        params["token_type_hint"] = request.token_type_hint

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # A blank or whitespace-only secret counts as not provided.
    secret = (
        request.client_secret
        if request.client_secret and request.client_secret.strip()
        else None
    )
    auth = apply_client_auth(params, request, client_secret=secret)

    return params, headers, auth


def process_revocation_response(
    response: httpx.Response,
) -> TokenRevocationResponse:
    """Process token revocation HTTP response.

    Per RFC 7009, a 200 response indicates success regardless of whether
    the token was valid.  No response body is expected.
    """
    logger.debug(f"Revocation response status: {response.status_code}")

    if response.is_success:
        logger.info("Token revocation successful")
        return TokenRevocationResponse(is_successful=True)

    error_msg = (
        f"Token revocation failed with status code: "
        f"{response.status_code}. Response Content: "
        f"{response.text[:200] or '(empty)'}"
    )
    return TokenRevocationResponse(is_successful=False, error=error_msg)


__all__ = [
    "log_revocation_request",
    "prepare_revocation_request_data",
    "process_revocation_response",
]
