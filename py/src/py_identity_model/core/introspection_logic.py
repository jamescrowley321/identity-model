"""
Token introspection business logic (RFC 7662).

Pure functions for preparing introspection requests and processing responses.
Used by both sync and async implementations.
"""

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_auth import apply_client_auth
from .error_handlers import handle_introspection_error
from .introspection_jwt import (
    INTROSPECTION_JWT_MEDIA_TYPE,
    verify_signed_introspection_response,
)
from .models import (
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
)
from .response_processors import parse_introspection_response


def log_introspection_request(request: TokenIntrospectionRequest) -> None:
    """Log token introspection request."""
    logger.info(f"Introspecting token at {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")
    if request.token_type_hint is not None:
        logger.debug(f"Token type hint: {request.token_type_hint}")


def prepare_introspection_request_data(
    request: TokenIntrospectionRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for introspection.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {"token": request.token}
    if request.token_type_hint is not None:
        params["token_type_hint"] = request.token_type_hint

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if request.signed_response is not None:
        # RFC 9701 §4: ask for the JWT response.
        headers["Accept"] = INTROSPECTION_JWT_MEDIA_TYPE

    auth = apply_client_auth(params, request, client_secret=request.client_secret)

    return params, headers, auth


def discovery_signed_response(
    request: TokenIntrospectionRequest,
) -> SignedIntrospectionOptions | None:
    """``request.signed_response`` when it gets its keys from discovery."""
    signed = request.signed_response
    return signed if signed is not None and signed.discovery_address else None


def log_introspection_status(status_code: int) -> None:
    """Log introspection response status code."""
    logger.debug(f"Introspection response status: {status_code}")


def process_introspection_response(
    response: httpx.Response,
    request: TokenIntrospectionRequest | None = None,
    verified: TokenIntrospectionResponse | None = None,
) -> TokenIntrospectionResponse:
    """Process token introspection HTTP response.

    With ``request.signed_response`` set, a 2xx response must be a verified
    JWT introspection response (RFC 9701 §5). In discovery mode the caller
    verifies it (it needs the keys) and passes the result as *verified*.
    """
    log_introspection_status(response.status_code)

    try:
        if verified is not None:
            result = verified
        elif (
            request is not None
            and request.signed_response is not None
            and response.is_success
        ):
            result = verify_signed_introspection_response(response, request)
        else:
            result = parse_introspection_response(response)
        if result.is_successful and result.claims is not None:
            active = result.claims.get("active", False)
            logger.info(f"Token introspection complete: active={active}")
        return result
    except Exception as e:
        return handle_introspection_error(e)


__all__ = [
    "discovery_signed_response",
    "log_introspection_request",
    "prepare_introspection_request_data",
    "process_introspection_response",
]
