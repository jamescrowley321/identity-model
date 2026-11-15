"""
Token Exchange business logic per RFC 8693.

Pure functions for preparing token exchange requests and processing responses.
"""

import json

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_auth import apply_client_auth
from .models import TokenExchangeRequest, TokenExchangeResponse
from .validators import validate_absolute_uri_without_fragment


_TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"


def log_token_exchange_request(request: TokenExchangeRequest) -> None:
    """Log token exchange request."""
    logger.info("Exchanging token at %s", redact_url(request.address))
    logger.debug(
        "Client ID: %s, Subject token type: %s",
        request.client_id,
        request.subject_token_type,
    )


def _validate_request_params(request: TokenExchangeRequest) -> None:
    """Validate token exchange request parameters.

    Raises:
        ValueError: If required fields are empty, ``actor_token`` is set
            without ``actor_token_type`` (or vice versa), or optional fields
            are empty strings when provided.
        ProtocolParameterError: If ``resource`` is not an absolute URI or has
            a fragment (RFC 8693 §2.1, RFC 8707 §2).
    """
    # Required field: client_id must not be empty
    if not request.client_id:
        raise ValueError("client_id must not be empty")

    # Required fields: subject_token and subject_token_type
    if not request.subject_token:
        raise ValueError("subject_token must not be empty")
    if not request.subject_token_type:
        raise ValueError("subject_token_type must not be empty")

    # RFC 8693 §2.1 — actor_token_type REQUIRED when actor_token present
    if request.actor_token is not None and request.actor_token_type is None:
        raise ValueError(
            "actor_token_type is REQUIRED when actor_token is provided "
            "(RFC 8693 Section 2.1)"
        )

    # actor_token_type without actor_token is meaningless per RFC 8693 §2.1
    if request.actor_token_type is not None and request.actor_token is None:
        raise ValueError(
            "actor_token_type has no meaning without actor_token (RFC 8693 Section 2.1)"
        )

    # Reject empty strings on optional fields when provided
    if request.actor_token is not None and not request.actor_token:
        raise ValueError("actor_token must not be empty when provided")
    if request.actor_token_type is not None and not request.actor_token_type:
        raise ValueError("actor_token_type must not be empty when provided")

    # RFC 8693 §2.1 / RFC 8707 §2: absolute URI, no fragment
    if request.resource:
        validate_absolute_uri_without_fragment(request.resource, "resource")


def prepare_token_exchange_request_data(
    request: TokenExchangeRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for token exchange.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.

    Raises:
        ValueError: If required fields are empty or ``actor_token`` /
            ``actor_token_type`` pairing is invalid (RFC 8693 §2.1).
        ProtocolParameterError: If ``resource`` is not an absolute URI or has
            a fragment.
    """
    _validate_request_params(request)

    params: dict[str, str] = {
        "grant_type": _TOKEN_EXCHANGE_GRANT_TYPE,
        "subject_token": request.subject_token,
        "subject_token_type": request.subject_token_type,
    }

    if request.actor_token is not None:
        params["actor_token"] = request.actor_token
    if request.actor_token_type is not None:
        params["actor_token_type"] = request.actor_token_type
    # Skip empty optional fields to avoid malformed form params
    if request.resource:
        params["resource"] = request.resource
    if request.audience:
        params["audience"] = request.audience
    if request.scope:
        params["scope"] = request.scope
    if request.requested_token_type:
        params["requested_token_type"] = request.requested_token_type

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # RFC 6749 §2.3.1 — client_id excluded from body when using Basic Auth
    auth = apply_client_auth(
        params, request, client_secret=request.client_secret or None
    )

    return params, headers, auth


def _parse_error_response(response: httpx.Response) -> str:
    """Parse error response, extracting RFC 6749 §5.2 fields when possible."""
    try:
        data = response.json()
    except Exception:
        content = response.content[:1024]
        return (
            f"Token exchange failed with status code: "
            f"{response.status_code}. Response Content: {content}"
        )

    if isinstance(data, dict):
        error = data.get("error")
        error_description = data.get("error_description", "")
        if error:
            if error_description:
                return (
                    f"Token exchange failed with status code: "
                    f"{response.status_code}. "
                    f"Error: {error} — {error_description}"
                )
            return (
                f"Token exchange failed with status code: "
                f"{response.status_code}. Error: {error}"
            )
        # No standard RFC 6749 §5.2 ``error`` field. Surface the raw JSON body
        # rather than masking it as "unknown" — providers such as Descope return
        # a non-standard error shape (e.g. errorCode/errorDescription) whose
        # detail is essential for diagnosing the rejection.
        body = json.dumps(data)[:1024]
        return (
            f"Token exchange failed with status code: "
            f"{response.status_code}. Response: {body}"
        )

    content = response.content[:1024]
    return (
        f"Token exchange failed with status code: "
        f"{response.status_code}. Response Content: {content}"
    )


def process_token_exchange_response(
    response: httpx.Response,
) -> TokenExchangeResponse:
    """Process token exchange HTTP response."""
    logger.debug("Token exchange response status: %s", response.status_code)

    if response.is_success:
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            error_msg = "Token exchange response has invalid JSON body"
            logger.error(error_msg)
            return TokenExchangeResponse(is_successful=False, error=error_msg)

        if not isinstance(data, dict):
            error_msg = (
                f"Token exchange response is not a JSON object: {type(data).__name__}"
            )
            logger.error(error_msg)
            return TokenExchangeResponse(is_successful=False, error=error_msg)

        # RFC 6749 §5.1 + RFC 8693 §2.2.1: validate REQUIRED fields
        missing: list[str] = []
        if not isinstance(data.get("access_token"), str) or not data["access_token"]:
            missing.append("access_token")
        if not isinstance(data.get("token_type"), str) or not data["token_type"]:
            missing.append("token_type")

        if missing:
            error_msg = (
                f"Token exchange response missing required fields "
                f"per RFC 6749 Section 5.1: {', '.join(missing)}"
            )
            logger.error(error_msg)
            return TokenExchangeResponse(is_successful=False, error=error_msg)

        # RFC 8693 §2.2.1: issued_token_type is REQUIRED but we tolerate
        # its absence for non-compliant servers; validate type when present
        issued_token_type = data.get("issued_token_type")
        if issued_token_type is not None and not isinstance(issued_token_type, str):
            issued_token_type = None

        logger.info("Token exchange successful")
        return TokenExchangeResponse(
            is_successful=True,
            token=data,
            issued_token_type=issued_token_type,
        )

    error_msg = _parse_error_response(response)
    return TokenExchangeResponse(is_successful=False, error=error_msg)


def handle_token_exchange_error(e: Exception) -> TokenExchangeResponse:
    """Handle errors during token exchange requests."""
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during token exchange: {e!s}"
        logger.error(error_msg, exc_info=True)
        return TokenExchangeResponse(is_successful=False, error=error_msg)

    if isinstance(e, ValueError):
        error_msg = f"Validation error during token exchange: {e!s}"
        logger.error(error_msg)
        return TokenExchangeResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during token exchange: {e!s}"
    logger.error(error_msg, exc_info=True)
    return TokenExchangeResponse(is_successful=False, error=error_msg)


__all__ = [
    "handle_token_exchange_error",
    "log_token_exchange_request",
    "prepare_token_exchange_request_data",
    "process_token_exchange_response",
]
