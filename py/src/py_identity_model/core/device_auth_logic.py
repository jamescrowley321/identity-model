"""
Device Authorization Grant business logic per RFC 8628.

Pure functions for preparing device authorization requests,
processing responses, and handling device token polling.
"""

import json

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_auth import apply_client_auth
from .error_handlers import raise_configuration_error
from .models import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)


# RFC 8628 Section 3.5: error codes during token polling
_POLLING_ERROR_CODES = frozenset(
    {"authorization_pending", "slow_down", "expired_token", "access_denied"}
)

_DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def _coerce_int(value: object) -> int | None:
    """Coerce a JSON numeric value to int, or None if not numeric/finite.

    Handles float-to-int coercion (JSON has no int/float distinction),
    rejects bool, and safely handles float('inf')/float('nan').
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return None
    return None


# ============================================================================
# Phase 1: Device Authorization Request
# ============================================================================


def log_device_auth_request(request: DeviceAuthorizationRequest) -> None:
    """Log device authorization request."""
    logger.info(f"Requesting device authorization from {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}, Scope: {request.scope}")


def prepare_device_auth_request_data(
    request: DeviceAuthorizationRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for device authorization.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {"client_id": request.client_id}
    if request.scope:
        params["scope"] = request.scope

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth = apply_client_auth(
        params, request, client_secret=request.client_secret or None
    )

    return params, headers, auth


def process_device_auth_response(
    response: httpx.Response,
) -> DeviceAuthorizationResponse:
    """Process device authorization HTTP response."""
    logger.debug(f"Device auth response status: {response.status_code}")

    if response.is_success:
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            error_msg = "Device authorization response has invalid JSON body"
            logger.error(error_msg)
            return DeviceAuthorizationResponse(is_successful=False, error=error_msg)

        if not isinstance(data, dict):
            error_msg = (
                f"Device authorization response is not a JSON object: "
                f"{type(data).__name__}"
            )
            logger.error(error_msg)
            return DeviceAuthorizationResponse(is_successful=False, error=error_msg)

        # RFC 8628 Section 3.2: validate REQUIRED fields
        device_code = data.get("device_code")
        user_code = data.get("user_code")
        verification_uri = data.get("verification_uri")

        missing: list[str] = []
        if not device_code:
            missing.append("device_code")
        if not user_code:
            missing.append("user_code")
        if not verification_uri:
            missing.append("verification_uri")

        expires_in = _coerce_int(data.get("expires_in"))
        if expires_in is None or expires_in <= 0:
            missing.append("expires_in")

        if missing:
            error_msg = (
                f"Device authorization response missing required fields "
                f"per RFC 8628 Section 3.2: {', '.join(missing)}"
            )
            logger.error(error_msg)
            return DeviceAuthorizationResponse(is_successful=False, error=error_msg)

        interval = _coerce_int(data.get("interval"))

        logger.info(f"Device authorization successful, user_code: {user_code}")
        return DeviceAuthorizationResponse(
            is_successful=True,
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            verification_uri_complete=data.get("verification_uri_complete"),
            expires_in=expires_in,
            interval=interval,
        )

    error_msg = (
        f"Device authorization request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return DeviceAuthorizationResponse(is_successful=False, error=error_msg)


def handle_device_auth_error(e: Exception) -> DeviceAuthorizationResponse:
    """Handle errors during device authorization requests."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during device authorization: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DeviceAuthorizationResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during device authorization: {e!s}"
    logger.error(error_msg, exc_info=True)
    return DeviceAuthorizationResponse(is_successful=False, error=error_msg)


# ============================================================================
# Phase 2: Device Token Polling
# ============================================================================


def log_device_token_request(request: DeviceTokenRequest) -> None:
    """Log device token polling request."""
    logger.info(f"Polling device token at {redact_url(request.address)}")


def prepare_device_token_request_data(
    request: DeviceTokenRequest,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for device token poll.

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    params: dict[str, str] = {
        "grant_type": _DEVICE_GRANT_TYPE,
        "device_code": request.device_code,
        "client_id": request.client_id,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    auth = apply_client_auth(
        params, request, client_secret=request.client_secret or None
    )

    return params, headers, auth


def _parse_success_response(
    response: httpx.Response,
) -> DeviceTokenResponse:
    """Parse a successful device token HTTP response.

    Validates the JSON body is a dict and returns the token data.
    """
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        error_msg = "Device token response has invalid JSON body"
        logger.error(error_msg)
        return DeviceTokenResponse(is_successful=False, error=error_msg)

    if not isinstance(data, dict):
        error_msg = f"Device token response is not a JSON object: {type(data).__name__}"
        logger.error(error_msg)
        return DeviceTokenResponse(is_successful=False, error=error_msg)

    logger.info("Device token request successful")
    return DeviceTokenResponse(is_successful=True, token=data)


def _parse_error_response(
    response: httpx.Response,
) -> DeviceTokenResponse:
    """Parse a failed device token HTTP response.

    Checks for RFC 8628 polling error codes (``authorization_pending``,
    ``slow_down``, ``expired_token``, ``access_denied``) and returns
    structured error information.
    """
    try:
        data = response.json()
    except Exception:
        error_msg = (
            f"Device token request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        return DeviceTokenResponse(is_successful=False, error=error_msg)

    if not isinstance(data, dict):
        error_msg = (
            f"Device token request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        return DeviceTokenResponse(is_successful=False, error=error_msg)

    error_code = data.get("error")
    if error_code in _POLLING_ERROR_CODES:
        interval = _coerce_int(data.get("interval"))
        error_description = data.get("error_description", f"Device flow: {error_code}")
        logger.debug(f"Device token poll: {error_code}")
        return DeviceTokenResponse(
            is_successful=False,
            error=error_description,
            error_code=error_code,
            interval=interval,
        )

    error_msg = (
        f"Device token request failed with status code: "
        f"{response.status_code}. Error: {data.get('error', 'unknown')}"
    )
    return DeviceTokenResponse(is_successful=False, error=error_msg)


def process_device_token_response(
    response: httpx.Response,
) -> DeviceTokenResponse:
    """Process device token polling HTTP response.

    Handles RFC 8628 polling error codes (``authorization_pending``,
    ``slow_down``, ``expired_token``, ``access_denied``) by setting
    ``error_code`` on the response instead of treating them as generic errors.
    """
    logger.debug(f"Device token response status: {response.status_code}")

    if response.is_success:
        return _parse_success_response(response)

    return _parse_error_response(response)


def handle_device_token_error(e: Exception) -> DeviceTokenResponse:
    """Handle errors during device token polling."""
    raise_configuration_error(e)
    if isinstance(e, httpx.RequestError):
        error_msg = f"Network error during device token poll: {e!s}"
        logger.error(error_msg, exc_info=True)
        return DeviceTokenResponse(is_successful=False, error=error_msg)

    error_msg = f"Unexpected error during device token poll: {e!s}"
    logger.error(error_msg, exc_info=True)
    return DeviceTokenResponse(is_successful=False, error=error_msg)


__all__ = [
    "handle_device_auth_error",
    "handle_device_token_error",
    "log_device_auth_request",
    "log_device_token_request",
    "prepare_device_auth_request_data",
    "prepare_device_token_request_data",
    "process_device_auth_response",
    "process_device_token_response",
]
