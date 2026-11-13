"""
Dynamic Client Registration business logic per RFC 7591 and RFC 7592.

Pure functions for preparing registration/management requests and processing
responses.  I/O is performed by the sync/async wrappers.
"""

import json

import httpx

from ..exceptions import ProtocolParameterError, ProtocolParameterErrorReason
from ..logging_config import logger
from ..logging_utils import redact_url
from .models import (
    ClientDeleteResponse,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
    ClientUpdateRequest,
)


# Client metadata fields (RFC 7591 Section 2) shared by register and update.
_METADATA_FIELDS = (
    "redirect_uris",
    "response_types",
    "grant_types",
    "application_type",
    "contacts",
    "client_name",
    "logo_uri",
    "client_uri",
    "policy_uri",
    "tos_uri",
    "token_endpoint_auth_method",
    "scope",
    "jwks_uri",
)

# RFC 7592 Section 2.2: fields the server issues, which an update request
# MUST NOT include. A read response carries them, so they are dropped when
# its metadata is passed back as ``extra_metadata``.
_UPDATE_FORBIDDEN_FIELDS = (
    "registration_access_token",
    "registration_client_uri",
    "client_secret_expires_at",
    "client_id_issued_at",
)


def _build_client_metadata(
    request: ClientRegistrationRequest | ClientUpdateRequest,
) -> dict:
    """Assemble the client metadata JSON body from set request fields.

    Only fields that are set (non-``None``) are included.  Update requests
    additionally carry ``client_id`` and an optional ``client_secret``
    (RFC 7592 Section 2.2).  ``extra_metadata`` is merged last so callers can
    supply OIDC-specific fields not modelled explicitly.
    """
    body: dict = {}
    for name in _METADATA_FIELDS:
        value = getattr(request, name, None)
        if value is not None:
            body[name] = value

    client_id = getattr(request, "client_id", None)
    if client_id is not None:
        body["client_id"] = client_id
    client_secret = getattr(request, "client_secret", None)
    if client_secret is not None:
        body["client_secret"] = client_secret

    if request.extra_metadata:
        body.update(request.extra_metadata)
    return body


def prepare_registration_request(
    request: ClientRegistrationRequest,
) -> tuple[dict, dict]:
    """Prepare the JSON body and headers for a client registration request.

    Returns ``(json_body, headers)``.  When ``initial_access_token`` is set a
    Bearer ``Authorization`` header is added for a protected registration
    endpoint (RFC 7591 Section 3).
    """
    logger.info(f"Registering client at {redact_url(request.address)}")
    body = _build_client_metadata(request)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if request.initial_access_token:
        headers["Authorization"] = f"Bearer {request.initial_access_token}"
    return body, headers


def prepare_management_headers(registration_access_token: str) -> dict:
    """Prepare Bearer headers for RFC 7592 client management requests."""
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {registration_access_token}",
    }


def prepare_update_request(request: ClientUpdateRequest) -> tuple[dict, dict]:
    """Prepare the JSON body and headers for a client update (RFC 7592 Section 2.2).

    The body includes ``client_id`` and the full client metadata; headers carry
    the registration access token. ``registration_access_token``,
    ``registration_client_uri``, ``client_secret_expires_at`` and
    ``client_id_issued_at`` are left out even when ``extra_metadata`` has them,
    so a read response's metadata can be passed back as is.

    Raises:
        ProtocolParameterError: ``extra_metadata`` has a ``client_id`` other
            than ``request.client_id``
            (:attr:`ProtocolParameterErrorReason.CLIENT_ID_MISMATCH`).
    """
    logger.info(f"Updating client at {redact_url(request.address)}")
    extra = request.extra_metadata or {}
    if "client_id" in extra and extra["client_id"] != request.client_id:
        raise ProtocolParameterError(
            ProtocolParameterErrorReason.CLIENT_ID_MISMATCH, "extra_metadata"
        )
    body = _build_client_metadata(request)
    for name in _UPDATE_FORBIDDEN_FIELDS:
        body.pop(name, None)
    headers = prepare_management_headers(request.registration_access_token)
    headers["Content-Type"] = "application/json"
    return body, headers


def _extract_error_message(response: httpx.Response, operation: str) -> str:
    """Build an error message, surfacing an OAuth error body when present.

    Per RFC 7591 Section 3.2.2 / RFC 7592, failures carry a JSON body with
    ``error`` and optional ``error_description`` (e.g. ``invalid_redirect_uri``,
    ``invalid_client_metadata``).
    """
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        data = None
    if isinstance(data, dict) and data.get("error"):
        error_code = data["error"]
        error_description = data.get("error_description")
        if error_description:
            return f"{error_code}: {error_description}"
        return error_code
    return (
        f"Client {operation} request failed with status code: "
        f"{response.status_code}. Response Content: "
        f"{response.text[:200] or '(empty)'}"
    )


def _parse_registration_success(
    response: httpx.Response,
) -> ClientRegistrationResponse:
    """Parse a successful registration/read/update response body."""
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        error_msg = "Client registration response has invalid JSON body"
        logger.error(error_msg)
        return ClientRegistrationResponse(is_successful=False, error=error_msg)

    client_id = data.get("client_id")
    if not client_id:
        error_msg = (
            "Client registration response missing required field 'client_id' "
            "per RFC 7591 Section 3.2.1"
        )
        logger.error(error_msg)
        return ClientRegistrationResponse(is_successful=False, error=error_msg)

    return ClientRegistrationResponse(
        is_successful=True,
        client_id=client_id,
        client_secret=data.get("client_secret"),
        client_id_issued_at=data.get("client_id_issued_at"),
        client_secret_expires_at=data.get("client_secret_expires_at"),
        registration_access_token=data.get("registration_access_token"),
        registration_client_uri=data.get("registration_client_uri"),
        metadata=data,
    )


def _registration_error(
    response: httpx.Response, operation: str
) -> ClientRegistrationResponse:
    """Build a failed :class:`ClientRegistrationResponse` for a non-2xx status."""
    error_msg = _extract_error_message(response, operation)
    logger.error(error_msg)
    return ClientRegistrationResponse(is_successful=False, error=error_msg)


def process_registration_response(
    response: httpx.Response,
) -> ClientRegistrationResponse:
    """Process a client registration HTTP response (RFC 7591 Section 3.2).

    Any 2xx is treated as success (the RFC specifies 201, some providers return
    200); non-2xx surfaces the OAuth error code/description.
    """
    logger.debug(f"Client registration response status: {response.status_code}")
    if response.is_success:
        logger.info("Client registration successful")
        return _parse_registration_success(response)
    return _registration_error(response, "registration")


def process_read_response(response: httpx.Response) -> ClientRegistrationResponse:
    """Process a client read HTTP response (RFC 7592 Section 2.1)."""
    logger.debug(f"Client read response status: {response.status_code}")
    if response.is_success:
        return _parse_registration_success(response)
    return _registration_error(response, "read")


def process_update_response(response: httpx.Response) -> ClientRegistrationResponse:
    """Process a client update HTTP response (RFC 7592 Section 2.2)."""
    logger.debug(f"Client update response status: {response.status_code}")
    if response.is_success:
        logger.info("Client update successful")
        return _parse_registration_success(response)
    return _registration_error(response, "update")


def process_delete_response(response: httpx.Response) -> ClientDeleteResponse:
    """Process a client delete HTTP response (RFC 7592 Section 2.3).

    A 204 No Content (or any 2xx) indicates success; the body is not read.
    """
    logger.debug(f"Client delete response status: {response.status_code}")
    if response.is_success:
        logger.info("Client deleted successfully")
        return ClientDeleteResponse(is_successful=True)

    error_msg = _extract_error_message(response, "delete")
    logger.error(error_msg)
    return ClientDeleteResponse(is_successful=False, error=error_msg)


__all__ = [
    "prepare_management_headers",
    "prepare_registration_request",
    "prepare_update_request",
    "process_delete_response",
    "process_read_response",
    "process_registration_response",
    "process_update_response",
]
