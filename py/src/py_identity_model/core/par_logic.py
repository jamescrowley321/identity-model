"""
Pushed Authorization Request (PAR) business logic per RFC 9126.

Pure functions for preparing PAR requests and processing responses.
"""

import json

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_auth import apply_client_auth
from .dpop import create_dpop_proof
from .models import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
    SignedPushedAuthorizationRequest,
)
from .validators import validate_absolute_uri_without_fragment


def log_par_request(
    request: PushedAuthorizationRequest | SignedPushedAuthorizationRequest,
) -> None:
    """Log pushed authorization request."""
    logger.info(f"Pushing authorization request to {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")


RequestParts = tuple[dict, dict, tuple[str, str] | None]
"""Form data, headers and optional HTTP Basic auth for one request attempt."""


def prepare_par_request_data(
    request: PushedAuthorizationRequest | SignedPushedAuthorizationRequest,
    dpop_nonce: str | None = None,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for PAR.

    Args:
        request: The pushed authorization request.
        dpop_nonce: Server-provided DPoP nonce to embed in the proof when the
            PAR is DPoP-bound and a prior ``use_dpop_nonce`` challenge was
            returned (RFC 9449 §8). Defaults to the nonce the key remembers
            for this server (:meth:`DPoPKey.nonce_for`, RFC 9449 §8.2).

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    if isinstance(request, SignedPushedAuthorizationRequest):
        request.check_request()
        # RFC 9126 §3: only ``request`` and client authentication go in the form.
        params = {"client_id": request.client_id, "request": request.request}
    else:
        params = _plain_params(request)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if request.dpop_key is not None:
        # RFC 9449: bind the PAR to the client's key. The PAR-endpoint proof
        # carries no ``ath`` (that is reserved for resource-server requests).
        headers["DPoP"] = create_dpop_proof(
            request.dpop_key,
            "POST",
            request.address,
            nonce=dpop_nonce or request.dpop_key.nonce_for(request.address),
        )

    auth = apply_client_auth(
        params, request, client_secret=request.client_secret or None
    )

    return params, headers, auth


def _plain_params(request: PushedAuthorizationRequest) -> dict[str, str]:
    """The authorization parameters as form fields (RFC 9126 §2.1)."""
    if not request.redirect_uri:
        raise ValueError("redirect_uri is required")
    validate_absolute_uri_without_fragment(request.redirect_uri, "redirect_uri")
    if bool(request.code_challenge) != bool(request.code_challenge_method):
        raise ValueError(
            "code_challenge and code_challenge_method must both be set or both be absent"
        )

    params: dict[str, str] = {
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "scope": request.scope,
        "response_type": request.response_type,
    }
    if request.state:
        params["state"] = request.state
    if request.nonce:
        params["nonce"] = request.nonce
    if request.code_challenge:
        params["code_challenge"] = request.code_challenge
    if request.code_challenge_method:
        params["code_challenge_method"] = request.code_challenge_method
    if request.response_mode:
        # JARM (JWT-Secured Authorization Response Mode): request a signed
        # authorization response, e.g. "jwt" / "query.jwt".
        params["response_mode"] = request.response_mode
    return params


def process_par_response(
    response: httpx.Response,
) -> PushedAuthorizationResponse:
    """Process PAR HTTP response."""
    logger.debug(f"PAR response status: {response.status_code}")

    if response.is_success:
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            error_msg = "PAR response has invalid JSON body"
            logger.error(error_msg)
            return PushedAuthorizationResponse(is_successful=False, error=error_msg)
        request_uri = data.get("request_uri")
        expires_in = data.get("expires_in")

        missing: list[str] = []
        # RFC 9126 §2.2: request_uri is a string.
        if not isinstance(request_uri, str) or not request_uri.strip():
            missing.append("request_uri")
        if not isinstance(expires_in, int) or expires_in <= 0:
            missing.append("expires_in")
        if missing:
            error_msg = (
                f"PAR response missing required fields per RFC 9126 "
                f"Section 2.2: {', '.join(missing)}"
            )
            logger.error(error_msg)
            return PushedAuthorizationResponse(is_successful=False, error=error_msg)
        logger.info("Pushed authorization request successful")
        return PushedAuthorizationResponse(
            is_successful=True,
            request_uri=request_uri,
            expires_in=expires_in,
        )

    error_msg = (
        f"Pushed authorization request failed with status code: "
        f"{response.status_code}. Response Content: {response.text}"
    )
    return PushedAuthorizationResponse(is_successful=False, error=error_msg)


__all__ = [
    "log_par_request",
    "prepare_par_request_data",
    "process_par_response",
]
