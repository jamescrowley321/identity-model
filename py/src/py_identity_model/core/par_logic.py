"""
Pushed Authorization Request (PAR) business logic per RFC 9126.

Pure functions for preparing PAR requests and processing responses.
"""

from dataclasses import fields
import json

import httpx

from ..logging_config import logger
from ..logging_utils import redact_url
from .client_assertion import apply_private_key_jwt
from .client_auth import basic_auth_credentials
from .dpop import create_dpop_proof
from .models import PushedAuthorizationRequest, PushedAuthorizationResponse
from .mtls import apply_mtls_client_auth


# Authorization parameters; with a request object they are claims of the JWT.
_AUTHORIZATION_FIELDS = frozenset(
    {
        "redirect_uri",
        "scope",
        "response_type",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "response_mode",
    }
)


def log_par_request(request: PushedAuthorizationRequest) -> None:
    """Log pushed authorization request."""
    logger.info(f"Pushing authorization request to {redact_url(request.address)}")
    logger.debug(f"Client ID: {request.client_id}")


def prepare_par_request_data(
    request: PushedAuthorizationRequest,
    dpop_nonce: str | None = None,
) -> tuple[dict, dict, tuple[str, str] | None]:
    """Prepare request data, headers, and optional auth for PAR.

    Args:
        request: The pushed authorization request.
        dpop_nonce: Server-provided DPoP nonce to embed in the proof when the
            PAR is DPoP-bound and a prior ``use_dpop_nonce`` challenge was
            returned (RFC 9449 §8).

    Returns:
        ``(data, headers, auth)`` where *auth* is ``None`` for public clients.
    """
    if request.request:
        params = _request_object_params(request)
    else:
        params = _plain_params(request)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if request.dpop_key is not None:
        # RFC 9449: bind the PAR to the client's key. The PAR-endpoint proof
        # carries no ``ath`` (that is reserved for resource-server requests).
        headers["DPoP"] = create_dpop_proof(
            request.dpop_key, "POST", request.address, nonce=dpop_nonce
        )

    auth: tuple[str, str] | None = None
    if request.private_key_jwt is not None:
        # RFC 7523: private_key_jwt assertion in body (client_id already
        # present for PAR per RFC 9126), no auth header.
        apply_private_key_jwt(
            params,
            request.private_key_jwt,
            client_id=request.client_id,
            default_audience=request.address,
        )
    elif request.mtls is not None:
        # RFC 8705 §2: mTLS client auth — certificate is presented at the TLS
        # layer, client_id goes in the body, no Authorization header.
        apply_mtls_client_auth(params, client_id=request.client_id)
    elif request.client_secret:
        auth = basic_auth_credentials(request.client_id, request.client_secret)

    return params, headers, auth


def _request_object_params(request: PushedAuthorizationRequest) -> dict[str, str]:
    """RFC 9126 §3: only ``request`` and client authentication go in the form.

    Every authorization parameter must be a claim of the request object, so a
    plain field set alongside it is refused rather than silently dropped.
    """
    for spec in fields(PushedAuthorizationRequest):
        if spec.name not in _AUTHORIZATION_FIELDS:
            continue
        value = getattr(request, spec.name)
        if value and value != spec.default:
            raise ValueError(
                f"{spec.name} must be a claim of the request object, not a "
                "separate parameter (RFC 9126 §3)"
            )
    return {"client_id": request.client_id, "request": request.request or ""}


def _plain_params(request: PushedAuthorizationRequest) -> dict[str, str]:
    """The authorization parameters as form fields (RFC 9126 §2.1)."""
    if not request.redirect_uri:
        raise ValueError("redirect_uri is required")
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
        if not request_uri:
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
