"""
Pushed Authorization Requests (synchronous implementation, RFC 9126).
"""

from collections.abc import Callable

import httpx

from ..core.dpop import extract_dpop_nonce, remember_dpop_nonce
from ..core.error_handlers import handle_par_error
from ..core.models import (
    PushedAuthorizationRequest,
    PushedAuthorizationResponse,
    SignedPushedAuthorizationRequest,
)
from ..core.par_logic import (
    RequestParts,
    log_par_request,
    prepare_par_request_data,
    process_par_response,
)
from .http_client import resolve_http_client, retry_with_backoff
from .managed_client import HTTPClient


@retry_with_backoff()
def _push_authorization_request(
    client: httpx.Client,
    url: str,
    prepare: Callable[[], RequestParts],
) -> httpx.Response:
    """Make PAR request with retry logic.

    *prepare* runs on every attempt, so each one carries a freshly minted
    DPoP proof and client assertion with a new ``jti`` (RFC 9449 §11.1).
    """
    data, headers, auth = prepare()
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def push_authorization_request(
    request: PushedAuthorizationRequest | SignedPushedAuthorizationRequest,
    http_client: HTTPClient | None = None,
) -> PushedAuthorizationResponse:
    """Push authorization parameters to the PAR endpoint (RFC 9126).

    Args:
        request: PAR request with authorization parameters, as plain form
            fields or as a signed request object.
        http_client: Optional managed HTTP client.

    Returns:
        PushedAuthorizationResponse with ``request_uri`` and ``expires_in``.
    """
    log_par_request(request)

    response = None
    owned_client = None
    try:
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _push_authorization_request(
            client, request.address, lambda: prepare_par_request_data(request)
        )
        if request.dpop_key is not None:
            # RFC 9449 §8: honor a single ``use_dpop_nonce`` challenge by
            # re-minting the proof with the server nonce and retrying once.
            remember_dpop_nonce(
                request.dpop_key, request.address, response, resource_server=False
            )
            nonce = extract_dpop_nonce(response)
            if nonce is not None:
                response.close()
                response = _push_authorization_request(
                    client,
                    request.address,
                    lambda: prepare_par_request_data(request, dpop_nonce=nonce),
                )
        if request.dpop_key is not None:
            remember_dpop_nonce(
                request.dpop_key, request.address, response, resource_server=False
            )
        return process_par_response(response)
    except Exception as e:
        return handle_par_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


__all__ = [
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    "SignedPushedAuthorizationRequest",
    "push_authorization_request",
]
