"""
Asynchronous JWT-Secured Authorization Response Mode (JARM) processing.

Async mirror of ``sync/jarm.py``.  Orchestrates the JARM flow (JARM §4.1,
signed responses): extract the response JWT, resolve issuer / JWKS / allowed
signing algorithms (via discovery or caller-supplied offline values), verify
signature and mandatory claims, and return a parsed
``AuthorizeCallbackResponse``.

The pure logic lives in ``core/jarm.py``; this module only performs async I/O.
"""

from ..core.authorize_response import AuthorizeCallbackResponse
from ..core.discovery_policy import DiscoveryPolicy
from ..core.jarm import (
    advertised_jarm_algorithms,
    build_authorize_response_from_claims,
    decode_jarm_claims,
    extract_jarm_header,
    extract_jarm_response_jwt,
    select_jarm_algorithm,
)
from ..core.models import (
    DiscoveryDocumentRequest,
    JwksRequest,
    JwksResponse,
)
from ..core.parsers import find_key_by_kid
from ..core.token_validation_logic import (
    validate_disco_response,
    validate_jwks_response,
    validate_jwks_uri,
)
from ..exceptions import ConfigurationException
from .discovery import get_discovery_document
from .jwks import get_jwks
from .managed_client import AsyncHTTPClient


async def _resolve_jarm_context(
    issuer: str,
    jwks: JwksResponse | None,
    algorithms: list[str] | None,
    require_https: bool,
    http_client: AsyncHTTPClient | None,
) -> tuple[list[str] | None, JwksResponse]:
    """Resolve ``(allowed_algs, jwks_response)`` for JARM verification.

    See ``sync.jarm._resolve_jarm_context`` for the offline vs discovery modes.
    """
    # The decoder skips the iss check for a None issuer, so refuse it here,
    # before either mode.
    if not isinstance(issuer, str) or not issuer:
        raise ConfigurationException("issuer is required for JARM processing")
    if jwks is not None:
        validate_jwks_response(jwks)
        return algorithms, jwks

    policy = DiscoveryPolicy(require_https=require_https)
    disco_doc_response = await get_discovery_document(
        DiscoveryDocumentRequest(issuer=issuer, policy=policy),
        http_client=http_client,
    )
    validate_disco_response(disco_doc_response)
    allowed_algs = (
        algorithms
        if algorithms is not None
        else advertised_jarm_algorithms(
            disco_doc_response.authorization_signing_alg_values_supported
        )
    )

    jwks_uri = validate_jwks_uri(disco_doc_response)
    jwks_response = await get_jwks(
        JwksRequest(address=jwks_uri, policy=policy), http_client=http_client
    )
    validate_jwks_response(jwks_response)
    return allowed_algs, jwks_response


async def process_jarm_response(  # noqa: PLR0913  # discovery and offline inputs
    response: str,
    *,
    client_id: str,
    issuer: str,
    jwks: JwksResponse | None = None,
    algorithms: list[str] | None = None,
    require_https: bool = True,
    leeway: float = 0,
    http_client: AsyncHTTPClient | None = None,
    is_jwt: bool = False,
) -> AuthorizeCallbackResponse:
    """Process a JARM authorization response and return the parsed callback.

    Async mirror of ``sync.jarm.process_jarm_response`` — see that function for
    full argument and exception documentation.
    """
    response_jwt = response if is_jwt else extract_jarm_response_jwt(response)

    allowed_algs, jwks_response = await _resolve_jarm_context(
        issuer, jwks, algorithms, require_https, http_client
    )

    kid, header_alg = extract_jarm_header(response_jwt)
    selected_alg = select_jarm_algorithm(header_alg, allowed_algs)
    key_dict, _key_alg = find_key_by_kid(
        kid, jwks_response.keys or [], jwt_alg=selected_alg
    )

    claims = decode_jarm_claims(
        response_jwt,
        key_dict,
        [selected_alg],
        issuer=issuer,
        audience=client_id,
        leeway=leeway,
    )
    return build_authorize_response_from_claims(claims, raw=response_jwt)


__all__ = [
    "AuthorizeCallbackResponse",
    "process_jarm_response",
]
