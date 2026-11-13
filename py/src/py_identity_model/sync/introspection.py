"""
Token introspection (synchronous implementation).

This module provides synchronous HTTP layer for OAuth 2.0 Token
Introspection (RFC 7662).
"""

import httpx

from ..core.discovery_policy import DiscoveryPolicy
from ..core.error_handlers import handle_introspection_error
from ..core.introspection_jwt import (
    KEY_LOOKUP_ERRORS,
    SignedIntrospectionRefused,
    allowed_introspection_algorithms,
    check_signed_introspection_header,
    read_signed_introspection,
    refused_introspection_response,
    verified_introspection_response,
)
from ..core.introspection_logic import (
    discovery_signed_response,
    log_introspection_request,
    prepare_introspection_request_data,
    process_introspection_response,
)
from ..core.models import (
    IntrospectionErrorKind,
    SignedIntrospectionOptions,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
)
from .http_client import resolve_http_client, retry_with_backoff
from .managed_client import HTTPClient
from .token_validation import (
    _discover_and_resolve_key,
    _resolve_cache,
    _resolve_client,
)
from .validation_cache import ValidationCache


def _verify_with_discovery(
    response: httpx.Response,
    request: TokenIntrospectionRequest,
    options: SignedIntrospectionOptions,
    http_client: HTTPClient | None,
    cache: ValidationCache | None,
) -> TokenIntrospectionResponse:
    """Verify a 2xx JWT introspection response against the keys and
    algorithms from ``options.discovery_address`` (RFC 9701 §5)."""
    client = _resolve_client(http_client)
    cache = _resolve_cache(cache)
    policy = options.discovery_policy or DiscoveryPolicy()
    try:
        token, header = read_signed_introspection(response)
        # One discovery document supplies the keys, the issuer and the
        # algorithms, so they can't come from two different fetches.
        try:
            key, _, disco = _discover_and_resolve_key(
                token, options.discovery_address, client, policy, cache
            )
        except KEY_LOOKUP_ERRORS as exc:
            raise SignedIntrospectionRefused(
                IntrospectionErrorKind.SIGNATURE, str(exc)
            ) from exc
        alg = check_signed_introspection_header(
            header,
            allowed_introspection_algorithms(
                options, disco.introspection_signing_alg_values_supported
            ),
        )
        return verified_introspection_response(token, key, alg, request, disco.issuer)
    except SignedIntrospectionRefused as refused:
        return refused_introspection_response(refused)


@retry_with_backoff()
def _introspect_token(
    client: httpx.Client,
    url: str,
    data: dict,
    headers: dict,
    auth: tuple[str, str] | None = None,
) -> httpx.Response:
    """Make introspection request with retry logic."""
    kwargs: dict = {"data": data, "headers": headers}
    if auth is not None:
        kwargs["auth"] = auth
    return client.post(url, **kwargs)


def introspect_token(
    request: TokenIntrospectionRequest,
    http_client: HTTPClient | None = None,
    *,
    cache: ValidationCache | None = None,
) -> TokenIntrospectionResponse:
    """Introspect an OAuth 2.0 token (RFC 7662).

    Args:
        request: Introspection request with token and client credentials.
        http_client: Optional managed HTTP client. In discovery mode
            (``signed_response.discovery_address``) it also fetches the
            discovery document and keys.
        cache: The validation cache for the discovery document and keys in
            discovery mode. ``None`` (default) uses the default cache, as
            ``validate_token`` does. Keyword-only.

    Returns:
        TokenIntrospectionResponse with claims dict including ``active`` bool.
    """
    log_introspection_request(request)

    response = None
    owned_client = None
    try:
        params, headers, auth = prepare_introspection_request_data(request)
        client, owned_client = resolve_http_client(request.mtls, http_client)
        response = _introspect_token(client, request.address, params, headers, auth)
        verified = None
        discovered = discovery_signed_response(request)
        if discovered is not None and response.is_success:
            verified = _verify_with_discovery(
                response, request, discovered, http_client, cache
            )
        return process_introspection_response(response, request, verified)
    except Exception as e:
        return handle_introspection_error(e)
    finally:
        if response is not None:
            response.close()
        if owned_client is not None:
            owned_client.close()


__all__ = [
    "IntrospectionErrorKind",
    "SignedIntrospectionOptions",
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    "introspect_token",
]
