"""
Authorization URL builder for OAuth 2.0 / OpenID Connect.

Constructs the authorization endpoint URL with all required and optional
query parameters for the authorization code flow.
"""

from urllib.parse import urlencode, urlparse


_RESERVED_PARAMS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "scope",
        "response_type",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
)


def build_authorization_url(  # noqa: PLR0913  # RFC 6749 §4.1.1 + RFC 7636 §4.3 define these params
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid",
    response_type: str = "code",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    **extra_params: str,
) -> str:
    """Build an OAuth 2.0 / OIDC authorization endpoint URL.

    Constructs a URL with query parameters for redirecting the user to
    the authorization server.  PKCE parameters (``code_challenge`` and
    ``code_challenge_method``) are included when provided.

    Args:
        authorization_endpoint: The authorization server's authorize URL
            (typically from the discovery document).
        client_id: The registered client identifier.
        redirect_uri: The callback URL registered with the authorization server.
        scope: Space-delimited scopes (default ``"openid"``).
        response_type: OAuth 2.0 response type (default ``"code"``).
        state: Opaque CSRF protection value.
        nonce: OpenID Connect nonce for replay protection.
        code_challenge: PKCE code challenge (from :func:`generate_code_challenge`).
        code_challenge_method: PKCE method — ``"S256"`` or ``"plain"``.
        **extra_params: Additional query parameters.

    Returns:
        The full authorization URL ready for redirect.

    Raises:
        ValueError: If *extra_params* contains a reserved OAuth parameter,
            if *code_challenge* is given without *code_challenge_method*
            (or vice versa per RFC 7636 §4.3), if *authorization_endpoint*
            is empty, or if *code_challenge_method* is not ``"S256"``
            or ``"plain"``.
    """
    # Validate authorization_endpoint is non-empty
    if not authorization_endpoint or not authorization_endpoint.strip():
        raise ValueError("authorization_endpoint must not be empty")

    # Reject extra_params that collide with reserved OAuth parameters
    collisions = _RESERVED_PARAMS & extra_params.keys()
    if collisions:
        raise ValueError(
            f"extra_params must not override reserved OAuth parameters: "
            f"{', '.join(sorted(collisions))}"
        )

    # RFC 7636 §4.3: code_challenge and code_challenge_method must be paired
    if (code_challenge is None) != (code_challenge_method is None):
        raise ValueError(
            "code_challenge and code_challenge_method must both be provided "
            "or both be omitted (RFC 7636 §4.3)"
        )

    # Validate code_challenge_method when provided
    if code_challenge_method is not None and code_challenge_method not in (
        "S256",
        "plain",
    ):
        raise ValueError(
            f"code_challenge_method must be 'S256' or 'plain', "
            f"got '{code_challenge_method}'"
        )

    # Strip fragment — query params after #fragment are ignored by browsers
    parsed = urlparse(authorization_endpoint)
    if parsed.fragment:
        authorization_endpoint = authorization_endpoint.split("#", 1)[0]
        parsed = urlparse(authorization_endpoint)

    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "response_type": response_type,
    }
    if state is not None:
        params["state"] = state
    if nonce is not None:
        params["nonce"] = nonce
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
    if code_challenge_method is not None:
        params["code_challenge_method"] = code_challenge_method
    params.update(extra_params)

    separator = "&" if parsed.query else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


def build_par_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    request_uri: str,
) -> str:
    """Build the authorization endpoint URL for a pushed authorization request.

    The URL carries exactly ``client_id`` and the ``request_uri`` returned by
    the PAR endpoint; every other authorization parameter was pushed and is
    not repeated on the front channel (RFC 9126 §4, FAPI 2.0 Security Profile
    §5.3.3.2).  Query parameters already on the endpoint are kept.

    Args:
        authorization_endpoint: The authorization server's authorize URL.
        client_id: The registered client identifier.
        request_uri: The ``request_uri`` from the PAR response.

    Returns:
        The full authorization URL ready for redirect.

    Raises:
        ValueError: If any argument is not a string or is empty.
    """
    for name, value in (
        ("authorization_endpoint", authorization_endpoint),
        ("client_id", client_id),
        ("request_uri", request_uri),
    ):
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        if not value.strip():
            raise ValueError(f"{name} must not be empty")

    # Strip fragment — query params after #fragment are ignored by browsers
    endpoint = authorization_endpoint.split("#", 1)[0]
    query = urlencode({"client_id": client_id, "request_uri": request_uri})
    has_query = "?" in endpoint
    if endpoint.endswith("?") or (has_query and endpoint.endswith("&")):
        separator = ""
    else:
        # A trailing "&" with no "?" is part of the path, not a delimiter.
        separator = "&" if has_query else "?"
    return f"{endpoint}{separator}{query}"


__all__ = ["build_authorization_url", "build_par_authorization_url"]
