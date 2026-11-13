"""
JWT Secured Authorization Request (JAR) utilities per RFC 9101.

Provides request object creation and authorization URL building for
passing authorization parameters as signed JWTs.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any
from urllib.parse import urlencode, urlparse
import uuid

import jwt as pyjwt

from ..exceptions import RequestObjectError, RequestObjectErrorKind
from .jwt_signing import validate_signing_algorithm
from .key_strength import enforce_signing_key_strength


@dataclass(frozen=True)
class _RequestParams:
    """Internal container for validated request object parameters."""

    private_key: str | bytes
    algorithm: str
    client_id: str
    audience: str
    redirect_uri: str
    response_type: str
    lifetime: int
    code_challenge: str | None
    code_challenge_method: str | None
    kid: str | None
    extra_claims: dict[str, Any]


_RESERVED_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "iat",
        "nbf",
        "exp",
        "jti",
        "client_id",
        "response_type",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
)

# RFC 9101 §4: "request and request_uri parameters MUST NOT be included in
# Request Objects."
_FORBIDDEN_CLAIMS = frozenset({"request", "request_uri"})

# A compact JWE has five dot-separated parts (RFC 7516 §7.1).
_JWE_COMPACT_DOTS = 4


def _validate_request_params(params: _RequestParams) -> None:
    """Validate all inputs for :func:`create_request_object`."""
    for name, value in (
        ("private_key", params.private_key),
        ("client_id", params.client_id),
        ("audience", params.audience),
        ("redirect_uri", params.redirect_uri),
        ("response_type", params.response_type),
    ):
        if not value:
            raise ValueError(f"{name} must not be empty")

    validate_signing_algorithm(params.algorithm, context="JAR")

    if params.lifetime <= 0:
        raise ValueError(f"lifetime must be positive, got {params.lifetime}")

    if (params.code_challenge is None) != (params.code_challenge_method is None):
        raise ValueError(
            "code_challenge and code_challenge_method must both be "
            "provided or both omitted"
        )

    for name, value in (
        ("code_challenge", params.code_challenge),
        ("code_challenge_method", params.code_challenge_method),
        ("kid", params.kid),
    ):
        if value is not None and not value:
            raise ValueError(f"{name} must be non-empty when provided")

    if _FORBIDDEN_CLAIMS & params.extra_claims.keys():
        raise RequestObjectError(RequestObjectErrorKind.FORBIDDEN_CLAIM)

    collisions = set(params.extra_claims) & _RESERVED_CLAIMS
    if collisions:
        raise ValueError(
            f"extra_claims cannot override reserved claims: {sorted(collisions)}"
        )

    enforce_signing_key_strength(params.private_key, params.algorithm)


def create_request_object(  # noqa: PLR0913  # RFC 9101 §4 request object carries all authorization params
    private_key: str | bytes,
    algorithm: str,
    client_id: str,
    audience: str,
    redirect_uri: str,
    scope: str = "openid",
    response_type: str = "code",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    lifetime: int = 300,
    kid: str | None = None,
    **extra_claims: Any,
) -> str:
    """Create a signed JWT request object per RFC 9101.

    The request object contains authorization parameters as JWT claims,
    ensuring request integrity through signing.  The JWT ``typ`` header
    is set to ``"oauth-authz-req+jwt"`` per RFC 9101 Section 10.2.

    Args:
        private_key: PEM-encoded private key for signing (bytes or str).
        algorithm: Signing algorithm (e.g. ``"ES256"``, ``"RS256"``,
            ``"EdDSA"``).
        client_id: Client identifier - becomes both ``iss`` and
            ``client_id`` claims.
        audience: Authorization server issuer - becomes ``aud`` claim.
        redirect_uri: Registered redirect URI.
        scope: Space-delimited scopes (default ``"openid"``).
        response_type: OAuth 2.0 response type (default ``"code"``).
        state: CSRF protection value.
        nonce: OpenID Connect nonce for replay protection.
        code_challenge: PKCE code challenge.
        code_challenge_method: PKCE method (``"S256"`` or ``"plain"``).
        lifetime: JWT validity in seconds (default 300).
        kid: Key ID to include in the JWT header for key lookup.
        **extra_claims: Additional claims to include in the request object.
            ``request`` and ``request_uri`` are refused (RFC 9101 §4).

    Returns:
        The signed JWT string.

    Raises:
        ValueError: If *algorithm* is not supported, required parameters
            are empty, *lifetime* is not positive, *code_challenge* and
            *code_challenge_method* are not both provided, or
            *extra_claims* contains a reserved claim name.
        RequestObjectError: ``FORBIDDEN_CLAIM`` if *extra_claims* contains
            ``request`` or ``request_uri``.
        WeakSigningKeyError: If *private_key* is an RSA key under 2048 bits
            (RFC 7518 §3.3, §3.5).
    """
    _validate_request_params(
        _RequestParams(
            private_key=private_key,
            algorithm=algorithm,
            client_id=client_id,
            audience=audience,
            redirect_uri=redirect_uri,
            response_type=response_type,
            lifetime=lifetime,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            kid=kid,
            extra_claims=extra_claims,
        )
    )

    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": client_id,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    claims.update(
        {
            name: value
            for name, value in (
                ("state", state),
                ("nonce", nonce),
                ("code_challenge", code_challenge),
                ("code_challenge_method", code_challenge_method),
            )
            if value is not None
        }
    )

    claims.update(extra_claims)

    headers: dict[str, str] = {"typ": "oauth-authz-req+jwt"}
    if kid is not None:
        headers["kid"] = kid

    return pyjwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


def _require_matching_client_id(request_object: str, client_id: str) -> None:
    """RFC 9101 §5: the query ``client_id`` matches the request object's."""
    if not isinstance(request_object, str):
        raise RequestObjectError(RequestObjectErrorKind.NOT_A_JWT)
    if request_object.count(".") == _JWE_COMPACT_DOTS:
        raise RequestObjectError(RequestObjectErrorKind.ENCRYPTED)
    try:
        claims = pyjwt.decode(request_object, options={"verify_signature": False})
    except pyjwt.PyJWTError as exc:
        raise RequestObjectError(RequestObjectErrorKind.NOT_A_JWT) from exc
    if claims.get("client_id") != client_id:
        raise RequestObjectError(RequestObjectErrorKind.CLIENT_ID_MISMATCH)


def build_jar_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    request_object: str,
    scope: str | None = None,
    response_type: str | None = None,
) -> str:
    """Build an authorization URL with a JAR ``request`` parameter.

    Per RFC 9101 Section 6.3, ``client_id`` MUST appear as a query
    parameter and ``scope``/``response_type`` SHOULD be duplicated
    outside the request object for backward compatibility.  The query
    ``client_id`` must match the request object's ``client_id`` claim
    (RFC 9101 §5); the claim is read without verifying the signature.

    Args:
        authorization_endpoint: The authorization server's authorize URL.
        client_id: The registered client identifier.
        request_object: Signed JWT from :func:`create_request_object`.
        scope: Optional scope to duplicate in query params.
        response_type: Optional response_type to duplicate in query params.

    Returns:
        The full authorization URL with the ``request`` parameter.

    Raises:
        RequestObjectError: ``ENCRYPTED`` if *request_object* is a compact
            JWE, ``NOT_A_JWT`` if it is not a JWT with a claims object, or
            ``CLIENT_ID_MISMATCH`` if its ``client_id`` is absent or is not
            *client_id*.
    """
    _require_matching_client_id(request_object, client_id)

    params: dict[str, str] = {
        "client_id": client_id,
        "request": request_object,
    }
    if scope is not None:
        params["scope"] = scope
    if response_type is not None:
        params["response_type"] = response_type

    parsed = urlparse(authorization_endpoint)
    separator = "&" if parsed.query else "?"
    return f"{authorization_endpoint}{separator}{urlencode(params)}"


__all__ = [
    "build_jar_authorization_url",
    "create_request_object",
]
