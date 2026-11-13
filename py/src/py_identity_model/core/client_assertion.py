"""
``private_key_jwt`` client authentication per RFC 7523 and OpenID Connect
Core 1.0 Section 9.

Builds the signed JWT ``client_assertion`` that authenticates a client at the
token, PAR, introspection, and revocation endpoints, and provides a shared
helper that injects the assertion into request parameters with the correct
precedence (``private_key_jwt`` > ``client_secret`` > public).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
import uuid

import jwt as pyjwt

from ..oidc_constants import ClientAssertionTypes, TokenRequest
from .jwt_signing import validate_signing_algorithm


if TYPE_CHECKING:
    from .models import PrivateKeyJwt

# Backdate ``iat``/``nbf`` by a small margin so an authorization server whose
# clock runs slightly ahead does not reject a freshly minted assertion as
# not-yet-valid at the boundary (RFC 7523 leaves skew tolerance to the AS).
_CLOCK_SKEW_LEEWAY_SECONDS = 10


def build_client_assertion(  # noqa: PLR0913  # RFC 7523 assertion params are all distinct
    *,
    client_id: str,
    audience: str,
    private_key: str | bytes,
    algorithm: str = "PS256",
    kid: str | None = None,
    lifetime: int = 300,
) -> str:
    """Build a signed ``private_key_jwt`` client assertion (RFC 7523 Section 2.2).

    The assertion authenticates the client to the authorization server.  Its
    claims follow RFC 7523 Section 3 / OpenID Connect Core 1.0 Section 9:

    - ``iss`` and ``sub`` are both the client identifier.
    - ``aud`` is the authorization server (token endpoint URL or issuer).
    - ``jti`` is a unique identifier (uuid4) to prevent replay.
    - ``iat`` / ``exp`` bound the assertion to a short lifetime.

    Args:
        client_id: Client identifier; becomes the ``iss`` and ``sub`` claims.
        audience: Authorization server identifier; becomes the ``aud`` claim.
        private_key: PEM-encoded private key for signing (``bytes`` or ``str``).
        algorithm: Asymmetric signing algorithm (default ``"PS256"``).
            FAPI 2.0 requires ``PS256`` or ``ES256``.
        kid: Optional key ID for the JWT header to aid key lookup.
        lifetime: Assertion validity in seconds (default 300).

    Returns:
        The signed client assertion JWT.

    Raises:
        ValueError: If a required parameter is empty, *algorithm* is not a
            supported asymmetric signing algorithm, *lifetime* is not
            positive, or *kid* is an empty string.
    """
    for name, value in (
        ("client_id", client_id),
        ("audience", audience),
        ("private_key", private_key),
    ):
        # Reject whitespace-only string values: they are truthy but would be
        # signed into ``iss``/``sub``/``aud`` and rejected opaquely by the AS.
        if not value or (isinstance(value, str) and not value.strip()):
            raise ValueError(f"{name} must not be empty")

    validate_signing_algorithm(algorithm, context="client assertion")

    # ``exp`` is derived from the backdated ``iat`` (``now - leeway``), so a
    # lifetime at or below the leeway yields an assertion already expired at
    # mint time. Require a lifetime that clears the skew window.
    if lifetime <= _CLOCK_SKEW_LEEWAY_SECONDS:
        raise ValueError(
            f"lifetime must be greater than the {_CLOCK_SKEW_LEEWAY_SECONDS}s "
            f"clock-skew leeway, got {lifetime}"
        )

    if kid is not None and not kid.strip():
        raise ValueError("kid must be non-empty when provided")

    issued_at = int(time.time()) - _CLOCK_SKEW_LEEWAY_SECONDS
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": str(uuid.uuid4()),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + lifetime,
    }

    headers: dict[str, str] = {}
    if kid is not None:
        headers["kid"] = kid

    return pyjwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


def apply_private_key_jwt(
    params: dict[str, str],
    config: PrivateKeyJwt,
    *,
    client_id: str,
    default_audience: str,
) -> None:
    """Inject a ``private_key_jwt`` client assertion into *params* in place.

    Adds ``client_id``, ``client_assertion_type``, and ``client_assertion`` to
    the request body per RFC 7523 Section 2.2.  ``client_id`` is included
    alongside the assertion (RFC 7521 Section 4.2); it identifies the same
    client as the assertion's ``sub``.  The assertion ``aud`` is
    :attr:`PrivateKeyJwt.audience` if set, else :attr:`PrivateKeyJwt.issuer`
    (FAPI 2.0 Security Profile §5.3.3.1), else *default_audience* (the
    request ``address``).  It is always a single string.

    Args:
        params: Request body parameters to mutate in place.
        config: The ``private_key_jwt`` authentication parameters.
        client_id: The client identifier.
        default_audience: Audience to use when neither ``config.audience``
            nor ``config.issuer`` is set.

    Raises:
        ValueError: If ``config.audience`` or ``config.issuer`` is set to
            something other than a string.
    """
    for name, value in (("audience", config.audience), ("issuer", config.issuer)):
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{name} must be a string, got {type(value).__name__}")
    assertion = build_client_assertion(
        client_id=client_id,
        audience=config.audience or config.issuer or default_audience,
        private_key=config.private_key,
        algorithm=config.algorithm,
        kid=config.kid,
        lifetime=config.lifetime,
    )
    params[TokenRequest.CLIENT_ID.value] = client_id
    params[TokenRequest.CLIENT_ASSERTION_TYPE.value] = (
        ClientAssertionTypes.JWT_BEARER.value
    )
    params[TokenRequest.CLIENT_ASSERTION.value] = assertion


__all__ = [
    "apply_private_key_jwt",
    "build_client_assertion",
]
