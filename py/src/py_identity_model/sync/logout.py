"""Synchronous Back-Channel Logout token validation.

Thin wrapper over ``validate_token``: performs the full standard JWT
validation (signature via JWKS, ``iss``, ``aud``, ``iat`` and ``exp`` when
present) then applies the Logout-Token-specific claim rules from
``core.logout_logic``. All business logic lives in ``core`` so the sync and
async wrappers stay in lock-step (OpenID Connect Back-Channel Logout 1.0 §2.4).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.logout_logic import validate_logout_token_claims
from .token_validation import validate_token


if TYPE_CHECKING:
    from ..core.models import TokenValidationConfig
    from .managed_client import HTTPClient


def validate_logout_token(
    logout_token: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: HTTPClient | None = None,
) -> dict:
    """Validate a Back-Channel Logout Token (Back-Channel Logout 1.0 §2.4).

    Runs the standard JWT validation via ``validate_token`` (signature,
    ``iss``, ``aud``, ``iat`` and ``exp`` when present), then enforces the
    Logout-Token-specific rules: required ``events`` member, ``sub``/``sid``
    presence, and the ``nonce`` prohibition.

    Args:
        logout_token: The compact-serialized Logout Token JWT received at the
            RP's ``backchannel_logout_uri``.
        token_validation_config: Validation configuration. ``audience`` should
            be the RP's ``client_id`` and ``issuer`` the OP issuer.
        disco_doc_address: Discovery document address (required when
            ``perform_disco`` is True).
        http_client: Optional managed HTTP client (see ``validate_token``).

    Returns:
        dict: The decoded and validated Logout Token claims.

    Raises:
        TokenValidationException: If standard JWT validation fails (bad
            signature, wrong issuer/audience, expired token).
        LogoutTokenValidationException: If a Logout-Token-specific rule fails.
        ConfigurationException: If the configuration is invalid.
    """
    claims = validate_token(
        logout_token,
        token_validation_config,
        disco_doc_address=disco_doc_address,
        http_client=http_client,
    )
    validate_logout_token_claims(claims)
    return claims


__all__ = ["validate_logout_token"]
