"""Synchronous Back-Channel Logout token validation.

Runs the standard JWT validation shared with ``validate_token``, minus its
access-token sender-constraint check (signature via JWKS, ``iss``, ``aud``,
and ``iat``/``exp`` when present) then applies the Logout-Token-specific claim rules from
``core.logout_logic``. All business logic lives in ``core`` so the sync and
async wrappers stay in lock-step (OpenID Connect Back-Channel Logout 1.0 §2.4).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.id_token_logic import require_issuer_without_discovery
from ..core.logout_logic import validate_logout_token_claims
from .token_validation import _validate_jwt_without_binding


if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..core.models import TokenValidationConfig
    from .managed_client import HTTPClient
    from .validation_cache import ValidationCache


def validate_logout_token(
    logout_token: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: HTTPClient | None = None,
    *,
    trusted_audiences: Iterable[str] | None = None,
    cache: ValidationCache | None = None,
) -> dict:
    """Validate a Back-Channel Logout Token (Back-Channel Logout 1.0 §2.4).

    Runs the standard JWT validation of ``validate_token`` (signature,
    ``iss``, ``aud``, and ``iat``/``exp`` when present), then enforces the
    Logout-Token-specific rules: required ``events`` member, ``sub``/``sid``
    presence, the ``nonce`` prohibition, and no audience the client does not
    trust (§2.6 step 4, applying OIDC Core §3.1.3.7 step 3).

    The access-token sender-constraint check (RFC 9449 §7, RFC 8705 §3) is not
    run: a Logout Token (Back-Channel Logout §2.6) arrives with no
    presentation, so a ``cnf`` claim in it is not checked.

    Args:
        logout_token: The compact-serialized Logout Token JWT received at the
            RP's ``backchannel_logout_uri``.
        token_validation_config: Validation configuration. ``audience`` should
            be the RP's ``client_id`` and ``issuer`` the OP issuer.
        disco_doc_address: Discovery document address (required when
            ``perform_disco`` is True).
        http_client: Optional managed HTTP client (see ``validate_token``).
        trusted_audiences: Additional audiences the client trusts besides
            ``token_validation_config.audience``. Every ``aud`` value MUST be
            the audience or one of these; omitted or empty means the audience
            is the only trusted one.
        cache: Optional :class:`ValidationCache` for the discovery document,
            JWKS and kid-miss cooldown (see ``validate_token``).

    Returns:
        dict: The decoded and validated Logout Token claims.

    Raises:
        TokenValidationException: If standard JWT validation fails (bad
            signature, wrong issuer/audience, expired token).
        LogoutTokenValidationException: If a Logout-Token-specific rule fails.
        ConfigurationException: If the configuration is invalid, including
            ``perform_disco=False`` with no ``issuer`` (§3.1.3.7 step 2).
    """
    require_issuer_without_discovery(token_validation_config)
    claims = _validate_jwt_without_binding(
        logout_token,
        token_validation_config,
        disco_doc_address=disco_doc_address,
        http_client=http_client,
        cache=cache,
    )
    validate_logout_token_claims(
        claims,
        client_id=token_validation_config.audience,
        trusted_audiences=trusted_audiences,
    )
    return claims


__all__ = ["validate_logout_token"]
