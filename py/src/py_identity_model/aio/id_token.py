"""Asynchronous OpenID Connect ID Token validation.

Async counterpart of :mod:`py_identity_model.sync.id_token`. Awaits the
standard async ``validate_token`` then applies the same pure ID-Token profile
rules from ``core.id_token_logic`` — sync/async parity is guaranteed by
sharing that single pure validation function (OpenID Connect Core 1.0
§3.1.3.7 / §3.3.2.11).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ..core.id_token_logic import validate_id_token_claims
from ..core.parsers import extract_jwt_header_fields
from .token_validation import validate_token


if TYPE_CHECKING:
    from ..core.models import TokenValidationConfig
    from .managed_client import AsyncHTTPClient


async def validate_id_token(  # noqa: PLR0913  # OIDC id-token profile knobs (§3.1.3.7/§3.3.2.11)
    id_token: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: AsyncHTTPClient | None = None,
    *,
    nonce: str | None = None,
    access_token: str | None = None,
    code: str | None = None,
    max_age: int | None = None,
) -> dict:
    """Validate an OpenID Connect ID Token (async) (OIDC Core §3.1.3.7 / §3.3.2.11).

    Runs the standard async JWT validation via ``validate_token`` (signature,
    ``iss``, ``aud``, ``iat`` and ``exp`` when present) — set
    ``token_validation_config.audience`` to the RP's ``client_id`` so the
    ``aud`` check is enforced there — then applies the ID-Token profile:
    required ``sub``, the ``azp`` authorized-party rules, and the optional
    ``nonce`` / ``max_age`` / ``at_hash`` / ``c_hash`` bindings that are checked
    only when the corresponding argument is supplied.

    Args:
        id_token: The compact-serialized ID Token JWT.
        token_validation_config: Validation configuration. ``audience`` should
            be the RP's ``client_id`` and ``issuer`` the OP issuer.
        disco_doc_address: Discovery document address (required when
            ``perform_disco`` is True).
        http_client: Optional managed async HTTP client (see ``validate_token``
            for the cache-bypass caveats).
        nonce: The ``nonce`` the RP sent on the authorization request. When
            provided, the token's ``nonce`` MUST match it (§3.1.3.7 step 11).
        access_token: The access token from the same response. When provided,
            the token's ``at_hash`` MUST match it (§3.3.2.11).
        code: The authorization code from the same response. When provided, the
            token's ``c_hash`` MUST match it (§3.3.2.11).
        max_age: The ``max_age`` the RP requested. When provided, ``auth_time``
            MUST be present and recent enough (§3.1.3.7 step 12).

    Returns:
        dict: The decoded and validated ID Token claims.

    Raises:
        TokenValidationException: If standard JWT validation fails (bad
            signature, wrong issuer/audience, expired token).
        IdTokenValidationException: If an ID-Token-profile rule fails.
        ConfigurationException: If the configuration is invalid.
    """
    claims = await validate_token(
        id_token,
        token_validation_config,
        disco_doc_address=disco_doc_address,
        http_client=http_client,
    )
    _kid, header_alg = extract_jwt_header_fields(id_token)
    validate_id_token_claims(
        claims,
        header_alg,
        client_id=token_validation_config.audience,
        nonce=nonce,
        access_token=access_token,
        code=code,
        max_age=max_age,
        leeway=token_validation_config.leeway or 0.0,
        now=time.time(),
    )
    return claims


__all__ = ["validate_id_token"]
