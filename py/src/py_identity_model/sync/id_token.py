"""Synchronous OpenID Connect ID Token validation.

Thin wrapper over ``validate_token``: performs the full standard JWT
validation (signature via JWKS, ``iss``, ``aud``, ``iat`` and ``exp`` when
present) then applies the ID-Token-specific profile rules from
``core.id_token_logic``. All business logic lives in ``core`` so the sync and
async wrappers stay in lock-step (OpenID Connect Core 1.0 §3.1.3.7 / §3.3.2.11).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ..core.id_token_logic import check_azp_config, validate_id_token_claims
from ..core.parsers import extract_jwt_header_fields
from .token_validation import validate_token


if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..core.models import TokenValidationConfig
    from .managed_client import HTTPClient


def validate_id_token(  # noqa: PLR0913  # OIDC id-token profile knobs (§3.1.3.7/§3.3.2.11)
    id_token: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: HTTPClient | None = None,
    *,
    trusted_audiences: Iterable[str] | None = None,
    validate_azp: bool = False,
    nonce: str | None = None,
    access_token: str | None = None,
    code: str | None = None,
    access_token_issued_with_id_token: bool = True,
    code_issued_with_id_token: bool = True,
    max_age: int | None = None,
) -> dict:
    """Validate an OpenID Connect ID Token (OIDC Core §3.1.3.7 / §3.3.2.11).

    Runs the standard JWT validation via ``validate_token`` (signature,
    ``iss``, ``aud``, ``iat`` and ``exp`` when present) — set
    ``token_validation_config.audience`` to the RP's ``client_id`` so the
    ``aud`` check is enforced there — then applies the ID-Token profile:
    required ``sub``, no audience the client does not trust, and the optional
    ``azp`` / ``nonce`` / ``max_age`` / ``at_hash`` / ``c_hash`` checks, each
    run only when the corresponding argument is supplied.

    Args:
        id_token: The compact-serialized ID Token JWT.
        token_validation_config: Validation configuration. ``audience`` should
            be the RP's ``client_id`` and ``issuer`` the OP issuer.
        disco_doc_address: Discovery document address (required when
            ``perform_disco`` is True).
        http_client: Optional managed HTTP client (see ``validate_token``).
        trusted_audiences: Additional audiences the client trusts besides
            ``token_validation_config.audience``. Every ``aud`` value MUST be
            the audience or one of these (§3.1.3.7 step 3); omitted or empty
            means the audience is the only trusted one.
        validate_azp: Opt in to the ``azp`` authorized-party rules: multiple
            audiences require an ``azp``, and a present ``azp`` must equal
            ``token_validation_config.audience``. Neither is a MUST in OIDC
            Core 1.0 errata set 2 (§3.1.3.7 steps 4-5), so the default is
            ``False`` and ``azp`` is ignored (§2). Requires
            ``token_validation_config.audience``.
        nonce: The ``nonce`` the RP sent on the authorization request. When
            provided, the token's ``nonce`` MUST match it (§3.1.3.7 step 11).
        access_token: The access token that came with the ID Token. When
            provided, the token's ``at_hash`` MUST match it (§3.3.2.11), and
            MUST be present unless ``access_token_issued_with_id_token`` is
            ``False``.
        code: The authorization code. When provided, the token's ``c_hash``
            MUST match it (§3.3.2.11), and MUST be present unless
            ``code_issued_with_id_token`` is ``False``.
        access_token_issued_with_id_token: Whether ``access_token`` came back
            in the same authorization response as the ID Token
            (``id_token token`` / ``code id_token token``), which makes
            ``at_hash`` REQUIRED (§3.2.2.10, §3.3.2.11). Defaults to ``True``.
            Pass ``False`` for a token-endpoint ID Token, which may omit
            ``at_hash`` (§3.1.3.6).
        code_issued_with_id_token: Whether ``code`` came back in the same
            authorization response as the ID Token (``code id_token`` /
            ``code id_token token``), which makes ``c_hash`` REQUIRED
            (§3.3.2.11). Defaults to ``True``.
        max_age: The ``max_age`` the RP requested. When provided, ``auth_time``
            MUST be present and recent enough (§3.1.3.7 step 12).

    Returns:
        dict: The decoded and validated ID Token claims.

    Raises:
        TokenValidationException: If standard JWT validation fails (bad
            signature, wrong issuer/audience, expired token).
        UntrustedAudienceException: If ``aud`` carries an audience the client
            does not trust (§3.1.3.7 step 3).
        IdTokenValidationException: If an ID-Token-profile rule fails.
        AzpRequiresClientIdError: If ``validate_azp`` is set without
            ``token_validation_config.audience``. Raised before any I/O.
        ConfigurationException: If the configuration is invalid.
    """
    check_azp_config(token_validation_config.audience, validate_azp)
    claims = validate_token(
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
        trusted_audiences=trusted_audiences,
        validate_azp=validate_azp,
        nonce=nonce,
        access_token=access_token,
        code=code,
        access_token_issued_with_id_token=access_token_issued_with_id_token,
        code_issued_with_id_token=code_issued_with_id_token,
        max_age=max_age,
        leeway=token_validation_config.leeway or 0.0,
        now=time.time(),
    )
    return claims


__all__ = ["validate_id_token"]
