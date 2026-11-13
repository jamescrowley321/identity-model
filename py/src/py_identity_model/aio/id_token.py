"""Asynchronous OpenID Connect ID Token validation.

Async counterpart of :mod:`py_identity_model.sync.id_token`. Awaits the
standard async JWT validation (``validate_token`` without its access-token
sender-constraint check) then applies the same pure ID-Token profile
rules from ``core.id_token_logic`` — sync/async parity is guaranteed by
sharing that single pure validation function (OpenID Connect Core 1.0
§3.1.3.7 / §3.3.2.11).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from ..core.id_token_logic import (
    RefreshNonce,
    check_azp_config,
    require_issuer_without_discovery,
    unset_empty_client_id,
    validate_id_token_claims,
)
from ..core.parsers import extract_jwt_header_fields
from .token_validation import _validate_jwt_without_binding


if TYPE_CHECKING:
    from collections.abc import Iterable

    from ..core.models import TokenValidationConfig
    from .managed_client import AsyncHTTPClient
    from .validation_cache import AsyncValidationCache


async def validate_id_token(  # noqa: PLR0913  # OIDC id-token profile knobs (§3.1.3.7/§3.3.2.11)
    id_token: str,
    token_validation_config: TokenValidationConfig,
    disco_doc_address: str | None = None,
    http_client: AsyncHTTPClient | None = None,
    *,
    nonce: str | RefreshNonce | None,
    cache: AsyncValidationCache | None = None,
    trusted_audiences: Iterable[str] | None = None,
    validate_azp: bool = False,
    access_token: str | None = None,
    code: str | None = None,
    access_token_issued_with_id_token: bool = True,
    code_issued_with_id_token: bool = True,
    max_age: int | None = None,
) -> dict:
    """Validate an OpenID Connect ID Token (async) (OIDC Core §3.1.3.7 / §3.3.2.11).

    Runs the standard async JWT validation of ``validate_token`` (signature,
    ``iss``, ``aud``, and ``iat``/``exp`` when present) — set
    ``token_validation_config.audience`` to the RP's ``client_id`` so the
    ``aud`` check is enforced there — then applies the ID-Token profile:
    required ``exp``, ``iat`` and ``sub``, no audience the client does not
    trust, the ``nonce`` binding, and the optional ``azp`` / ``max_age`` /
    ``at_hash`` / ``c_hash`` checks, each run only when the corresponding
    argument is supplied.

    The access-token sender-constraint check (RFC 9449 §7, RFC 8705 §3) is not
    run: an ID Token (OIDC Core §3.1.3.7) arrives with no presentation, so a
    ``cnf`` claim in it is not checked.

    Args:
        id_token: The compact-serialized ID Token JWT.
        token_validation_config: Validation configuration. ``audience`` should
            be the RP's ``client_id`` and ``issuer`` the OP issuer.
        disco_doc_address: Discovery document address (required when
            ``perform_disco`` is True).
        http_client: Optional managed async HTTP client (see ``validate_token``).
        cache: Optional :class:`AsyncValidationCache` for the discovery document,
            JWKS and kid-miss cooldown (see ``validate_token``).
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
        nonce: Required, so the choice is explicit. One of:

            - the ``nonce`` the RP sent on the authorization request: the
              token's ``nonce`` MUST be present and match it (§3.1.3.7 step
              11, §3.2.2.11 step 2);
            - ``None`` when the RP sent none: a token that carries a ``nonce``
              is rejected (§2: a present ``nonce`` MUST equal the value sent);
            - ``RefreshNonce(original)`` for an ID Token returned by a token
              refresh: an absent ``nonce`` is accepted, and a present one MUST
              equal ``original``, the nonce of the ID Token from the original
              authentication (§12.2).
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
        IdTokenMissingClaimError: If ``exp`` or ``iat`` is absent (§2).
        IdTokenValidationException: If an ID-Token-profile rule fails.
        AzpRequiresClientIdError: If ``validate_azp`` is set without
            ``token_validation_config.audience``. Raised before any I/O.
        ConfigurationException: If the configuration is invalid, including
            ``perform_disco=False`` with no ``issuer`` (§3.1.3.7 step 2).
    """
    token_validation_config = unset_empty_client_id(token_validation_config)
    require_issuer_without_discovery(token_validation_config)
    check_azp_config(token_validation_config.audience, validate_azp)
    claims = await _validate_jwt_without_binding(
        id_token,
        token_validation_config,
        disco_doc_address=disco_doc_address,
        http_client=http_client,
        cache=cache,
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
