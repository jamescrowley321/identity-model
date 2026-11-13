"""
Sender-constrained access tokens at the resource server (async).

Async counterparts of :mod:`py_identity_model.core.token_binding` and of
:func:`py_identity_model.core.dpop_verify.verify_dpop_proof`. The checks are
the same; the DPoP replay check awaits the replay cache, so an
:class:`~py_identity_model.core.dpop_verify.AsyncDPoPReplayCache` (a store
reached over the network) works here. A sync
:class:`~py_identity_model.core.dpop_verify.DPoPReplayCache` works too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.dpop_verify import _check_dpop_proof, record_proof_async
from ..core.token_binding import (
    TokenBinding,
    _check_binding_before_replay,
    _introspection_binding_before_replay,
)


if TYPE_CHECKING:
    from ..core.dpop_verify import (
        DPoPProof,
        DPoPProofRequest,
        DPoPVerificationOptions,
    )
    from ..core.models import TokenIntrospectionResponse, TokenValidationConfig
    from ..core.token_binding import TokenPresentation


async def verify_dpop_proof(
    proof: str,
    request: DPoPProofRequest,
    options: DPoPVerificationOptions,
    *,
    now: float | None = None,
) -> DPoPProof:
    """Verify a DPoP proof JWT received by a resource server (RFC 9449 §4.3).

    The async counterpart of
    :func:`py_identity_model.core.dpop_verify.verify_dpop_proof`, with the
    same checks; the replay check awaits ``options.replay_cache``.

    Raises:
        DPoPValidationError: If any check fails; ``kind`` says which.
    """
    verified, record = _check_dpop_proof(proof, request, options, now=now)
    await record_proof_async(record)
    return verified


async def check_token_binding(
    claims: dict,
    access_token: str,
    config: TokenValidationConfig,
    presentation: TokenPresentation | None,
) -> None:
    """Check an access token's sender constraint (async).

    The async counterpart of
    :func:`py_identity_model.core.token_binding.check_token_binding`.
    """
    record = _check_binding_before_replay(
        claims, access_token, config.required_binding, config.dpop, presentation
    )
    if record is not None:
        await record_proof_async(record)


async def check_introspection_binding(
    response: TokenIntrospectionResponse,
    access_token: str,
    presentation: TokenPresentation | None,
    *,
    required_binding: TokenBinding = TokenBinding.NONE,
    dpop: DPoPVerificationOptions | None = None,
) -> None:
    """Check an introspected token's sender constraint (async).

    The async counterpart of
    :func:`py_identity_model.core.token_binding.check_introspection_binding`,
    with the same rules and errors.
    """
    record = _introspection_binding_before_replay(
        response, access_token, presentation, required_binding, dpop
    )
    if record is not None:
        await record_proof_async(record)


__all__ = [
    "check_introspection_binding",
    "check_token_binding",
    "verify_dpop_proof",
]
