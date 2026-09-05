"""Injectable, composable claims validation (issue #603).

The token validators run a caller-supplied *claims validator* after signature,
issuer, audience and required-claim checks pass — the hook an application uses to
enforce its own rules on the decoded claims (tenant membership, custom scopes,
role checks, ...).

A claims validator is any callable ``(claims) -> None`` that raises to reject.
This module makes that contract first-class and composable:

* :class:`ClaimsValidator` — the documented protocol (a callable
  ``(claims) -> None``).
* :class:`ClaimsValidationError` — the typed rejection (a
  :class:`~py_identity_model.exceptions.TokenValidationException`), so a
  rejection carries a structured ``reason`` / ``claim`` instead of an opaque
  string.
* :func:`combine_claims_validators` — compose several validators into one
  (all-must-pass or any-must-pass).
* Ready-made, portable validators: :func:`require_claims`,
  :func:`require_claim_value`, :func:`require_scopes`.

Backward compatible: a plain ``(claims) -> None`` callable that raises any
exception still works exactly as before — this is an additive, opt-in layer.
The same interface shape is intended to be mirrored in the Go and Rust
libraries (interface / trait) so a resource server expresses the same policy in
any language.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from ..exceptions import TokenValidationException


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


class ClaimsValidationError(TokenValidationException):
    """Raised by a claims validator to reject a token's claims.

    Carries a structured ``reason`` (and optionally the offending ``claim``) so
    callers — and the token validators — can surface *why* without parsing a
    message string. It is a :class:`TokenValidationException`, so the existing
    ``except TokenValidationException`` handlers catch it unchanged.
    """

    def __init__(self, reason: str, *, claim: str | None = None) -> None:
        self.reason = reason
        self.claim = claim
        details: dict[str, str] = {"reason": reason}
        if claim is not None:
            details["claim"] = claim
        super().__init__(reason, token_part="payload", details=details)


@runtime_checkable
class ClaimsValidator(Protocol):
    """A callable that validates decoded token claims.

    Called with the decoded claims mapping after the standard checks pass.
    Return ``None`` to accept; raise :class:`ClaimsValidationError` to reject
    (any other exception is treated as a programming error and surfaces as a
    generic validation failure).

    ``claims`` is positional-only, so a validator may name its parameter
    anything — the library always calls it positionally.
    """

    def __call__(self, claims: Mapping[str, Any], /) -> None: ...


def combine_claims_validators(
    validators: Iterable[ClaimsValidator],
    *,
    require: Literal["all", "any"] = "all",
) -> ClaimsValidator:
    """Compose ``validators`` into a single claims validator.

    Args:
        validators: The validators to combine (evaluated in order).
        require: ``"all"`` (default) — every validator must accept; the combined
            validator raises the first :class:`ClaimsValidationError` (fail
            fast). ``"any"`` — at least one validator must accept; the combined
            validator raises a :class:`ClaimsValidationError` aggregating every
            reason only if all of them reject.

    Returns:
        A single ``(claims) -> None`` validator.

    Raises:
        ValueError: If ``require="any"`` is given no validators — an empty
            any-of set can never be satisfied, so it would reject every token
            (guarded like the middleware's empty-marker check). An empty
            ``require="all"`` set is a no-op (accept), which is harmless.

    Note:
        In ``any`` mode only a :class:`ClaimsValidationError` counts as a
        rejection worth trying the next validator for; any other exception
        (including a non-``ClaimsValidationError`` ``TokenValidationException``)
        propagates immediately rather than being aggregated — a "clean reject"
        is specifically a ``ClaimsValidationError``.

        Members must be synchronous. The resulting validator is synchronous and
        works in both the sync and async token-validation paths. Composing
        async validators is not yet supported.
    """
    if require not in ("all", "any"):
        # Guard a typo (e.g. "All") rather than silently treating it as "any"
        # and rejecting every token at call time with an empty reason.
        raise ValueError(f"require must be 'all' or 'any', got {require!r}")
    members = tuple(validators)
    if require == "any" and not members:
        raise ValueError(
            "combine_claims_validators(require='any') needs at least one "
            "validator; an empty any-of set rejects every token."
        )

    def _validate(claims: Mapping[str, Any]) -> None:
        if require == "all":
            for validator in members:
                validator(claims)
            return
        reasons: list[str] = []
        for validator in members:
            try:
                validator(claims)
            except ClaimsValidationError as exc:
                reasons.append(exc.reason)
            else:
                return
        raise ClaimsValidationError(
            "no validator accepted the claims: " + "; ".join(reasons)
        )

    return _validate


def _missing(claims: Mapping[str, Any], name: str) -> bool:
    """Whether ``name`` is absent or ``None`` in ``claims``."""
    return claims.get(name) is None


def require_claims(*names: str) -> ClaimsValidator:
    """A validator that rejects unless every named claim is present (non-null)."""
    if not names:
        raise ValueError("require_claims needs at least one claim name")

    def _validate(claims: Mapping[str, Any]) -> None:
        for name in names:
            if _missing(claims, name):
                raise ClaimsValidationError(
                    f"required claim {name!r} is missing", claim=name
                )

    return _validate


def require_claim_value(name: str, value: Any) -> ClaimsValidator:
    """A validator that rejects unless claim ``name`` is present and equals ``value``.

    An absent claim always rejects — including when ``value`` is ``None``, so
    ``require_claim_value("x", None)`` means "``x`` must be present and null",
    not "``x`` may be missing" (a fail-open a plain ``.get() != value`` would
    allow).
    """

    def _validate(claims: Mapping[str, Any]) -> None:
        if name not in claims or claims[name] != value:
            raise ClaimsValidationError(
                f"claim {name!r} must equal {value!r}", claim=name
            )

    return _validate


def _granted_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    """Scopes the token grants, from ``scope`` (space string) or ``scp`` (list).

    Any other shape (missing, dict, number) yields no granted scopes rather than
    raising — a malformed scope claim must fail closed, not crash validation.
    """
    raw = claims.get("scope")
    if raw is None or raw == "":
        # An absent OR empty ``scope`` falls through to ``scp`` — some IdPs send
        # ``{"scope": "", "scp": [...]}``; an empty string must not shadow the
        # populated array. A malformed (non-string) ``scope`` does NOT fall
        # through — it yields no scopes and rejects (fail closed).
        raw = claims.get("scp")
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset(s for s in raw if isinstance(s, str))
    return frozenset()


def require_scopes(*scopes: str) -> ClaimsValidator:
    """A validator that rejects unless the token grants every named scope.

    Reads OAuth 2.0 scopes from the ``scope`` (space-delimited string) or ``scp``
    (array) claim.
    """
    if not scopes:
        raise ValueError("require_scopes needs at least one scope")

    def _validate(claims: Mapping[str, Any]) -> None:
        granted = _granted_scopes(claims)
        missing = [scope for scope in scopes if scope not in granted]
        if missing:
            raise ClaimsValidationError(
                f"missing required scope(s): {', '.join(missing)}", claim="scope"
            )

    return _validate


__all__ = [
    "ClaimsValidationError",
    "ClaimsValidator",
    "combine_claims_validators",
    "require_claim_value",
    "require_claims",
    "require_scopes",
]
