"""
State and issuer validation for OAuth 2.0 / OpenID Connect authorization callbacks.

Provides constant-time comparison of the ``state`` parameter to prevent
CSRF attacks on authorization callbacks (RFC 6749 Section 10.12), and
validation of the ``iss`` authorization-response parameter to defend
against mix-up attacks (RFC 9207).
"""

from dataclasses import dataclass
from enum import Enum
import hmac

from .authorize_response import AuthorizeCallbackResponse


class AuthorizeCallbackValidationResult(Enum):
    """Outcome of authorization callback state / issuer validation."""

    SUCCESS = "success"
    STATE_MISMATCH = "state_mismatch"
    MISSING_STATE = "missing_state"
    ERROR_RESPONSE = "error_response"
    ISSUER_MISMATCH = "issuer_mismatch"
    MISSING_ISSUER = "missing_issuer"


@dataclass(frozen=True, kw_only=True)
class StateValidationResult:
    """Result of validating the ``state`` parameter in an authorization callback."""

    is_valid: bool
    result: AuthorizeCallbackValidationResult
    error: str | None = None
    error_description: str | None = None


def validate_authorize_callback_state(
    response: AuthorizeCallbackResponse,
    expected_state: str | None,
) -> StateValidationResult:
    """Validate the ``state`` parameter from an authorization callback.

    Checks are performed in priority order:

    1. **Error response** — if the authorization server returned an error,
       validation fails with ``ERROR_RESPONSE``.
    2. **Missing state** — if the callback or the caller-supplied
       *expected_state* is ``None`` or an empty string, validation fails
       with ``MISSING_STATE``.  Non-string types are also treated as
       missing.
    3. **State mismatch** — the received state is compared to
       *expected_state* using ``hmac.compare_digest`` (constant-time) to
       avoid timing side-channels.

    Args:
        response: A parsed ``AuthorizeCallbackResponse``.
        expected_state: The ``state`` value sent in the original
            authorization request.  May be ``None`` when the caller's
            session has expired or no state was stored.

    Returns:
        A ``StateValidationResult`` indicating whether validation passed.
    """
    if not response.is_successful:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.ERROR_RESPONSE,
            error=response.error,
            error_description=response.error_description,
        )

    if not isinstance(expected_state, str) or not expected_state:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.MISSING_STATE,
            error="missing_state",
            error_description="Expected state is missing or empty (session may have expired)",
        )

    if not response.state:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.MISSING_STATE,
            error="missing_state",
            error_description="State parameter not present in callback",
        )

    if not hmac.compare_digest(response.state, expected_state):
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.STATE_MISMATCH,
            error="state_mismatch",
            error_description="State parameter does not match expected value",
        )

    return StateValidationResult(
        is_valid=True,
        result=AuthorizeCallbackValidationResult.SUCCESS,
    )


def validate_authorize_callback_issuer(
    response: AuthorizeCallbackResponse,
    expected_issuer: str | None,
    *,
    iss_parameter_supported: bool = False,
    require: bool = False,
) -> StateValidationResult:
    """Validate the ``iss`` parameter from an authorization callback (RFC 9207).

    RFC 9207 adds an ``iss`` parameter to authorization responses so a client
    can bind the response to the authorization server that issued it, closing
    the "mix-up" attack class (RFC 9207 Section 1, Section 4) where a response
    from a malicious/compromised AS is replayed at an honest AS's callback.

    Checks are performed in priority order:

    1. **Error response** — if the authorization server returned an error,
       validation fails with ``ERROR_RESPONSE`` (mirrors state validation;
       there is no issuer to validate on an error).
    2. **Issuer present** — when the callback carries ``iss``, it MUST match
       *expected_issuer* (RFC 9207 Section 2.4: "the client MUST validate").
       This holds even when the metadata flag is unset — a present ``iss``
       is always validated, never ignored. "Present" means the parameter was
       supplied at all: a present-but-empty ``iss`` (``...&iss=``) is
       malformed and validated (and thus rejected), not folded into the
       "absent" branch. A missing/empty *expected_issuer* yields
       ``ISSUER_MISMATCH`` (fail closed: we cannot confirm the response's
       origin).
    3. **Issuer absent** — when the AS advertises support
       (*iss_parameter_supported*) or the caller opts into strict mode
       (*require*), an absent ``iss`` fails with ``MISSING_ISSUER`` (the
       server promised it / the caller demands it). Otherwise there is
       nothing to validate and the result is ``SUCCESS``.

    Unlike state, the issuer is not a secret, so a plain ``==`` comparison is
    used — constant-time comparison would guard a timing side-channel that
    does not exist here (contrast ``validate_authorize_callback_state``).

    Args:
        response: A parsed ``AuthorizeCallbackResponse``.
        expected_issuer: The ``issuer`` the client expects, typically
            ``DiscoveryDocumentResponse.issuer`` for the AS the request was
            sent to. May be ``None`` when unknown.
        iss_parameter_supported: Whether the AS advertises
            ``authorization_response_iss_parameter_supported`` in its
            metadata. When ``True``, an absent ``iss`` is treated as a
            failure.
        require: Strict opt-in. When ``True``, ``iss`` is required
            regardless of advertised metadata support.

    Returns:
        A ``StateValidationResult`` indicating whether validation passed.
    """
    if not response.is_successful:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.ERROR_RESPONSE,
            error=response.error,
            error_description=response.error_description,
        )

    enforce = iss_parameter_supported or require

    # ``is not None`` (not truthiness): the parser preserves a present-but-empty
    # ``iss=`` as "" (keep_blank_values), distinct from an absent parameter
    # (None). An empty issuer is malformed and MUST be validated (→ mismatch),
    # never silently downgraded to the "absent" branch.
    if response.issuer is not None:
        if not expected_issuer or response.issuer != expected_issuer:
            return StateValidationResult(
                is_valid=False,
                result=AuthorizeCallbackValidationResult.ISSUER_MISMATCH,
                error="issuer_mismatch",
                error_description=(
                    "Authorization response issuer does not match expected "
                    "issuer (possible mix-up attack)"
                ),
            )
        return StateValidationResult(
            is_valid=True,
            result=AuthorizeCallbackValidationResult.SUCCESS,
        )

    if enforce:
        return StateValidationResult(
            is_valid=False,
            result=AuthorizeCallbackValidationResult.MISSING_ISSUER,
            error="missing_issuer",
            error_description=(
                "Issuer (iss) parameter not present in callback but is "
                "required (advertised by the authorization server or "
                "explicitly required by the client)"
            ),
        )

    return StateValidationResult(
        is_valid=True,
        result=AuthorizeCallbackValidationResult.SUCCESS,
    )


__all__ = [
    "AuthorizeCallbackValidationResult",
    "StateValidationResult",
    "validate_authorize_callback_issuer",
    "validate_authorize_callback_state",
]
