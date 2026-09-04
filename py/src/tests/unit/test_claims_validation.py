"""Unit tests for the injectable, composable claims validators (issue #603)."""

import pytest

from py_identity_model import (
    ClaimsValidationError,
    ClaimsValidator,
    TokenValidationConfig,
    combine_claims_validators,
    require_claim_value,
    require_claims,
    require_scopes,
)
from py_identity_model.core.token_validation_logic import (
    validate_async_claims,
    validate_claims,
)
from py_identity_model.exceptions import TokenValidationException


pytestmark = pytest.mark.unit


def _config(validator) -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=False, claims_validator=validator)


# --- ClaimsValidationError -------------------------------------------------


def test_claims_validation_error_is_typed_and_structured():
    err = ClaimsValidationError("nope", claim="tenant")
    assert isinstance(err, TokenValidationException)
    assert err.reason == "nope"
    assert err.claim == "tenant"
    assert err.details == {"reason": "nope", "claim": "tenant"}


def test_claims_validation_error_without_claim():
    err = ClaimsValidationError("nope")
    assert err.claim is None
    assert err.details == {"reason": "nope"}


# --- require_claims --------------------------------------------------------


def test_require_claims_accepts_when_all_present():
    require_claims("sub", "tid")({"sub": "u1", "tid": "t1"})


def test_require_claims_rejects_missing_with_claim_name():
    with pytest.raises(ClaimsValidationError) as exc:
        require_claims("sub", "tid")({"sub": "u1"})
    assert exc.value.claim == "tid"


def test_require_claims_treats_none_as_missing():
    with pytest.raises(ClaimsValidationError):
        require_claims("tid")({"tid": None})


def test_require_claims_needs_a_name():
    with pytest.raises(ValueError, match="at least one"):
        require_claims()


# --- require_claim_value ---------------------------------------------------


def test_require_claim_value_accepts_and_rejects():
    require_claim_value("role", "admin")({"role": "admin"})
    with pytest.raises(ClaimsValidationError) as exc:
        require_claim_value("role", "admin")({"role": "user"})
    assert exc.value.claim == "role"


# --- require_scopes --------------------------------------------------------


def test_require_scopes_from_space_delimited_string():
    require_scopes("read")({"scope": "read write"})


def test_require_scopes_from_scp_list():
    require_scopes("read", "write")({"scp": ["read", "write", "admin"]})


def test_require_scopes_rejects_missing_and_names_them():
    with pytest.raises(ClaimsValidationError) as exc:
        require_scopes("read", "delete")({"scope": "read"})
    assert "delete" in exc.value.reason
    assert "read" not in exc.value.reason  # only the missing one is named


def test_require_scopes_malformed_claim_fails_closed():
    # A dict/number scope claim yields no granted scopes → reject, never crash.
    with pytest.raises(ClaimsValidationError):
        require_scopes("read")({"scope": {"unexpected": "shape"}})


# --- combine_claims_validators ---------------------------------------------


def test_combine_all_passes_when_every_validator_passes():
    combined = combine_claims_validators(
        [require_claims("sub"), require_scopes("read")]
    )
    combined({"sub": "u1", "scope": "read"})


def test_combine_all_raises_first_failure():
    combined = combine_claims_validators(
        [require_claims("sub"), require_claim_value("role", "admin")]
    )
    with pytest.raises(ClaimsValidationError) as exc:
        combined({"sub": "u1", "role": "user"})
    assert exc.value.claim == "role"


def test_combine_any_passes_when_one_passes():
    combined = combine_claims_validators(
        [require_claim_value("role", "admin"), require_scopes("read")],
        require="any",
    )
    combined({"role": "user", "scope": "read"})  # second one passes


def test_combine_any_aggregates_reasons_when_all_reject():
    combined = combine_claims_validators(
        [require_claims("a"), require_claims("b")], require="any"
    )
    with pytest.raises(ClaimsValidationError) as exc:
        combined({"c": 1})
    assert "'a'" in exc.value.reason
    assert "'b'" in exc.value.reason


def test_combine_any_empty_is_rejected_at_construction():
    with pytest.raises(ValueError, match="at least one"):
        combine_claims_validators([], require="any")


def test_combine_all_empty_is_a_noop():
    combine_claims_validators([])({"anything": True})


def test_combine_all_propagates_non_claims_exception():
    # A programming error in a member is not swallowed as a rejection.
    def boom(_claims):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        combine_claims_validators([boom])({})


# --- protocol --------------------------------------------------------------


def test_plain_callable_satisfies_the_protocol():
    assert isinstance(require_claims("sub"), ClaimsValidator)


# --- integration with the validation pipeline ------------------------------


def test_validate_claims_preserves_structured_reason():
    # A ClaimsValidationError propagates unwrapped (reason/claim intact), not
    # flattened into a generic "Claims validation failed: ..." string.
    config = _config(require_claims("tid"))
    with pytest.raises(ClaimsValidationError) as exc:
        validate_claims({"sub": "u1"}, config)
    assert exc.value.claim == "tid"


def test_validate_claims_wraps_plain_exception_generically():
    def legacy(_claims):
        raise ValueError("boom")  # a pre-#603 style validator

    with pytest.raises(TokenValidationException) as exc:
        validate_claims({"sub": "u1"}, _config(legacy))
    # Wrapped, not a ClaimsValidationError, and carries the generic message.
    assert not isinstance(exc.value, ClaimsValidationError)
    assert "Claims validation failed" in str(exc.value)


def test_validate_claims_accepts_valid_claims():
    validate_claims({"sub": "u1", "scope": "read"}, _config(require_scopes("read")))


async def test_validate_async_claims_preserves_structured_reason():
    config = _config(require_claim_value("role", "admin"))
    with pytest.raises(ClaimsValidationError) as exc:
        await validate_async_claims({"role": "user"}, config)
    assert exc.value.claim == "role"


async def test_validate_async_claims_supports_async_validator():
    async def async_validator(claims):
        if claims.get("sub") != "ok":
            raise ClaimsValidationError("bad sub", claim="sub")

    with pytest.raises(ClaimsValidationError) as exc:
        await validate_async_claims({"sub": "no"}, _config(async_validator))
    assert exc.value.claim == "sub"
