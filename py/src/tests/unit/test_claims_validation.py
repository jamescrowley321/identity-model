"""Unit tests for the injectable, composable claims validators (issue #603)."""

import logging

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
    assert err.token_part == "payload"
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
    with pytest.raises(ValueError, match="at least one") as exc:
        require_claims()
    # Exact message (not just `match`) so a mutation to the string is killed.
    assert str(exc.value) == "require_claims needs at least one claim name"


# --- require_claim_value ---------------------------------------------------


def test_require_claim_value_accepts_and_rejects():
    require_claim_value("role", "admin")({"role": "admin"})
    with pytest.raises(ClaimsValidationError) as exc:
        require_claim_value("role", "admin")({"role": "user"})
    assert exc.value.claim == "role"
    assert exc.value.reason == "claim 'role' must equal 'admin'"


def test_require_claim_value_rejects_absent_claim():
    with pytest.raises(ClaimsValidationError) as exc:
        require_claim_value("role", "admin")({})
    assert exc.value.claim == "role"


def test_require_claim_value_none_requires_present_null_not_absent():
    # "must equal None" means present-and-null — an absent claim must NOT pass
    # (the fail-open a plain `.get() != value` would allow).
    require_claim_value("x", None)({"x": None})
    with pytest.raises(ClaimsValidationError):
        require_claim_value("x", None)({})


# --- require_scopes --------------------------------------------------------


def test_require_scopes_from_space_delimited_string():
    require_scopes("read")({"scope": "read write"})


def test_require_scopes_from_scp_list():
    require_scopes("read", "write")({"scp": ["read", "write", "admin"]})


def test_require_scopes_needs_a_scope():
    with pytest.raises(ValueError, match="at least one") as exc:
        require_scopes()
    assert str(exc.value) == "require_scopes needs at least one scope"


def test_require_scopes_rejects_missing_and_names_them():
    # Two missing scopes exercise the ', '-join separator; the granted "read" is
    # not named. Exact reason + claim pin the message, separator, and claim tag.
    with pytest.raises(ClaimsValidationError) as exc:
        require_scopes("delete", "admin", "read")({"scope": "read"})
    assert exc.value.claim == "scope"
    assert exc.value.reason == "missing required scope(s): delete, admin"


def test_require_scopes_malformed_claim_fails_closed():
    # A non-string, non-list scope claim yields no granted scopes → reject,
    # never crash.
    for bad in ({"unexpected": "shape"}, 123, None):
        with pytest.raises(ClaimsValidationError):
            require_scopes("read")({"scope": bad})


def test_require_scopes_list_drops_non_string_members_without_crashing():
    # Non-string list members are ignored; valid string scopes still count.
    require_scopes("read")({"scope": ["read", 7, None]})
    with pytest.raises(ClaimsValidationError):
        require_scopes("admin")({"scope": ["read", 7, None]})


def test_require_scopes_empty_scope_falls_through_to_scp():
    # An empty-string `scope` must not shadow a populated `scp` (interop).
    require_scopes("read")({"scope": "", "scp": ["read", "write"]})


def test_require_scopes_nonempty_scope_takes_precedence_over_scp():
    # A present, non-empty `scope` wins; `scp` is not consulted.
    with pytest.raises(ClaimsValidationError):
        require_scopes("write")({"scope": "read", "scp": ["write"]})


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
    assert exc.value.reason == (
        "no validator accepted the claims: "
        "required claim 'a' is missing; required claim 'b' is missing"
    )


def test_combine_any_empty_is_rejected_at_construction():
    with pytest.raises(ValueError, match="at least one") as exc:
        combine_claims_validators([], require="any")
    assert str(exc.value) == (
        "combine_claims_validators(require='any') needs at least one "
        "validator; an empty any-of set rejects every token."
    )


def test_combine_all_empty_is_a_noop():
    combine_claims_validators([])({"anything": True})


def test_combine_all_propagates_non_claims_exception():
    # A programming error in a member is not swallowed as a rejection.
    def boom(_claims):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        combine_claims_validators([boom])({})


def test_combine_any_propagates_non_claims_exception():
    # The load-bearing invariant: `any` mode catches only ClaimsValidationError,
    # so a member's programming error is NOT recorded as a rejection reason (which
    # could flip the result to accept) — it propagates.
    def boom(_claims):
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        combine_claims_validators([boom, require_claims("sub")], require="any")({})


def test_combine_rejects_invalid_require_mode():
    # A typo like "All" must be a loud construction error, not a silent
    # reject-everything (it would otherwise fall into the any-branch).
    with pytest.raises(ValueError, match="'all' or 'any'"):
        combine_claims_validators([require_claims("sub")], require="All")  # type: ignore[bad-argument-type]


# --- protocol --------------------------------------------------------------


def test_plain_callable_satisfies_the_protocol():
    assert isinstance(require_claims("sub"), ClaimsValidator)
    assert not isinstance(42, ClaimsValidator)


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


def _only_identity_record(caplog) -> logging.LogRecord:
    # Exactly one py_identity_model record, so a mutation that drops or
    # duplicates the log is caught by the count.
    records = [r for r in caplog.records if r.name == "py_identity_model"]
    assert len(records) == 1, [r.getMessage() for r in records]
    return records[0]


def test_validate_claims_logs_the_rejection(caplog):
    # A structured rejection must still be logged server-side (the reason is not
    # lost just because it propagates unwrapped). Assert the EXACT message +
    # level so a mutation to the log string, level, or the logged value is
    # killed (a substring check survives mutmut's "XX…XX" string wrap).
    with (
        caplog.at_level(logging.INFO, logger="py_identity_model"),
        pytest.raises(ClaimsValidationError),
    ):
        validate_claims({"sub": "u1"}, _config(require_claims("tid")))
    rec = _only_identity_record(caplog)
    assert rec.levelno == logging.INFO
    assert rec.getMessage() == (
        "Claims validation rejected the token: required claim 'tid' is missing"
    )


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


async def test_validate_async_claims_logs_the_rejection(caplog):
    with (
        caplog.at_level(logging.INFO, logger="py_identity_model"),
        pytest.raises(ClaimsValidationError),
    ):
        await validate_async_claims({"sub": "u1"}, _config(require_claims("tid")))
    rec = _only_identity_record(caplog)
    assert rec.levelno == logging.INFO
    assert rec.getMessage() == (
        "Claims validation rejected the token: required claim 'tid' is missing"
    )
