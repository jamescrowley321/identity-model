"""Guards the expired-token harness gate itself.

``expired_token_or_skip`` is what stops a blanked ``TEST_EXPIRED_TOKEN``
secret from quietly disabling the tests that prove this library rejects
expired JWTs (#708). Its failure branch is exercised by no other test: both
call sites run with a live token, so deleting the ``pytest.fail`` and leaving
only the skip would keep the whole suite green -- precisely the failure mode
the helper exists to prevent.

A note on how these assert, because the obvious spelling does not work.
``pytest.raises(Failed)`` does NOT catch ``Skipped``, so a regression that
turns the fail back into a skip lets ``Skipped`` propagate and marks *this
test* skipped -- which pytest reports as a non-failure. The gate guarding the
gate would then have the same skipped-reads-as-passed hole as the thing it
guards. ``_outcome_of`` therefore catches both outcomes and returns the class,
so the assertion is on a value and a skip can never be mistaken for a pass.
"""

from __future__ import annotations

from _pytest.outcomes import Failed, Skipped
import pytest

from tests.integration.test_utils import expired_token_or_skip


VALID_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.c2ln"

#: Values that must not be accepted as an expired JWT. The WAF body is the real
#: one: Descope answers `Python-urllib` requests with it, so a mint script
#: without error handling writes exactly this into the secret.
NOT_A_JWT = {
    "empty": "",
    "waf_error_body": "error code: 1010",
    "two_segments": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9",
    "empty_signature": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.",
    "four_segments": "a.b.c.d",
}


def _outcome_of(config: dict) -> tuple[type | None, str]:
    """Return ``(outcome class, message)`` without letting a skip escape."""
    try:
        return None, expired_token_or_skip(config)
    except Skipped as exc:
        return Skipped, str(exc)
    except Failed as exc:
        return Failed, str(exc)


@pytest.mark.unit
def test_returns_the_token_when_it_is_a_jwt():
    outcome, value = _outcome_of(
        {"TEST_EXPIRED_TOKEN": VALID_JWT, "TEST_REQUIRE_LIVE": True}
    )
    assert outcome is None
    assert value == VALID_JWT


@pytest.mark.unit
@pytest.mark.parametrize("value", NOT_A_JWT.values(), ids=list(NOT_A_JWT))
def test_fails_rather_than_skips_when_live_is_required(value):
    """The assertion #708 turns on: in CI the job must go red, not green."""
    outcome, message = _outcome_of(
        {"TEST_EXPIRED_TOKEN": value, "TEST_REQUIRE_LIVE": True}
    )
    assert outcome is Failed, (
        f"expected a hard failure, got {getattr(outcome, '__name__', 'a pass')}"
        " -- a skipped test is not a passed test"
    )
    assert "TEST_EXPIRED_TOKEN" in message


@pytest.mark.unit
@pytest.mark.parametrize("value", NOT_A_JWT.values(), ids=list(NOT_A_JWT))
def test_skips_when_live_is_not_required(value):
    """Local runs keep the old behaviour: the token is genuinely optional."""
    outcome, _ = _outcome_of({"TEST_EXPIRED_TOKEN": value, "TEST_REQUIRE_LIVE": False})
    assert outcome is Skipped


@pytest.mark.unit
def test_absent_require_live_key_skips():
    """A config predating TEST_REQUIRE_LIVE must not start failing."""
    outcome, _ = _outcome_of({"TEST_EXPIRED_TOKEN": ""})
    assert outcome is Skipped


@pytest.mark.unit
def test_failure_message_never_echoes_the_token():
    """The value is a credential; only its shape may reach the report."""
    secret = "not-a-jwt-but-still-secret"
    outcome, message = _outcome_of(
        {"TEST_EXPIRED_TOKEN": secret, "TEST_REQUIRE_LIVE": True}
    )
    assert outcome is Failed
    assert secret not in message
