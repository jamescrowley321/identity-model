"""Tests for login detection in conformance/scripts/rotate_conformance_token.py.

The rotation script's whole job is gated on one question: *is this browser
profile authenticated to the conformance suite?* Getting that wrong in the
optimistic direction is silent — the script skips the interactive login wait,
tries to mint a token against a dead session, and closes the browser before the
operator can do anything. That is exactly what happened on 2026-09-15.

The original check inferred authentication from the **absence** of a nav link
named "Login". The suite's login page has no such link — it renders
"Proceed with Google" and "Proceed with GitLab" — so the selector matched
nothing and the script concluded it was signed in.

These tests pin the inverted contract: authentication must be proven by a
successful authenticated API call, and anything else — 401, 403, a network
failure, a surprise redirect — means *not logged in*. Fail closed.
"""

from __future__ import annotations

import pytest
from rotate_conformance_token import _needs_login


class FakePage:
    """Minimal stand-in for a Playwright ``Page``.

    Records the expressions it was asked to evaluate so a test can assert the
    check actually probes the API rather than sniffing the DOM.
    """

    def __init__(self, result: object | Exception) -> None:
        self._result = result
        self.evaluated: list[str] = []

    def evaluate(self, expression: str, *args: object) -> object:
        self.evaluated.append(expression)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def test_authenticated_session_does_not_need_login() -> None:
    page = FakePage(200)
    assert _needs_login(page) is False


@pytest.mark.parametrize("status", [401, 403])
def test_unauthenticated_status_needs_login(status: int) -> None:
    """The regression. A dead session must be reported as needing login.

    Before the fix this returned False, because the page had no "Login" link
    for the selector to find.
    """
    page = FakePage(status)
    assert _needs_login(page) is True


@pytest.mark.parametrize("status", [0, 302, 404, 500, 503])
def test_unexpected_status_needs_login(status: int) -> None:
    """Anything that is not a clean 200 fails closed."""
    page = FakePage(status)
    assert _needs_login(page) is True


def test_probe_failure_needs_login() -> None:
    """A thrown probe (offline, DNS failure, navigation mid-flight) fails closed."""
    page = FakePage(RuntimeError("net::ERR_NAME_NOT_RESOLVED"))
    assert _needs_login(page) is True


def test_non_numeric_result_needs_login() -> None:
    """A malformed probe result is not evidence of a session."""
    page = FakePage(None)
    assert _needs_login(page) is True


def test_check_probes_the_api_not_the_dom() -> None:
    """Guard against a regression to DOM-sniffing.

    The suite's markup is not a stable contract; ``/api/plan`` is. If someone
    reintroduces a selector-based heuristic this fails.
    """
    page = FakePage(200)
    _needs_login(page)

    assert page.evaluated, "expected _needs_login to probe via page.evaluate"
    probe = " ".join(page.evaluated)
    assert "/api/plan" in probe
    assert "credentials" in probe
