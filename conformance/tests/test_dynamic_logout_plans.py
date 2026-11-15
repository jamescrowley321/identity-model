"""Harness rules for the dynamic and logout plans (issue #1139)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from run_tests import DECLARED_UNSUPPORTED_TESTS


MANIFEST = json.loads((Path(__file__).parents[1] / "expected_modules.json").read_text())
END_SESSION = "https://op.example.com/end_session"


def test_webfinger_and_unsigned_request_objects_are_declared_unsupported():
    assert sorted(DECLARED_UNSUPPORTED_TESTS) == [
        "oidcc-client-test-discovery-webfinger-acct",
        "oidcc-client-test-discovery-webfinger-url",
        "oidcc-client-test-request-uri-signed-none",
    ]


def test_every_declared_unsupported_module_is_allowlisted_as_skipped():
    entries = {
        name: [plan[name] for plan in MANIFEST.values() if name in plan]
        for name in DECLARED_UNSUPPORTED_TESTS
    }

    assert {
        name: [(e["expect"], sorted(e.get("allow", {}))) for e in found]
        for name, found in entries.items()
    } == dict.fromkeys(DECLARED_UNSUPPORTED_TESTS, [("none", ["SKIPPED"])])


def test_no_state_module_expects_the_missing_state_to_be_refused():
    plan = MANIFEST["rpinitiated-logout-rp"]

    assert plan["oidcc-client-test-rp-init-logout-no-state"] == {
        "expect": "reject",
        "reasons": ["logout_state_validation"],
    }


def test_logout_always_sends_a_state(monkeypatch):
    import app as harness_app

    monkeypatch.setattr(
        harness_app,
        "_last_logout_context",
        {"end_session_endpoint": END_SESSION, "id_token": "", "client_id": "c"},
    )
    client = TestClient(harness_app.app, follow_redirects=False)

    response = client.get("/logout", params={"send_state": "false"})

    sent = parse_qs(urlsplit(response.headers["location"]).query)["state"]
    assert sent == [harness_app._expected_logout_state]


def test_logout_token_is_validated_with_the_registered_algorithm_only():
    import app as harness_app

    config = harness_app._logout_token_validation_config(
        {"issuer": "https://op.example.com", "client_id": "c"}
    )

    assert (config.algorithms, config.audience, config.issuer) == (
        ["RS256"],
        "c",
        "https://op.example.com",
    )
