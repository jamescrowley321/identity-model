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


def _p256_key_with_short_x():
    """The first small-scalar P-256 key whose ``x`` has a leading zero byte."""
    from cryptography.hazmat.primitives.asymmetric import ec

    for scalar in range(1, 5000):
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        if key.public_key().public_numbers().x < 1 << 248:
            return key
    raise AssertionError("no short-x key in range")


def test_server_signing_jwk_keeps_full_width_coordinates(monkeypatch):
    import base64

    import run_tests

    key = _p256_key_with_short_x()
    monkeypatch.setattr(run_tests.ec, "generate_private_key", lambda _curve: key)

    jwk = run_tests._generate_server_signing_jwks()["keys"][0]

    widths = {
        member: len(base64.urlsafe_b64decode(jwk[member] + "=="))
        for member in ("x", "y", "d")
    }
    assert widths == {"x": 32, "y": 32, "d": 32}
