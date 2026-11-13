"""Tests for the runner's per-module verdict and expected-module manifest."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from run_tests import (
    MANIFEST_PATH,
    Expectation,
    ManifestError,
    ModuleExpectation,
    RPEvidence,
    assess_module,
    check_plan_modules,
    drive_rp_authorize,
    load_manifest,
    _suite_status,
)


RP = "http://localhost:8888"
SUITE = "https://localhost.emobix.co.uk:8443"
ISSUER = f"{SUITE}/test/a/py-idm/"

REJECT_ID_TOKEN = ModuleExpectation(
    expect=Expectation.REJECT, reasons=frozenset({"id_token_validation"})
)
ACCEPT = ModuleExpectation(expect=Expectation.ACCEPT)
REJECTED_ID_TOKEN = {
    "test_id": "m1",
    "status": "error",
    "error": "id_token_validation: Invalid issuer",
}
ACCEPTED = {"test_id": "m1", "status": "success"}


def _drive_negative_flow_ending_in(callback: httpx.Response) -> list[str]:
    """Drive /authorize -> OP -> /callback, with the callback answering ``callback``."""
    respx.get(f"{RP}/authorize").mock(
        return_value=httpx.Response(302, headers={"location": f"{ISSUER}authorize"})
    )
    respx.get(f"{ISSUER}authorize").mock(
        return_value=httpx.Response(
            302, headers={"location": f"{RP}/callback?code=c&state=s"}
        )
    )
    respx.get(f"{RP}/callback").mock(return_value=callback)
    return drive_rp_authorize(
        rp_base_url=RP,
        issuer=ISSUER,
        client_id="conformance-rp",
        client_secret="",
        test_id="m1",
    )


@respx.mock
def test_harness_500_on_negative_module_fails():
    crashes = _drive_negative_flow_ending_in(httpx.Response(500))

    assert crashes == ["RP returned HTTP 500 at /callback"]
    # The suite saw the RP stop and passed the module; the crash overrides it,
    # even though the harness has no recorded result to contradict the suite.
    assert assess_module(
        "PASSED", REJECT_ID_TOKEN, RPEvidence(None, tuple(crashes))
    ) == ("FAILED", "harness crashed: RP returned HTTP 500 at /callback")


@respx.mock
def test_harness_deliberate_502_is_not_a_crash():
    crashes = _drive_negative_flow_ending_in(httpx.Response(502))

    assert crashes == []


@respx.mock
def test_harness_unreachable_is_a_crash():
    respx.get(f"{RP}/authorize").mock(side_effect=httpx.ConnectError("refused"))

    crashes = drive_rp_authorize(
        rp_base_url=RP,
        issuer=ISSUER,
        client_id="conformance-rp",
        client_secret="",
        test_id="m1",
    )

    assert crashes == ["RP request failed at /authorize: refused"]


@respx.mock
def test_correct_rejection_passes():
    crashes = _drive_negative_flow_ending_in(httpx.Response(400))

    assert assess_module(
        "PASSED", REJECT_ID_TOKEN, RPEvidence(REJECTED_ID_TOKEN, tuple(crashes))
    ) == ("PASSED", "")


def test_finished_with_null_result_is_failed():
    assert _suite_status({"status": "FINISHED", "result": None}) == "FAILED"


def test_finished_with_absent_result_is_failed():
    assert _suite_status({"status": "FINISHED"}) == "FAILED"


def test_finished_with_result_keeps_it():
    assert _suite_status({"status": "FINISHED", "result": "PASSED"}) == "PASSED"


def test_unfinished_status_is_kept():
    assert _suite_status({"status": "TIMEOUT", "id": "m1"}) == "TIMEOUT"


def test_null_result_fails_the_module():
    status = _suite_status({"status": "FINISHED", "result": None})

    assert assess_module(status, ACCEPT, RPEvidence(ACCEPTED)) == ("FAILED", "")


def test_negative_without_recorded_rejection_fails():
    assert assess_module("PASSED", REJECT_ID_TOKEN, RPEvidence(None)) == (
        "FAILED",
        "harness recorded no result for this module",
    )


def test_negative_the_rp_accepted_fails():
    assert assess_module("PASSED", REJECT_ID_TOKEN, RPEvidence(ACCEPTED)) == (
        "FAILED",
        "expected the RP to reject; harness recorded no rejection",
    )


def test_negative_rejected_for_wrong_reason_fails():
    wrong_reason = {"status": "error", "error": "token_exchange: invalid_grant"}

    assert assess_module("PASSED", REJECT_ID_TOKEN, RPEvidence(wrong_reason)) == (
        "FAILED",
        "RP rejected for 'token_exchange', expected one of ['id_token_validation']",
    )


def test_positive_the_rp_rejected_fails():
    assert assess_module("PASSED", ACCEPT, RPEvidence(REJECTED_ID_TOKEN)) == (
        "FAILED",
        "expected the RP to accept; harness recorded "
        "'id_token_validation: Invalid issuer'",
    )


def test_positive_with_success_passes():
    assert assess_module("PASSED", ACCEPT, RPEvidence(ACCEPTED)) == ("PASSED", "")


def test_suite_failure_is_kept():
    assert assess_module("FAILED", ACCEPT, RPEvidence(ACCEPTED)) == ("FAILED", "")


@pytest.mark.parametrize("status", ["SKIPPED", "WARNING"])
def test_unlisted_skip_or_warning_fails(status):
    assert assess_module(status, ACCEPT, RPEvidence(ACCEPTED)) == (
        "FAILED",
        f"suite status {status} is not allowlisted for this module",
    )


def test_allowlisted_skip_passes():
    expectation = ModuleExpectation(
        expect=Expectation.REJECT,
        reasons=frozenset({"id_token_validation"}),
        allowed_statuses=(("SKIPPED", "alg=none is never accepted"),),
    )

    assert assess_module("SKIPPED", expectation, RPEvidence(REJECTED_ID_TOKEN)) == (
        "SKIPPED",
        "",
    )


def test_allowlisted_skip_does_not_cover_warning():
    expectation = ModuleExpectation(
        expect=Expectation.ACCEPT,
        allowed_statuses=(("SKIPPED", "reason"),),
    )

    assert assess_module("WARNING", expectation, RPEvidence(ACCEPTED)) == (
        "FAILED",
        "suite status WARNING is not allowlisted for this module",
    )


def test_expect_none_skips_harness_evidence():
    expectation = ModuleExpectation(expect=Expectation.NONE)

    assert assess_module("PASSED", expectation, RPEvidence(None)) == ("PASSED", "")


MANIFEST = {"m-a": ACCEPT, "m-b": REJECT_ID_TOKEN}


def test_plan_matching_manifest_has_no_problems():
    assert check_plan_modules(["m-b", "m-a"], MANIFEST) == []


def test_missing_module_is_reported():
    assert check_plan_modules(["m-a"], MANIFEST) == [
        "expected modules missing from plan: m-b"
    ]


def test_unexpected_module_is_reported():
    assert check_plan_modules(["m-a", "m-b", "m-c"], MANIFEST) == [
        "unexpected modules in plan: m-c"
    ]


def test_duplicate_module_is_reported():
    assert check_plan_modules(["m-a", "m-b", "m-a"], MANIFEST) == [
        "modules listed more than once: m-a"
    ]


def _write_manifest(tmp_path: Path, plan_entry: dict) -> Path:
    path = tmp_path / "expected_modules.json"
    path.write_text(json.dumps({"plan": plan_entry}))
    return path


def test_load_manifest_parses_entries(tmp_path):
    path = _write_manifest(
        tmp_path,
        {
            "m-a": {"expect": "accept"},
            "m-b": {
                "expect": "reject",
                "reasons": ["id_token_validation"],
                "allow": {"SKIPPED": "why"},
            },
        },
    )

    assert load_manifest("plan", path) == {
        "m-a": ACCEPT,
        "m-b": ModuleExpectation(
            expect=Expectation.REJECT,
            reasons=frozenset({"id_token_validation"}),
            allowed_statuses=(("SKIPPED", "why"),),
        ),
    }


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"expect": "reject"}, "plan/m: a reject module must list its reasons"),
        (
            {"expect": "accept", "reasons": ["x"]},
            "plan/m: only reject modules take reasons",
        ),
        (
            {"expect": "accept", "allow": {"FAILED": "no"}},
            "plan/m: 'FAILED' cannot be allowlisted",
        ),
        (
            {"expect": "accept", "allow": {"SKIPPED": " "}},
            "plan/m: allowlisted SKIPPED needs a reason",
        ),
        ({"expect": "maybe"}, "plan/m: invalid expect 'maybe'"),
        ({"expect": "accept", "extra": 1}, "plan/m: unknown keys ['extra']"),
    ],
)
def test_load_manifest_rejects_malformed_entries(tmp_path, entry, message):
    path = _write_manifest(tmp_path, {"m": entry})

    with pytest.raises(ManifestError) as excinfo:
        load_manifest("plan", path)

    assert str(excinfo.value) == message


def test_load_manifest_without_plan_raises(tmp_path):
    path = _write_manifest(tmp_path, {})

    with pytest.raises(ManifestError) as excinfo:
        load_manifest("other", path)

    assert str(excinfo.value) == "no expected-module manifest for plan 'other'"


@pytest.mark.parametrize("plan", sorted(json.loads(MANIFEST_PATH.read_text())))
def test_committed_manifest_loads(plan):
    assert load_manifest(plan) != {}


def test_harness_records_unknown_state_against_last_flow(monkeypatch):
    import app as harness_app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(
        harness_app,
        "_last_flow_context",
        {"issuer": ISSUER, "client_id": "c", "disco_address": "", "test_id": "m9"},
    )
    monkeypatch.setattr(harness_app, "test_results", {})
    client = TestClient(harness_app.app)

    callback = client.get("/callback", params={"state": "nope", "code": "x"})
    recorded = client.get("/results/m9")

    assert callback.status_code == httpx.codes.BAD_REQUEST
    assert recorded.json() == {
        "test_id": "m9",
        "status": "error",
        "error": "state_validation: unknown state 'nope'",
    }


@pytest.mark.parametrize(
    ("status_code", "detail", "recorded"),
    [
        (401, "Nonce mismatch", "nonce_mismatch: Nonce mismatch"),
        (
            502,
            "Identity provider discovery failed",
            "discovery_failed: Identity provider discovery failed",
        ),
        (400, "something new", "router_rejected: something new"),
        (500, "Internal Server Error", "router_crashed: Internal Server Error"),
    ],
)
def test_fastapi_harness_classifies_router_rejections(status_code, detail, recorded):
    import app_fastapi

    response = httpx.Response(status_code, json={"detail": detail})

    assert app_fastapi._router_rejection(response) == recorded
