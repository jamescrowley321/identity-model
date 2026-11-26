"""Hosted runs of the plans whose OP calls the RP server-to-server.

The hosted suite cannot reach the harness on the runner's localhost, so the
dynamic and logout plans need the RP's public URL; without one they must fail
before a plan is created, not module by module.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from run_tests import (
    OP_CALLBACK_PROFILES,
    apply_rp_public_url,
    effective_rp_public_url,
    rp_public_url_problem,
    rp_public_url_unreachable,
)


HOSTED = "https://www.certification.openid.net/"
LOCAL = "https://localhost.emobix.co.uk:8443"
PUBLIC = "https://rp.example.com"
CONFIGS = OP_CALLBACK_PROFILES.keys()
CONFIG_DIR = Path(__file__).parent.parent / "configs"


def test_callback_profiles_are_the_dynamic_and_logout_plans():
    assert sorted(OP_CALLBACK_PROFILES) == [
        "backchannel-logout-rp",
        "dynamic-rp",
        "rpinitiated-logout-rp",
    ]


@pytest.mark.parametrize("profile", sorted(CONFIGS))
def test_hosted_callback_plan_without_public_url_is_refused(profile):
    problem = rp_public_url_problem(profile, HOSTED, None)

    assert problem is not None
    assert "--rp-public-url" in problem


@pytest.mark.parametrize("profile", sorted(CONFIGS))
def test_local_suite_needs_no_public_url(profile):
    assert rp_public_url_problem(profile, LOCAL, None) is None


@pytest.mark.parametrize("profile", ["basic-rp", "config-rp", "form-post-basic-rp"])
def test_redirect_only_plans_need_no_public_url_when_hosted(profile):
    assert rp_public_url_problem(profile, HOSTED, None) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8888",
        "http://127.0.0.1:8888",
        "rp.example.com",
        "ftp://rp.example.com",
    ],
)
def test_unreachable_or_malformed_public_url_is_refused(url):
    assert rp_public_url_problem("backchannel-logout-rp", HOSTED, url) is not None


def test_public_url_is_accepted_when_hosted():
    assert rp_public_url_problem("backchannel-logout-rp", HOSTED, PUBLIC) is None


@pytest.mark.parametrize("profile", ["rpinitiated-logout-rp", "backchannel-logout-rp"])
def test_logout_configs_register_the_public_backchannel_uri(profile):
    client = json.loads((CONFIG_DIR / f"{profile}.json").read_text())["client"]

    overridden = apply_rp_public_url(client, PUBLIC + "/")

    assert overridden["backchannel_logout_uri"] == f"{PUBLIC}/backchannel-logout"
    assert {k: v for k, v in overridden.items() if k != "backchannel_logout_uri"} == {
        k: v for k, v in client.items() if k != "backchannel_logout_uri"
    }
    # The committed config, used by the local suite, is left untouched.
    assert client["backchannel_logout_uri"] == "http://rp:8888/backchannel-logout"


def test_public_url_is_ignored_for_a_local_suite():
    assert effective_rp_public_url(LOCAL, PUBLIC) is None
    assert effective_rp_public_url(HOSTED, PUBLIC) == PUBLIC
    assert effective_rp_public_url(HOSTED, None) is None


def test_client_without_backchannel_uri_is_unchanged():
    client = {"client_id": "conformance-rp"}

    assert apply_rp_public_url(client, PUBLIC) is client
    assert apply_rp_public_url(None, PUBLIC) is None


def test_no_public_url_keeps_the_config():
    client = {"backchannel_logout_uri": "http://rp:8888/backchannel-logout"}

    assert apply_rp_public_url(client, None) is client


def test_health_reports_the_op_facing_base_url():
    import app as harness_app

    body = TestClient(harness_app.app).get("/health").json()

    assert body["op_facing_base_url"] == harness_app.RP_INTERNAL_BASE_URL


@respx.mock
def test_reachable_harness_with_matching_base_passes():
    respx.get(f"{PUBLIC}/health").respond(
        json={"status": "ok", "op_facing_base_url": PUBLIC}
    )

    assert rp_public_url_unreachable(PUBLIC + "/") is None


@respx.mock
def test_harness_base_with_trailing_slash_is_refused():
    # It would build request_uri as https://host//request-object/<id>.
    respx.get(f"{PUBLIC}/health").respond(
        json={"status": "ok", "op_facing_base_url": PUBLIC + "/"}
    )

    assert rp_public_url_unreachable(PUBLIC) is not None


def test_malformed_url_is_reported_not_raised():
    assert "not reachable" in (rp_public_url_unreachable("http://") or "")


@respx.mock
def test_harness_handing_out_another_base_is_refused():
    respx.get(f"{PUBLIC}/health").respond(
        json={"status": "ok", "op_facing_base_url": "http://localhost:8888"}
    )

    problem = rp_public_url_unreachable(PUBLIC)

    assert problem is not None
    assert f"RP_INTERNAL_BASE_URL={PUBLIC}" in problem


@respx.mock
def test_unreachable_public_url_is_refused():
    respx.get(f"{PUBLIC}/health").mock(side_effect=httpx.ConnectError("refused"))

    assert "not reachable" in (rp_public_url_unreachable(PUBLIC) or "")


@respx.mock
def test_non_200_health_is_refused():
    respx.get(f"{PUBLIC}/health").respond(status_code=502)

    assert "HTTP 502" in (rp_public_url_unreachable(PUBLIC) or "")


@respx.mock
def test_non_json_health_is_refused():
    respx.get(f"{PUBLIC}/health").respond(text="<html>tunnel error</html>")

    assert "JSON" in (rp_public_url_unreachable(PUBLIC) or "")
