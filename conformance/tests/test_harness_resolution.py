"""Tests for ``--harness`` config/manifest and plan resolution in run_tests.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from run_tests import (
    DEFAULT_PY_PLANS,
    MANIFEST_PATH,
    OP_CALLBACK_PROFILES,
    RP_BASE_URL,
    Harness,
    HarnessError,
    HarnessRun,
    discover_harness_plans,
    harness_plans,
    load_manifest,
    parse_plan_list,
    resolve_harness_run,
    resolve_plans,
    resolve_rp_urls,
)


GO_RP_URL = "http://localhost:8890"
HOSTED = "https://www.certification.openid.net/"
LOCAL = "https://localhost.emobix.co.uk:8443"
PUBLIC = "https://rp.example.com"
OIDF_RP_PLANS = [
    "basic-rp",
    "form-post-basic-rp",
    "config-rp",
    "fapi2-rp",
    "fapi2-mtls-rp",
    "fapi2-message-signing-rp",
    "dynamic-rp",
    "rpinitiated-logout-rp",
    "backchannel-logout-rp",
]
HARNESS_PLANS = harness_plans()
PLAN_CONFIG = {
    "plan_name": "oidcc-client-basic-certification-test-plan",
    "variant": {"client_registration": "static_client"},
    "alias": "test-rp",
}


def _write(config_dir: Path, name: str, config: object) -> Path:
    path = config_dir / f"{name}.json"
    path.write_text(json.dumps(config))
    return path


def test_python_harness_keeps_existing_config_and_default_rp_url(tmp_path):
    config_path = _write(tmp_path, "basic-rp", PLAN_CONFIG)

    run = resolve_harness_run(
        Harness.PY, "basic-rp", config_dir=tmp_path, results_dir=tmp_path
    )

    assert run == HarnessRun(
        config_path=config_path,
        manifest_plan="basic-rp",
        rp_base_url=RP_BASE_URL,
        rp_log_subdir=Path("basic-rp"),
        default_output=None,
    )


@pytest.mark.parametrize("harness", [Harness.GO, Harness.RUST])
@pytest.mark.parametrize("plan", HARNESS_PLANS)
def test_go_rust_harness_reads_prefixed_config_and_shared_manifest_key(
    tmp_path, harness, plan
):
    config_path = _write(
        tmp_path, f"{harness}-{plan}", {**PLAN_CONFIG, "rp_url": GO_RP_URL + "/"}
    )

    run = resolve_harness_run(harness, plan, config_dir=tmp_path, results_dir=tmp_path)

    assert run == HarnessRun(
        config_path=config_path,
        manifest_plan=plan,
        rp_base_url=GO_RP_URL,
        rp_log_subdir=Path(harness, plan),
        default_output=tmp_path / f"{harness}-{plan}-latest.json",
    )


def test_go_hosted_run_writes_under_hosted(tmp_path):
    _write(tmp_path, "go-basic-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    run = resolve_harness_run(
        Harness.GO, "basic-rp", hosted=True, config_dir=tmp_path, results_dir=tmp_path
    )

    assert run.default_output == tmp_path / "hosted" / "go-basic-rp-latest.json"


def test_rp_url_flag_overrides_config(tmp_path):
    _write(tmp_path, "rust-config-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    run = resolve_harness_run(
        Harness.RUST,
        "config-rp",
        "http://rp-rust:8891",
        config_dir=tmp_path,
        results_dir=tmp_path,
    )

    assert run.rp_base_url == "http://rp-rust:8891"


@pytest.mark.parametrize("plan", ["fastapi-basic-rp", "no-such-rp"])
def test_go_harness_rejects_plan_outside_harness_plans(tmp_path, plan):
    _write(tmp_path, f"go-{plan}", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="runs only"):
        resolve_harness_run(Harness.GO, plan, config_dir=tmp_path, results_dir=tmp_path)


def test_harness_plans_are_every_manifest_plan_but_fastapi():
    assert list(HARNESS_PLANS) == OIDF_RP_PLANS


def test_harness_plans_follow_the_manifest(tmp_path):
    manifest = tmp_path / "expected_modules.json"
    manifest.write_text(json.dumps({"b-rp": {}, "fastapi-b-rp": {}, "a-rp": {}}))

    assert harness_plans(manifest) == ("b-rp", "a-rp")


def test_unreadable_manifest_is_a_harness_error(tmp_path):
    with pytest.raises(HarnessError, match="cannot read manifest"):
        harness_plans(tmp_path / "missing.json")


def test_discovery_finds_the_harness_configs_in_manifest_order(tmp_path):
    for name in ["go-fapi2-rp", "go-basic-rp", "go-dynamic-rp", "rust-config-rp"]:
        _write(tmp_path, name, {**PLAN_CONFIG, "rp_url": GO_RP_URL})
    _write(tmp_path, "config-rp", PLAN_CONFIG)

    assert discover_harness_plans(Harness.GO, config_dir=tmp_path) == [
        "basic-rp",
        "fapi2-rp",
        "dynamic-rp",
    ]
    assert discover_harness_plans(Harness.RUST, config_dir=tmp_path) == ["config-rp"]


@pytest.mark.parametrize("name", ["go-fastapi-basic-rp", "go-basic-rpp"])
def test_discovery_rejects_a_config_naming_no_runnable_plan(tmp_path, name):
    _write(tmp_path, name, {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match=f"{name}.json names no plan"):
        discover_harness_plans(Harness.GO, config_dir=tmp_path)


@pytest.mark.parametrize(
    ("spec", "plans"),
    [
        ("", []),
        ("  ", []),
        ("fapi2-rp", ["fapi2-rp"]),
        ("fapi2-rp fapi2-mtls-rp", ["fapi2-rp", "fapi2-mtls-rp"]),
        ("fapi2-rp,fapi2-mtls-rp", ["fapi2-rp", "fapi2-mtls-rp"]),
        (" basic-rp, config-rp ,basic-rp ", ["basic-rp", "config-rp"]),
    ],
)
def test_parse_plan_list(spec, plans):
    assert parse_plan_list(spec) == plans


def test_python_default_plans_are_the_basic_trio():
    assert resolve_plans(Harness.PY, "") == list(DEFAULT_PY_PLANS)
    assert list(DEFAULT_PY_PLANS) == ["basic-rp", "config-rp", "form-post-basic-rp"]


def test_python_runs_any_named_harness_plan():
    assert resolve_plans(Harness.PY, ",".join(OIDF_RP_PLANS)) == OIDF_RP_PLANS


@pytest.mark.parametrize("plan", ["fastapi-basic-rp", "no-such-rp"])
def test_python_rejects_unknown_and_fastapi_plans(plan):
    with pytest.raises(HarnessError, match="unknown plan"):
        resolve_plans(Harness.PY, f"basic-rp {plan}")


@pytest.mark.parametrize("harness", [Harness.GO, Harness.RUST])
def test_go_rust_default_is_every_plan_with_a_config(tmp_path, harness):
    for plan in ["fapi2-mtls-rp", "basic-rp", "backchannel-logout-rp"]:
        _write(tmp_path, f"{harness}-{plan}", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    assert resolve_plans(harness, "", config_dir=tmp_path) == [
        "basic-rp",
        "fapi2-mtls-rp",
        "backchannel-logout-rp",
    ]


def test_go_rust_default_without_configs_is_an_error(tmp_path):
    with pytest.raises(HarnessError, match="no .*go-<plan>.json config exists"):
        resolve_plans(Harness.GO, "", config_dir=tmp_path)


def test_named_plan_without_its_harness_config_is_an_error(tmp_path):
    _write(tmp_path, "go-basic-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="config not found: .*go-fapi2-rp.json"):
        resolve_plans(Harness.GO, "basic-rp fapi2-rp", config_dir=tmp_path)


@pytest.mark.parametrize("harness", list(Harness))
@pytest.mark.parametrize("plan", sorted(OP_CALLBACK_PROFILES))
def test_hosted_op_callback_plan_needs_a_public_url_for_every_harness(
    tmp_path, harness, plan
):
    name = plan if harness is Harness.PY else f"{harness}-{plan}"
    _write(tmp_path, name, {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="needs --rp-public-url"):
        resolve_plans(harness, plan, suite_url=HOSTED, config_dir=tmp_path)
    assert resolve_plans(
        harness, plan, suite_url=HOSTED, rp_public_url=PUBLIC, config_dir=tmp_path
    ) == [plan]
    assert resolve_plans(harness, plan, suite_url=LOCAL, config_dir=tmp_path) == [plan]


@pytest.mark.parametrize("harness", list(Harness))
@pytest.mark.parametrize(
    "plan", ["basic-rp", "fapi2-rp", "fapi2-mtls-rp", "fapi2-message-signing-rp"]
)
def test_hosted_plan_without_op_callbacks_needs_no_public_url(tmp_path, harness, plan):
    name = plan if harness is Harness.PY else f"{harness}-{plan}"
    _write(tmp_path, name, {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    assert resolve_plans(harness, plan, suite_url=HOSTED, config_dir=tmp_path) == [plan]


@pytest.mark.parametrize("harness", [Harness.GO, Harness.RUST])
def test_hosted_default_skips_discovered_op_callback_plans_without_public_url(
    tmp_path, harness, caplog
):
    for plan in ["basic-rp", "dynamic-rp", "fapi2-rp", "backchannel-logout-rp"]:
        _write(tmp_path, f"{harness}-{plan}", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    assert resolve_plans(harness, "", suite_url=HOSTED, config_dir=tmp_path) == [
        "basic-rp",
        "fapi2-rp",
    ]
    assert "skipping dynamic-rp, backchannel-logout-rp" in caplog.text
    assert resolve_plans(
        harness, "", suite_url=HOSTED, rp_public_url=PUBLIC, config_dir=tmp_path
    ) == ["basic-rp", "fapi2-rp", "dynamic-rp", "backchannel-logout-rp"]
    assert resolve_plans(harness, "", suite_url=LOCAL, config_dir=tmp_path) == [
        "basic-rp",
        "fapi2-rp",
        "dynamic-rp",
        "backchannel-logout-rp",
    ]


def test_hosted_default_with_only_op_callback_plans_is_an_error(tmp_path):
    _write(tmp_path, "go-dynamic-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="needs --rp-public-url"):
        resolve_plans(Harness.GO, "", suite_url=HOSTED, config_dir=tmp_path)


def test_hosted_default_still_rejects_a_malformed_public_url(tmp_path):
    for plan in ["basic-rp", "dynamic-rp"]:
        _write(tmp_path, f"go-{plan}", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="not an absolute http"):
        resolve_plans(
            Harness.GO,
            "",
            suite_url=HOSTED,
            rp_public_url="ftp://x",
            config_dir=tmp_path,
        )


def test_rp_urls_are_distinct_per_resolved_config(tmp_path):
    mtls_url = "https://localhost:8891"
    _write(tmp_path, "go-basic-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})
    _write(tmp_path, "go-config-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL + "/"})
    _write(tmp_path, "go-fapi2-mtls-rp", {**PLAN_CONFIG, "rp_url": mtls_url})

    assert resolve_rp_urls(
        Harness.GO, ["fapi2-mtls-rp", "basic-rp", "config-rp"], config_dir=tmp_path
    ) == [mtls_url, GO_RP_URL]


def test_rp_urls_need_no_basic_rp_config(tmp_path):
    _write(tmp_path, "rust-fapi2-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    plans = resolve_plans(Harness.RUST, "", config_dir=tmp_path)
    assert resolve_rp_urls(Harness.RUST, plans, config_dir=tmp_path) == [GO_RP_URL]


def test_missing_go_config_is_an_error(tmp_path):
    with pytest.raises(HarnessError, match="config not found"):
        resolve_harness_run(
            Harness.GO, "basic-rp", config_dir=tmp_path, results_dir=tmp_path
        )


def test_go_config_without_rp_url_is_an_error(tmp_path):
    _write(tmp_path, "go-basic-rp", PLAN_CONFIG)

    with pytest.raises(HarnessError, match="needs rp_url"):
        resolve_harness_run(
            Harness.GO, "basic-rp", config_dir=tmp_path, results_dir=tmp_path
        )


@pytest.mark.parametrize(
    "rp_url", ["localhost:8890", "ftp://x", 8890, "", "http://[::1"]
)
def test_malformed_rp_url_is_an_error(tmp_path, rp_url):
    _write(tmp_path, "go-basic-rp", {**PLAN_CONFIG, "rp_url": rp_url})

    with pytest.raises(HarnessError, match="rp_url must be"):
        resolve_harness_run(
            Harness.GO, "basic-rp", config_dir=tmp_path, results_dir=tmp_path
        )


def test_invalid_json_config_is_an_error(tmp_path):
    (tmp_path / "go-basic-rp.json").write_text("{not json")

    with pytest.raises(HarnessError, match="invalid JSON"):
        resolve_harness_run(
            Harness.GO, "basic-rp", config_dir=tmp_path, results_dir=tmp_path
        )


@pytest.mark.parametrize("plan", HARNESS_PLANS)
def test_every_harness_plan_has_a_manifest_entry(plan):
    assert load_manifest(plan, MANIFEST_PATH)


@pytest.mark.parametrize("plan", HARNESS_PLANS)
def test_python_configs_resolve_to_port_8888(plan):
    run = resolve_harness_run(Harness.PY, plan)

    assert run.rp_base_url == RP_BASE_URL
