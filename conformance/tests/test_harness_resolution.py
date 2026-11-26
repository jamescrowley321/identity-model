"""Tests for ``--harness`` config/manifest resolution in run_tests.py (#1198)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from run_tests import (
    MANIFEST_PATH,
    HARNESS_PLANS,
    RP_BASE_URL,
    Harness,
    HarnessError,
    HarnessRun,
    load_manifest,
    resolve_harness_run,
)


GO_RP_URL = "http://localhost:8890"
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


def test_go_harness_rejects_plan_outside_harness_plans(tmp_path):
    _write(tmp_path, "go-fastapi-basic-rp", {**PLAN_CONFIG, "rp_url": GO_RP_URL})

    with pytest.raises(HarnessError, match="runs only"):
        resolve_harness_run(
            Harness.GO, "fastapi-basic-rp", config_dir=tmp_path, results_dir=tmp_path
        )


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
