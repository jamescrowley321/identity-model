"""release/v5 alpha plumbing for the two Python distributions (#1147)."""

from __future__ import annotations

import re
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.version import Version


_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO_ROOT / ".github" / "workflows"
_CORE_CONFIG = _REPO_ROOT / "py" / "pyproject.toml"
_FASTAPI_CONFIG = (
    _REPO_ROOT / "py" / "packages" / "fastapi-identity-model" / "pyproject.toml"
)
_ALPHA_CLASSIFIER = "Development Status :: 3 - Alpha"
_SELECTED_RELEASE_BRANCH = "${{ github.event.inputs.branch || github.ref_name }}"


def _toml(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def _workflow(name: str) -> dict:
    return yaml.safe_load((_WORKFLOWS / name).read_text())


@pytest.mark.parametrize(
    ("config_path", "expected_branches"),
    [
        (
            _CORE_CONFIG,
            {
                "main": {"match": "main"},
                "other": {"match": ".*", "prerelease_token": "a", "prerelease": True},
            },
        ),
        (
            _FASTAPI_CONFIG,
            {
                "main": {"match": "main"},
                "v5": {
                    "match": "^release/v5$",
                    "prerelease_token": "a",
                    "prerelease": True,
                },
            },
        ),
    ],
)
def test_python_packages_use_alpha_prereleases_and_classifiers(
    config_path, expected_branches
) -> None:
    config = _toml(config_path)

    assert config["tool"]["semantic_release"]["branches"] == expected_branches
    assert _ALPHA_CLASSIFIER in config["project"]["classifiers"]


@pytest.mark.parametrize(
    ("branch", "expected_group"),
    [
        ("main", "main"),
        ("release/v5", "v5"),
        ("feature/x", None),
        ("release/v50", None),
    ],
)
def test_fastapi_versions_only_main_and_release_v5(branch, expected_group) -> None:
    branches = _toml(_FASTAPI_CONFIG)["tool"]["semantic_release"]["branches"]
    # PSR picks the first group whose `match` regex re.match-es the branch.
    matched = next(
        (name for name, group in branches.items() if re.match(group["match"], branch)),
        None,
    )

    assert matched == expected_group


def test_fastapi_alpha_can_install_the_core_alpha() -> None:
    project = _toml(_FASTAPI_CONFIG)["project"]
    requirement = next(
        Requirement(value)
        for value in project["dependencies"]
        if Requirement(value).name == "py-identity-model"
    )

    assert Version("5.0.0a1") in requirement.specifier
    assert Version("5.0.0a0") not in requirement.specifier
    assert Version("6.0.0") not in requirement.specifier


def test_psr_alpha_tags_match_both_publish_triggers() -> None:
    # These are the tags printed by the PSR 10.6.2 --noop acceptance dry runs.
    core_tag = "py-v5.0.0-a.1"
    fastapi_tag = "fastapi-identity-model-v0.4.0-a.1"
    core_patterns = _workflow("publish-dist.yml")[True]["push"]["tags"]
    fastapi_patterns = _workflow("release-fastapi.yml")[True]["push"]["tags"]

    core_alpha_pattern = "py-v[0-9]+.[0-9]+.[0-9]+-a.[0-9]+"
    assert core_alpha_pattern in core_patterns
    assert re.fullmatch(core_alpha_pattern, core_tag)
    assert "fastapi-identity-model-v*" in fastapi_patterns
    assert fnmatchcase(fastapi_tag, "fastapi-identity-model-v*")


def test_fastapi_versions_the_selected_main_or_release_v5_branch() -> None:
    jobs = _workflow("release.yml")["jobs"]
    fastapi_job = jobs["release-fastapi-version"]
    gate = " ".join(fastapi_job["if"].split())

    assert "== 'main'" in gate
    assert "== 'release/v5'" in gate
    checkout = next(
        step
        for step in fastapi_job["steps"]
        if "uses" in step and "checkout" in step["uses"]
    )
    assert checkout["with"]["ref"] == _SELECTED_RELEASE_BRANCH
    sync = next(
        step
        for step in fastapi_job["steps"]
        if step.get("name") == "Sync with commits pushed by the core release job"
    )
    assert sync["env"] == {"BRANCH": _SELECTED_RELEASE_BRANCH}
    assert sync["run"] == 'git pull --ff-only origin "$BRANCH"'
    assert fastapi_job["concurrency"]["group"] == (
        "${{ github.workflow }}-release-fastapi-" + _SELECTED_RELEASE_BRANCH
    )


def test_core_release_gates_on_the_selected_branch() -> None:
    jobs = _workflow("release.yml")["jobs"]

    assert jobs["conformance"]["with"] == {"ref": _SELECTED_RELEASE_BRANCH}
    assert jobs["release"]["concurrency"]["group"] == (
        "${{ github.workflow }}-release-" + _SELECTED_RELEASE_BRANCH
    )
    for step in jobs["release"]["steps"]:
        assert "inputs.branch" not in step.get("run", ""), step.get("name")


def test_conformance_checks_out_the_called_ref() -> None:
    workflow = _workflow("conformance.yml")
    checkouts = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "checkout" in step.get("uses", "")
    ]

    assert workflow[True]["workflow_call"]["inputs"]["ref"]["type"] == "string"
    assert checkouts
    for checkout in checkouts:
        assert checkout["with"]["ref"] == "${{ inputs.ref || github.ref }}"


@pytest.mark.parametrize(
    ("job_name", "config_name"),
    [
        ("release-go-version", "semantic-release-go.toml"),
        ("release-rust-version", "semantic-release-rust.toml"),
    ],
)
def test_native_release_tracks_stay_main_only(job_name, config_name) -> None:
    job = _workflow("release.yml")["jobs"][job_name]
    config = _toml(_REPO_ROOT / "tools" / config_name)

    assert "== 'main'" in job["if"]
    assert "release/v5" not in job["if"]
    assert set(config["tool"]["semantic_release"]["branches"]) == {"main"}
