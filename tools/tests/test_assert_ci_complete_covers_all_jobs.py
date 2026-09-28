"""Self-test for the ci-complete wiring check (tools/assert_ci_complete_covers_all_jobs.py).

``ci-complete`` is the one required check that stands for the whole CI matrix,
and this script is what stops its wiring from drifting. A version of it that
compared only the *keys* of its env maps passed three concrete miswirings of
the real workflow:

- A. ``go-mutation-gate=true`` hard-coded in SKIP_ALLOWED, so the Go mutation
  gate could skip forever and still read as justified;
- B. ``security-gate=${{ needs.lint.result }}`` in RESULTS, so the security
  gate's own result was never read;
- C. a duplicate ``security-gate=success`` line appended to RESULTS, which the
  last-wins bash reader turns into an unconditional pass.

And the paths filter it trusts omitted ``tools/**`` and ``Makefile``, so a PR
editing only a mutation waiver skipped both native mutation gates while
ci-complete called the skip justified.

Each test below feeds the checker the REAL ci.yml with exactly one such edit
applied and asserts the precise set of failures it reports -- so a checker that
goes back to passing any of them fails here, and so does one that starts
flagging the untouched workflow.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
from typing import Any

import pytest
import yaml


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DRIVER = _REPO_ROOT / "tools" / "assert_ci_complete_covers_all_jobs.py"
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_spec = importlib.util.spec_from_file_location("assert_ci_complete", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
gate_check = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gate_check
_spec.loader.exec_module(gate_check)

GATE = gate_check.GATE

GO_SKIP = (
    "${{ needs.changes.outputs.go != 'true' && "
    "needs.changes.outputs.shared != 'true' && !inputs.run-native-tests }}"
)
RUST_SKIP = GO_SKIP.replace("outputs.go", "outputs.rust")


def _real_text() -> str:
    return _WORKFLOW.read_text()


def _mutate(text: str, old: str, new: str) -> str:
    """Replace exactly one occurrence, so a stale anchor fails loudly."""
    assert text.count(old) == 1, f"anchor not unique in ci.yml: {old!r}"
    return text.replace(old, new)


def _failures(workflow: str | dict[str, Any]) -> set[tuple[str, str, str]]:
    loaded = yaml.safe_load(workflow) if isinstance(workflow, str) else workflow
    return {(f.kind, f.job, f.subject) for f in gate_check.check(loaded, _REPO_ROOT)}


def _conditional_jobs() -> list[str]:
    jobs = yaml.safe_load(_real_text())["jobs"]
    return sorted(n for n, j in jobs.items() if n != GATE and "if" in j)


def _skip_allowed_line(text: str, job: str) -> str:
    step = next(
        s
        for s in yaml.safe_load(text)["jobs"][GATE]["steps"]
        if "SKIP_ALLOWED" in (s.get("env") or {})
    )
    return next(
        line.strip()
        for line in step["env"]["SKIP_ALLOWED"].splitlines()
        if line.strip().startswith(f"{job}=")
    )


# ── the real workflow ────────────────────────────────────────────────────────


def test_real_workflow_is_fully_wired() -> None:
    assert _failures(_real_text()) == set()


def test_real_workflow_has_the_jobs_these_tests_mutate() -> None:
    # Guards the anchors below: if a job is renamed, these tests would
    # otherwise start testing nothing.
    jobs = yaml.safe_load(_real_text())["jobs"]
    assert {"go-mutation-gate", "rust-mutation-gate", "security-gate", "lint"} <= set(
        jobs
    )


# ── scenario A: hard-coded skip allowance ────────────────────────────────────


@pytest.mark.parametrize("value", ["true", "${{ true }}", "${{ !false }}"])
def test_A_hardcoded_true_skip_allowance_is_rejected(value: str) -> None:
    text = _mutate(
        _real_text(), f"go-mutation-gate={GO_SKIP}", f"go-mutation-gate={value}"
    )
    assert _failures(text) == {("skip-allowed-not-negation", "go-mutation-gate", "")}


@pytest.mark.parametrize("job", _conditional_jobs())
def test_every_conditional_job_rejects_a_hardcoded_true(job: str) -> None:
    text = _real_text()
    line = _skip_allowed_line(text, job)
    text = _mutate(text, line, f"{job}=${{{{ true }}}}")
    assert _failures(text) == {("skip-allowed-not-negation", job, "")}


def test_skip_allowance_copied_from_another_job_is_rejected() -> None:
    text = _mutate(
        _real_text(), f"go-mutation-gate={GO_SKIP}", f"go-mutation-gate={RUST_SKIP}"
    )
    assert _failures(text) == {("skip-allowed-not-negation", "go-mutation-gate", "")}


def test_skip_allowance_that_drops_a_term_is_rejected() -> None:
    weakened = "${{ needs.changes.outputs.go != 'true' && !inputs.run-native-tests }}"
    text = _mutate(
        _real_text(), f"go-mutation-gate={GO_SKIP}", f"go-mutation-gate={weakened}"
    )
    assert _failures(text) == {("skip-allowed-not-negation", "go-mutation-gate", "")}


@pytest.mark.parametrize(
    "equivalent",
    [
        # Same conjuncts, different order.
        "${{ !inputs.run-native-tests && needs.changes.outputs.shared != 'true' "
        "&& needs.changes.outputs.go != 'true' }}",
        # The literal negation of the `if:`, before De Morgan.
        "${{ !(needs.changes.outputs.go == 'true' || "
        "needs.changes.outputs.shared == 'true' || inputs.run-native-tests) }}",
        # Operands of a comparison swapped.
        "${{ 'true' != needs.changes.outputs.go && "
        "needs.changes.outputs.shared != 'true' && !inputs.run-native-tests }}",
    ],
)
def test_logically_identical_skip_allowance_is_accepted(equivalent: str) -> None:
    text = _mutate(
        _real_text(), f"go-mutation-gate={GO_SKIP}", f"go-mutation-gate={equivalent}"
    )
    assert _failures(text) == set()


# ── scenario B: RESULTS reading another job ──────────────────────────────────


def test_B_results_reading_another_job_is_rejected() -> None:
    text = _mutate(
        _real_text(),
        "security-gate=${{ needs.security-gate.result }}",
        "security-gate=${{ needs.lint.result }}",
    )
    assert _failures(text) == {("results-wrong-source", "security-gate", "")}


def test_results_literal_success_is_rejected() -> None:
    text = _mutate(
        _real_text(),
        "security-gate=${{ needs.security-gate.result }}",
        "security-gate=success",
    )
    assert _failures(text) == {("results-wrong-source", "security-gate", "")}


# ── scenario C: duplicate key overriding the real entry ─────────────────────


def test_C_duplicate_results_entry_is_rejected() -> None:
    anchor = "load-smoke=${{ needs.load-smoke.result }}"
    text = _mutate(_real_text(), anchor, f"{anchor}\n            security-gate=success")
    # Both the duplicate and the value the last-wins reader would act on.
    assert _failures(text) == {
        ("duplicate-RESULTS", "security-gate", ""),
        ("results-wrong-source", "security-gate", ""),
    }


def test_duplicate_skip_allowed_entry_is_rejected() -> None:
    anchor = f"rust-mutation-gate={RUST_SKIP}"
    text = _mutate(_real_text(), anchor, f"{anchor}\n            go-mutation-gate=true")
    assert _failures(text) == {
        ("duplicate-SKIP_ALLOWED", "go-mutation-gate", ""),
        ("skip-allowed-not-negation", "go-mutation-gate", ""),
    }


# ── paths filter vs what change-gated jobs read ──────────────────────────────


def test_filter_without_tools_and_makefile_is_rejected() -> None:
    text = _mutate(_real_text(), "              - 'tools/**'\n", "")
    text = _mutate(text, "              - 'Makefile'\n", "")
    assert _failures(text) == {
        ("filter-misses-read", job, path)
        for job in ("go-mutation-gate", "rust-mutation-gate")
        for path in (
            "Makefile",
            "tools/mutation_security_native.py",
            "tools/mutation_security_go_allowlist.txt",
            "tools/mutation_security_rust_allowlist.txt",
        )
    }


def test_filter_covering_the_driver_but_not_its_allowlists_is_rejected() -> None:
    # The allowlists are never named in ci.yml or the Makefile; the driver
    # builds their paths as REPO_ROOT / "tools" / "..._allowlist.txt". A filter
    # narrowed to just the driver would let a waiver-only PR skip the gates.
    text = _mutate(
        _real_text(),
        "              - 'tools/**'\n",
        "              - 'tools/mutation_security_native.py'\n",
    )
    assert _failures(text) == {
        ("filter-misses-read", job, f"tools/mutation_security_{lang}_allowlist.txt")
        for job in ("go-mutation-gate", "rust-mutation-gate")
        for lang in ("go", "rust")
    }


def test_filter_without_env_profile_is_rejected() -> None:
    text = _mutate(_real_text(), "              - '.env.identityserver'\n", "")
    assert _failures(text) == {
        ("filter-misses-read", "integration-tests-go", ".env.identityserver")
    }


def test_filter_without_infra_is_rejected() -> None:
    text = _mutate(_real_text(), "              - 'infra/**'\n", "")
    assert _failures(text) == {
        ("filter-misses-read", job, "infra/docker-compose.yml")
        for job in ("integration-tests-go", "integration-tests-rust")
    }


@pytest.mark.parametrize(
    "glob",
    [
        # Negation: dorny excludes the path, a negation-blind matcher would
        # still see `**` and call the read covered.
        "!tools/mutation_security_native.py",
        "tools/{mutation_security_native.py,other.py}",
        "tools/[m]utation_security_native.py",
        "tools/@(mutation_security_native.py)",
    ],
)
def test_filter_glob_the_checker_cannot_evaluate_is_rejected(glob: str) -> None:
    text = _mutate(
        _real_text(),
        "              - 'tools/**'\n",
        f"              - 'tools/**'\n              - '{glob}'\n",
    )
    assert _failures(text) == {("unsupported-filter-glob", "changes", glob)}


def test_change_type_filter_entry_is_rejected() -> None:
    workflow = _load()
    step = next(
        s
        for s in workflow["jobs"]["changes"]["steps"]
        if str(s.get("uses", "")).startswith("dorny/paths-filter")
    )
    filters = yaml.safe_load(step["with"]["filters"])
    filters["shared"].append({"added": "tools/**"})
    step["with"]["filters"] = yaml.safe_dump(filters)
    assert {(k, j) for k, j, _ in _failures(workflow)} == {
        ("unsupported-filter-glob", "changes")
    }


# ── structural drift ─────────────────────────────────────────────────────────


def _load() -> dict[str, Any]:
    return copy.deepcopy(yaml.safe_load(_real_text()))


def _check_step(workflow: dict[str, Any]) -> dict[str, Any]:
    return next(
        s for s in workflow["jobs"][GATE]["steps"] if "RESULTS" in (s.get("env") or {})
    )


def test_job_missing_from_needs_and_results_is_rejected() -> None:
    text = _mutate(
        _real_text(), "            load-smoke=${{ needs.load-smoke.result }}\n", ""
    )
    text = _mutate(text, ", load-smoke]", "]")
    assert _failures(text) == {
        ("missing-from-needs", "load-smoke", ""),
        ("missing-from-RESULTS", "load-smoke", ""),
    }


def test_needs_only_job_cannot_be_exempted() -> None:
    # A job with `needs:` but no `if:` skips only when a dependency skipped --
    # the anomaly the gate exists to catch. It must not be SKIP_ALLOWED.
    workflow = _load()
    workflow["jobs"]["extra"] = {
        "needs": "changes",
        "runs-on": "ubuntu-latest",
        "steps": [],
    }
    workflow["jobs"][GATE]["needs"].append("extra")
    env = _check_step(workflow)["env"]
    env["RESULTS"] += "extra=${{ needs.extra.result }}\n"
    env["SKIP_ALLOWED"] += "extra=${{ true }}\n"
    assert _failures(workflow) == {("skip-allowed-on-unconditional", "extra", "")}


def test_conditional_job_without_skip_allowance_is_rejected() -> None:
    text = _mutate(_real_text(), f"            go-mutation-gate={GO_SKIP}\n", "")
    assert _failures(text) == {("missing-from-SKIP_ALLOWED", "go-mutation-gate", "")}


def test_malformed_results_line_is_rejected() -> None:
    anchor = "load-smoke=${{ needs.load-smoke.result }}"
    text = _mutate(_real_text(), anchor, f"{anchor}\n            security-gate")
    assert _failures(text) == {("malformed-RESULTS", "", "")}


def test_empty_env_on_a_gate_step_does_not_crash() -> None:
    workflow = _load()
    workflow["jobs"][GATE]["steps"].insert(0, {"run": "true", "env": None})
    assert _failures(workflow) == set()


def test_missing_gate_job_is_rejected() -> None:
    workflow = _load()
    del workflow["jobs"][GATE]
    assert _failures(workflow) == {("no-gate-job", GATE, "")}
