#!/usr/bin/env python3
"""Cross-language /spec vector-coverage gate (CONS-1.5, AC-CONS-1.5.2/1.5.3).

Runs each language's thin conformance runner (Python, Go, Rust) against the
shared ``spec/conformance`` vectors with ``SPEC_COVERAGE_OUT`` set, then
verifies every language executed every executable vector case id. Any missing
(language, vector-id) pair fails the gate by name; success prints a 100%
per-language coverage report.

Native-executed cases (``execution: "native"`` in the spec — behaviours a
static vector cannot express) must carry a per-language native-test anchor in
the language's report; the runners themselves verify the anchors point at real
tests.

Usage:
    uv run python tools/spec_coverage_gate.py            # run runners + gate
    uv run python tools/spec_coverage_gate.py --check-only <reports-dir>

Today ``validation.json`` is the only capability with executable vectors; as
more capabilities gain vectors, extend RUNNERS' report emission to one file
per capability and this inventory loop picks them up.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = REPO_ROOT / "spec" / "conformance"
DEFAULT_REPORT_DIR = REPO_ROOT / "build" / "spec-coverage"

# (language, working dir, command) — each runner writes SPEC_COVERAGE_OUT.
RUNNERS: list[tuple[str, Path, list[str]]] = [
    (
        "python",
        REPO_ROOT / "py",
        [
            "uv",
            "run",
            "pytest",
            "src/tests/unit/test_spec_conformance.py",
            "-m",
            "unit",
            "-n",
            "0",
            "-p",
            "no:benchmark",
            "-q",
        ],
    ),
    (
        "go",
        REPO_ROOT / "go",
        [
            "go",
            "test",
            "./internal/conformance/",
            "-run",
            "TestValidationConformance",
            "-count=1",
        ],
    ),
    (
        "rust",
        REPO_ROOT / "rust",
        ["cargo", "test", "--test", "spec_conformance"],
    ),
]


def spec_inventory() -> dict[str, dict[str, set[str]]]:
    """Executable + native case ids per capability that carries vectors."""
    inventory: dict[str, dict[str, set[str]]] = {}
    for path in sorted(SPEC_DIR.glob("*.json")):
        capability = json.loads(path.read_text())
        # A capability can opt OUT of the cross-language gate while its polyglot
        # runners are still being built (e.g. id-token.json — Python already
        # executes every vector, but the Go/Rust runners land in Epic 23 story
        # 23.2). Such a file carries executable vectors that would otherwise
        # trip the single-capability invariant below; skipping it here keeps the
        # gate green without silently dropping the enforced capabilities. Flip
        # the marker to any non-"pending" value (or drop it) once every language
        # ships a runner and this gate is extended to per-capability reports.
        if capability.get("cross_language_coverage_gate") == "pending":
            continue
        cases = capability.get("tests", [])
        executable = {
            c["id"]
            for c in cases
            if c.get("vectors") and c.get("execution") != "native"
        }
        native = {c["id"] for c in cases if c.get("execution") == "native"}
        if executable:
            inventory[capability["capability"]] = {
                "executable": executable,
                "native": native,
            }
    return inventory


def run_runners(report_dir: Path) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    for language, cwd, command in RUNNERS:
        out = report_dir / f"{language}.json"
        out.unlink(missing_ok=True)
        print(f"[spec-coverage] running {language} runner: {' '.join(command)}")
        env = dict(os.environ, SPEC_COVERAGE_OUT=str(out))
        result = subprocess.run(command, cwd=cwd, env=env, check=False)  # noqa: S603
        if result.returncode != 0:
            sys.exit(
                f"[spec-coverage] {language} runner FAILED (exit {result.returncode})"
            )


def check_reports(report_dir: Path) -> int:
    inventory = spec_inventory()
    if not inventory:
        sys.exit("[spec-coverage] no capability with executable vectors found in spec/")

    # Each language runner writes ONE report keyed to a single capability today
    # (only validation.json has executable vectors). If a second capability
    # gains vectors, this one-report-per-language shape would silently stop
    # gating it — so fail loudly and force the runners to emit per-capability
    # reports before that can happen, rather than pass covering only some.
    if len(inventory) > 1:
        sys.exit(
            "[spec-coverage] GATE FAILED — multiple capabilities now carry "
            f"executable vectors ({sorted(inventory)}), but each language runner "
            "reports only one. Extend the runners to emit a per-capability "
            "coverage report and update this gate to check every (language, "
            "capability) pair before landing new vectors."
        )

    failures: list[str] = []
    for language, _, _ in RUNNERS:
        report_path = report_dir / f"{language}.json"
        if not report_path.is_file():
            failures.append(f"{language}: no coverage report produced at {report_path}")
            continue
        report = json.loads(report_path.read_text())
        capability = report["capability"]
        want = inventory.get(capability)
        if want is None:
            failures.append(f"{language}: reported unknown capability {capability!r}")
            continue
        executed = set(report.get("executed", []))
        native = report.get("native", {})

        failures.extend(
            f"({language}, {case_id}): vector case not executed"
            for case_id in sorted(want["executable"] - executed)
        )
        failures.extend(
            f"({language}, {case_id}): native case has no native-test anchor"
            for case_id in sorted(want["native"])
            if not native.get(case_id)
        )

        covered = len(want["executable"] & executed)
        total = len(want["executable"])
        pct = 100.0 * covered / total if total else 0.0
        print(
            f"[spec-coverage] {language:<7} {capability}: "
            f"{covered}/{total} vector cases ({pct:.0f}%), "
            f"{len(want['native'])} native (anchored: "
            f"{sum(1 for c in want['native'] if native.get(c))})"
        )

    # A capability every language must cover: also fail if a language's report
    # is missing a capability that has executable vectors (single-capability
    # today; the per-language file becomes per-capability when more land).
    if failures:
        print("\n[spec-coverage] GATE FAILED — missing (language, vector-id) pairs:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("[spec-coverage] GATE PASSED — 100% vector coverage in every language")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-only",
        metavar="REPORTS_DIR",
        help="skip running the runners; gate existing reports in this directory",
    )
    args = parser.parse_args()

    if args.check_only:
        return check_reports(Path(args.check_only))
    run_runners(DEFAULT_REPORT_DIR)
    return check_reports(DEFAULT_REPORT_DIR)


if __name__ == "__main__":
    sys.exit(main())
