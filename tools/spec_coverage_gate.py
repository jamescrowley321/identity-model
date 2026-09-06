#!/usr/bin/env python3
"""Cross-language /spec vector-coverage gate (CONS-1.5, AC-CONS-1.5.2/1.5.3).

Runs each language's thin conformance runner (Python, Go, Rust) against the
shared ``spec/vectors`` vectors with ``SPEC_COVERAGE_OUT`` set, then
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

Reports are per **(language, capability)** pair — ``<language>.<capability>.json``
— so a capability is gated independently in each language. ``RUNNERS`` lists one
entry per pair, and any capability with executable vectors that lacks an entry
for some language fails the gate: a vector file nobody runs is worse than none,
because the spec then claims coverage that is never checked.

A capability can opt out while its runners are being built by setting
``cross_language_coverage_gate: "pending"`` in its vector file. That is a
temporary state — the marker means "not yet gated", never "not required".
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = REPO_ROOT / "spec" / "vectors"
DEFAULT_REPORT_DIR = REPO_ROOT / "build" / "spec-coverage"

# (language, capability, working dir, command) — each entry runs ONE language's
# runner for ONE capability and writes its report to SPEC_COVERAGE_OUT. A
# capability that carries executable vectors MUST have an entry here for every
# language, or the gate fails closed (see check_reports): a vector file nobody
# runs is worse than no vector file, because it looks covered.
RUNNERS: list[tuple[str, str, Path, list[str]]] = [
    (
        "python",
        "validation",
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
        "python",
        "id-token",
        REPO_ROOT / "py",
        [
            "uv",
            "run",
            "pytest",
            "src/tests/unit/test_id_token_conformance.py",
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
        "validation",
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
        "go",
        "id-token",
        REPO_ROOT / "go",
        [
            "go",
            "test",
            "./internal/conformance/",
            "-run",
            "TestIDTokenConformance",
            "-count=1",
        ],
    ),
    (
        "rust",
        "validation",
        REPO_ROOT / "rust",
        ["cargo", "test", "--test", "spec_conformance"],
    ),
    (
        "rust",
        "id-token",
        REPO_ROOT / "rust",
        ["cargo", "test", "--test", "spec_conformance_id_token"],
    ),
]

#: Languages that must cover every gated capability.
LANGUAGES = ["python", "go", "rust"]


def report_name(language: str, capability: str) -> str:
    """Report filename for one (language, capability) pair."""
    return f"{language}.{capability}.json"


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
    for language, capability, cwd, command in RUNNERS:
        out = report_dir / report_name(language, capability)
        out.unlink(missing_ok=True)
        print(
            f"[spec-coverage] running {language}/{capability} runner: "
            f"{' '.join(command)}"
        )
        env = dict(os.environ, SPEC_COVERAGE_OUT=str(out))
        result = subprocess.run(command, cwd=cwd, env=env, check=False)  # noqa: S603
        if result.returncode != 0:
            sys.exit(
                f"[spec-coverage] {language}/{capability} runner FAILED "
                f"(exit {result.returncode})"
            )


def check_reports(report_dir: Path) -> int:
    inventory = spec_inventory()
    if not inventory:
        sys.exit("[spec-coverage] no capability with executable vectors found in spec/")

    # Fail closed on a capability nobody runs. A vector file that carries
    # executable cases but has no runner entry for some language is worse than
    # no vector file at all: the spec claims cross-language coverage the gate
    # never checks. This replaces the older single-capability guard, which
    # bailed out entirely as soon as a second capability gained vectors.
    configured = {(language, capability) for language, capability, _, _ in RUNNERS}
    missing_runners = [
        f"({language}, {capability}): capability has executable vectors but no "
        f"runner is configured in RUNNERS"
        for capability in sorted(inventory)
        for language in LANGUAGES
        if (language, capability) not in configured
    ]
    if missing_runners:
        print("\n[spec-coverage] GATE FAILED — capabilities with no runner:")
        for line in missing_runners:
            print(f"  - {line}")
        return 1

    failures: list[str] = []
    for language, capability, _, _ in RUNNERS:
        want = inventory.get(capability)
        if want is None:
            # Runner configured for a capability that is opted out ("pending")
            # or carries no executable vectors: nothing to gate, and not an
            # error — the runner still ran, its own suite asserts its coverage.
            continue

        report_path = report_dir / report_name(language, capability)
        if not report_path.is_file():
            failures.append(
                f"({language}, {capability}): no coverage report produced at "
                f"{report_path}"
            )
            continue
        report = json.loads(report_path.read_text())
        reported = report["capability"]
        if reported != capability:
            failures.append(
                f"({language}, {capability}): report declares capability "
                f"{reported!r} — runner and gate disagree"
            )
            continue

        executed = set(report.get("executed", []))
        native = report.get("native", {})

        failures.extend(
            f"({language}, {capability}, {case_id}): vector case not executed"
            for case_id in sorted(want["executable"] - executed)
        )
        failures.extend(
            f"({language}, {capability}, {case_id}): native case has no "
            f"native-test anchor"
            for case_id in sorted(want["native"])
            if not native.get(case_id)
        )

        covered = len(want["executable"] & executed)
        total = len(want["executable"])
        pct = 100.0 * covered / total if total else 0.0
        print(
            f"[spec-coverage] {language:<7} {capability:<12} "
            f"{covered}/{total} vector cases ({pct:.0f}%), "
            f"{len(want['native'])} native (anchored: "
            f"{sum(1 for c in want['native'] if native.get(c))})"
        )

    if failures:
        print(
            "\n[spec-coverage] GATE FAILED — missing (language, capability, vector-id):"
        )
        for failure in failures:
            print(f"  - {failure}")
        return 1
    gated = ", ".join(sorted(inventory))
    print(
        f"[spec-coverage] GATE PASSED — 100% vector coverage in every language "
        f"for: {gated}"
    )
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
