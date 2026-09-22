#!/usr/bin/env python3
"""Cross-language /spec vector-coverage gate (CONS-1.5, AC-CONS-1.5.2/1.5.3).

Runs each language's thin conformance runner (Python, Go, Rust) against the
shared ``spec/vectors`` vectors with ``SPEC_COVERAGE_OUT`` set, then
verifies every language executed every vector of every executable case — not
merely that the case id appeared. Any missing (language, case) pair, and any
case that ran fewer vectors than the spec carries, fails the gate by name.

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

A capability can opt out while its runners are being built, by name, in the
``OPTED_OUT`` set below. It is deliberately NOT a marker in the vector file:
the gate reads those files, so a file that could exempt itself would let any
capability leave enforcement by editing the data the gate is reading — the
no-runner check iterates the same inventory the marker empties, so it cannot
see the exclusion either, and the gate still prints GATE PASSED. Dropping a
capability has to be a diff to this file. Opting out is a temporary state:
it means "not yet gated", never "not required".

The absence of a ``vectors`` array was exactly the self-exemption that rule
forbids. A capability whose cases carry no executable vectors produced an
empty inventory entry and was skipped — silently, and by editing the data the
gate reads. Ten of the twelve capabilities in ``spec/`` sit in that state (95
of 119 cases), so the gate covered two capabilities while reporting GATE
PASSED for all of them. ``UNVECTORED`` now names them here, in the gate, and
a capability that carries no vectors and is not named fails closed.

What this gate does NOT prove: that the declaration is complete. The expected
per-case vector counts are read from ``spec/vectors/*.json``, and the runners
execute those same files, so deleting a vector from a case lowers both sides
and the gate still passes. That is the residual of the self-exemption family
above, and it is not closable here — a gate cannot audit its own baseline.
What stops it is that ``spec/vectors/*.json`` is NORMATIVE and its diffs are
reviewed as spec changes, not as test edits: removing a vector is a visible
change to a normative file, and has to be argued for there. Read GATE PASSED
as "every vector the spec declares was executed by every language", never as
"the spec declares enough vectors".
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

#: Capabilities temporarily outside the cross-language gate while their runners
#: are built. Listed here — in the gate — and never in a vector file, so removing
#: a capability from enforcement is a change to the enforcement code rather than
#: to the data that code reads. Every entry is a debt to be paid, not a setting.
OPTED_OUT: frozenset[str] = frozenset()

#: Capabilities whose vector files are prose contracts: cases with ids and
#: descriptions, but no executable ``vectors`` array for a runner to execute.
#:
#: These were invisible. `spec_inventory` kept only capabilities with
#: executable cases, so one with none produced no entry, the no-runner check
#: iterated that same empty inventory, and the gate printed GATE PASSED having
#: inspected nothing — the precise failure the OPTED_OUT rule above exists to
#: prevent, arrived at through data rather than a marker.
#:
#: Naming them here does not gate them; it stops the gap being invisible, and
#: makes closing one a deletion from this dict. The value is the number of
#: cases currently stranded, so the cost is legible in review.
#:
#: Like OPTED_OUT, every entry is a debt. Two checks keep it honest: a
#: capability missing from both this dict and OPTED_OUT fails the gate, and an
#: entry here that has since gained executable vectors fails it too, so the
#: list cannot rot into a permanent exemption.
UNVECTORED: dict[str, int] = {
    "authorization-code": 6,
    "client-credentials": 6,
    "configuration": 33,
    "discovery": 10,
    "dpop": 8,
    "introspection": 6,
    "jwks": 7,
    "revocation": 5,
    "token-exchange": 6,
    "userinfo": 8,
}

#: Languages that must cover every gated capability.
LANGUAGES = ["python", "go", "rust"]


def report_name(language: str, capability: str) -> str:
    """Report filename for one (language, capability) pair."""
    return f"{language}.{capability}.json"


def _carries(want: dict) -> str:
    """What a capability has that needs a runner, for the no-runner message.

    A native-only capability carries no executable vectors, so saying it does
    sends the reader looking for a `vectors` array that is not there.
    """
    parts = []
    if want["executable"]:
        parts.append(f"{sum(want['executable'].values())} executable vectors")
    if want["native"]:
        parts.append(f"{len(want['native'])} native cases")
    return " and ".join(parts)


def spec_inventory() -> tuple[dict[str, dict[str, set[str]]], set[str]]:
    """Executable + native case ids per capability that carries vectors."""
    inventory: dict[str, dict[str, set[str]]] = {}
    unvectored: set[str] = set()
    for path in sorted(SPEC_DIR.glob("*.json")):
        try:
            capability = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            sys.exit(f"[spec-coverage] {path} is not valid JSON: {exc}")
        name = capability["capability"]
        # The opt-out lives in OPTED_OUT, in this file. A vector file cannot
        # exempt itself: see the module docstring.
        if name in OPTED_OUT:
            continue
        cases = capability.get("tests", [])
        # Per case, how many vectors it carries — not merely that it has some.
        # The gate used to verify case ids only, so a case could drop four of
        # its five vectors and every language still reported it executed.
        executable = {
            c["id"]: len(c["vectors"])
            for c in cases
            if c.get("vectors") and c.get("execution") != "native"
        }
        native = {c["id"] for c in cases if c.get("execution") == "native"}
        # `or native`: a capability whose cases are ALL `execution: "native"`
        # has nothing in `executable`, but it is not unvectored — it carries
        # native cases whose per-language anchors this gate exists to check.
        # Keyed on `executable` alone it fell through to `unvectored`, the
        # `native` set was discarded, and the fix a contributor would reach for
        # is to name it in UNVECTORED to make the gate pass — which files it
        # under "carries no executable vectors" and drops its anchor checks for
        # good. Same shape as the missing-`vectors` exemption above: a
        # capability leaving the gate by way of the data the gate reads.
        if executable or native:
            inventory[name] = {"executable": executable, "native": native}
        else:
            # Recorded rather than dropped. Skipping silently here is what let
            # ten capabilities leave the gate without a diff to this file.
            unvectored.add(name)
    return inventory, unvectored


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
    inventory, unvectored = spec_inventory()
    if not inventory:
        sys.exit("[spec-coverage] no capability with executable vectors found in spec/")

    # A capability with no executable vectors used to vanish here. Both
    # directions are checked so the exemption list cannot rot: an unnamed
    # capability cannot leave the gate by dropping its vectors, and a named one
    # cannot stay exempt after gaining them.
    undeclared = sorted(unvectored - set(UNVECTORED) - OPTED_OUT)
    stale = sorted(set(UNVECTORED) & set(inventory))
    vanished = sorted(set(UNVECTORED) - unvectored - set(inventory))
    if undeclared or stale or vanished:
        print("\n[spec-coverage] GATE FAILED — exemption list out of date:")
        for name in undeclared:
            print(
                f"  - {name}: carries no executable `vectors`, so nothing gates "
                f"it, and it is named in neither UNVECTORED nor OPTED_OUT. Add "
                f"vectors, or declare the gap in tools/spec_coverage_gate.py."
            )
        for name in stale:
            print(
                f"  - {name}: now carries executable vectors but is still listed "
                f"in UNVECTORED. Remove the entry so the gate enforces it."
            )
        for name in vanished:
            print(
                f"  - {name}: listed in UNVECTORED but no such capability exists "
                f"in spec/. Remove the stale entry."
            )
        return 1

    if UNVECTORED:
        stranded = sum(UNVECTORED.values())
        print(
            f"[spec-coverage] {len(UNVECTORED)} capabilities carry no executable "
            f"vectors and are NOT gated ({stranded} cases): "
            f"{', '.join(sorted(UNVECTORED))}"
        )

    # Fail closed on a capability nobody runs. A vector file that carries
    # executable cases but has no runner entry for some language is worse than
    # no vector file at all: the spec claims cross-language coverage the gate
    # never checks. This replaces the older single-capability guard, which
    # bailed out entirely as soon as a second capability gained vectors.
    configured = {(language, capability) for language, capability, _, _ in RUNNERS}
    missing_runners = [
        f"({language}, {capability}): capability carries "
        f"{_carries(inventory[capability])} but no runner is configured in "
        f"RUNNERS"
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
        # A runner that half-wrote its report (killed mid-write, out of disk)
        # leaves malformed JSON behind. Report that as a named gate failure
        # rather than letting json.loads raise: an uncaught JSONDecodeError
        # aborts the whole check, so one bad report would hide every other
        # language's real coverage gap behind a traceback.
        try:
            report = json.loads(report_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(
                f"({language}, {capability}): coverage report {report_path} is "
                f"unreadable or malformed — {exc}"
            )
            continue
        if not isinstance(report, dict) or "capability" not in report:
            failures.append(
                f"({language}, {capability}): coverage report {report_path} is "
                f"not a report object with a 'capability' key"
            )
            continue

        reported = report["capability"]
        if reported != capability:
            failures.append(
                f"({language}, {capability}): report declares capability "
                f"{reported!r} — runner and gate disagree"
            )
            continue

        executed = set(report.get("executed", []))
        native = report.get("native", {})
        # Per-case vector counts. A runner that reports only case ids cannot
        # prove it ran every vector in a case, so its absence is a gate failure
        # rather than something to infer from `executed`.
        executed_vectors = report.get("executed_vectors")
        if not isinstance(executed_vectors, dict):
            failures.append(
                f"({language}, {capability}): report has no 'executed_vectors' "
                f"map of case id to the number of vectors that ran"
            )
            continue
        # The counts are arithmetic below (min(), sum()), so a non-integer count
        # raises TypeError there and aborts the whole check — which would hide
        # every later language's real gap behind a traceback, the exact failure
        # mode the malformed-report guard above exists to prevent. Name it here
        # instead. bool is an int in Python; a True vector count is nonsense, so
        # it is rejected rather than silently counted as 1.
        bad_counts = sorted(
            case_id
            for case_id, ran in executed_vectors.items()
            if isinstance(ran, bool) or not isinstance(ran, int)
        )
        if bad_counts:
            failures.append(
                f"({language}, {capability}): 'executed_vectors' has "
                f"non-integer vector counts for {', '.join(bad_counts)}"
            )
            continue

        failures.extend(
            f"({language}, {capability}, {case_id}): vector case not executed"
            for case_id in sorted(set(want["executable"]) - executed)
        )
        for case_id, expected_vectors in sorted(want["executable"].items()):
            if case_id not in executed:
                continue  # already reported as not executed at all
            ran = executed_vectors.get(case_id)
            if ran != expected_vectors:
                failures.append(
                    f"({language}, {capability}, {case_id}): ran {ran} of "
                    f"{expected_vectors} vectors"
                )
        failures.extend(
            f"({language}, {capability}, {case_id}): native case has no "
            f"native-test anchor"
            for case_id in sorted(want["native"])
            if not native.get(case_id)
        )

        covered = len(set(want["executable"]) & executed)
        total = len(want["executable"])
        vectors_ran = sum(
            min(executed_vectors.get(c, 0), n) for c, n in want["executable"].items()
        )
        vectors_total = sum(want["executable"].values())
        pct = 100.0 * vectors_ran / vectors_total if vectors_total else 0.0
        print(
            f"[spec-coverage] {language:<7} {capability:<12} "
            f"{covered}/{total} cases, {vectors_ran}/{vectors_total} vectors "
            f"({pct:.0f}%), {len(want['native'])} native (anchored: "
            f"{sum(1 for c in want['native'] if native.get(c))})"
        )

    if failures:
        print(
            "\n[spec-coverage] GATE FAILED — missing (language, capability, vector-id):"
        )
        for failure in failures:
            print(f"  - {failure}")
        return 1
    gated = ", ".join(
        f"{name} ({n} vector{'' if n == 1 else 's'})"
        for name, n in (
            (name, sum(want["executable"].values()))
            for name, want in sorted(inventory.items())
        )
    )
    print(
        f"[spec-coverage] GATE PASSED — every vector executed in every language "
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
