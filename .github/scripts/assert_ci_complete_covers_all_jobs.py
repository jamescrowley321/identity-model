#!/usr/bin/env python3
"""Assert the ci-complete merge gate actually aggregates every CI job.

``ci-complete`` is the one required status check that stands for the whole
matrix, and it stands for exactly the jobs named in three places that have to
agree: its ``needs:`` list, the ``RESULTS`` map it inspects, and the
``SKIP_ALLOWED`` map that says which skips are legitimate.

A job missing from any of them is invisible to the gate. Nothing about that is
noticeable by eye -- the workflow still runs the job, the job still reports its
own green check, and the aggregate check still passes. It simply stops being
able to block a merge. This script makes that drift a CI failure instead, so a
job added without wiring cannot silently become optional.

Exits non-zero with a specific message naming the offending jobs.
"""

from __future__ import annotations

import pathlib
import sys

import yaml

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "ci.yml"
GATE = "ci-complete"


def _env_block_keys(step: dict, name: str) -> set[str]:
    """Job names on the left of ``=`` in a newline-delimited env block."""
    raw = step.get("env", {}).get(name, "")
    return {
        line.split("=", 1)[0].strip()
        for line in raw.splitlines()
        if line.strip() and "=" in line
    }


def main() -> int:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    jobs = workflow["jobs"]

    if GATE not in jobs:
        print(f"error: {WORKFLOW} has no '{GATE}' job", file=sys.stderr)
        return 1

    gate = jobs[GATE]
    expected = set(jobs) - {GATE}
    needs = set(gate.get("needs", []))

    check_step = next(
        (s for s in gate["steps"] if "RESULTS" in s.get("env", {})),
        None,
    )
    if check_step is None:
        print(
            f"error: '{GATE}' has no step carrying a RESULTS env block",
            file=sys.stderr,
        )
        return 1

    results = _env_block_keys(check_step, "RESULTS")
    skip_allowed = _env_block_keys(check_step, "SKIP_ALLOWED")

    failures: list[str] = []

    for label, actual in (("needs:", needs), ("the RESULTS map", results)):
        missing = sorted(expected - actual)
        if missing:
            failures.append(
                f"{len(missing)} job(s) missing from {label} of '{GATE}', so "
                f"they cannot block a merge: {', '.join(missing)}"
            )
        extra = sorted(actual - expected)
        if extra:
            failures.append(
                f"{label} of '{GATE}' names {len(extra)} job(s) that do not "
                f"exist: {', '.join(extra)}"
            )

    # Every allow-listed skip must name a real job. A typo here silently
    # un-exempts a job that is meant to be skippable, or worse, exempts
    # nothing while reading as though it does.
    unknown = sorted(skip_allowed - expected)
    if unknown:
        failures.append(
            f"SKIP_ALLOWED of '{GATE}' names {len(unknown)} job(s) that do "
            f"not exist: {', '.join(unknown)}"
        )

    # A job with no `if:` can only be skipped by a skipped dependency, which is
    # always an anomaly -- exempting one would hide exactly what this gate is
    # for.
    unconditional = {
        name
        for name, job in jobs.items()
        if name != GATE and "if" not in job and not job.get("needs")
    }
    wrongly_exempt = sorted(skip_allowed & unconditional)
    if wrongly_exempt:
        failures.append(
            f"SKIP_ALLOWED of '{GATE}' exempts {len(wrongly_exempt)} job(s) "
            f"that have no `if:` and so can never legitimately skip: "
            f"{', '.join(wrongly_exempt)}"
        )

    # Conversely, every conditional job must say when its skip is legitimate.
    conditional = expected - unconditional
    unexplained = sorted(conditional - skip_allowed)
    if unexplained:
        failures.append(
            f"{len(unexplained)} conditional job(s) are absent from "
            f"SKIP_ALLOWED of '{GATE}', so a legitimate skip will fail the "
            f"gate: {', '.join(unexplained)}"
        )

    if failures:
        for line in failures:
            print(f"error: {line}", file=sys.stderr)
        return 1

    print(
        f"{GATE} aggregates all {len(expected)} jobs "
        f"({len(conditional)} conditional, {len(unconditional)} unconditional)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
