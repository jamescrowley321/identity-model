"""Real-Locust capacity/breakpoint proof for the load suite — TH-4.

This is the capacity ``test``-phase DoD: a REAL open-model ramp (Locust paced
via ``constant_throughput``) driving the booted RS (real uvicorn subprocess,
real HTTP) up the arrival-rate ladder until goodput stops tracking offered load
— the knee. A green fixed-load run is not proof of a capacity limit; this drives
load to saturation and records where the single worker falls over.

The knee is a *co-located, directional* ceiling (generator + mock OP + RS share
the box, per the design's accepted trade-off) plus a regression signal — NOT the
RS's absolute isolated limit, which needs a deployed target. The assertions here
pin the *mechanism* (goodput plateaus **when** a knee is found, zero 5xx under
saturation, monotonic offered rate, the curve renders), never a machine-specific
RPS number — and never that a breakpoint *must* exist within the ladder. On this
co-located config a fast runner can sustain the whole ladder (clean exhaustion)
and a contended one can plateau at rung 1; both are valid, reported outcomes (the
knee is Track-B directional data per ``sprint-change-proposal-2026-08-19.md``, not
a shared-CI pass/fail), so requiring a breakpoint would false-fail on runner noise.

Self-contained and skips cleanly without the load group (see the CI-short suite
for why locust must not be imported in-process). Run via
``make test-harness-load-capacity`` under ``uv run --group load --all-packages``.
"""

from __future__ import annotations

import importlib.util
import os

import pytest


if importlib.util.find_spec("locust") is None:
    pytest.skip("locust (load group) not installed", allow_module_level=True)
pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

from .runner import (
    render_capacity_report,
    run_capacity_profile,
    write_capacity_report,
)
from .scenarios import Profile, profile_scenarios


pytestmark = pytest.mark.integration

_CAPACITY_IDS = [s.id for s in profile_scenarios(Profile.CAPACITY)]

# Where the fixture writes the rendered ramp curve + knee so CI can upload it as
# an artifact. Defaults to the repo/cwd so a local run also leaves a readable
# report (gitignored); the nightly job overrides it to the artifact path.
_REPORT_PATH = os.environ.get("HARNESS_CAPACITY_REPORT", "capacity-report.txt")


@pytest.fixture(scope="module")
def capacity_results():
    """Run the CAPACITY profile once; share the per-scenario ramp results.

    Each ramp boots its own RS and stops at the first rung that breaches SLO, so
    a saturating single worker knees within a few rungs — bounded run time. The
    rendered report is written to ``_REPORT_PATH`` before the assertions run, so
    the downloadable artifact exists even when a later assertion fails.
    """
    results = {r.scenario_id: r for r in run_capacity_profile(Profile.CAPACITY)}
    write_capacity_report(list(results.values()), _REPORT_PATH)
    return results


def test_every_capacity_scenario_ran(capacity_results):
    """The profile executed exactly the capacity catalogue (C1, C2)."""
    assert set(capacity_results) == set(_CAPACITY_IDS)


def test_each_ramp_produced_a_consistent_curve(capacity_results):
    """Every ramp drove real rungs and produced an internally consistent result.

    A breakpoint is *reported when found*, not *required*: a fast, uncontended
    runner can sustain the whole 500→8000 ladder (clean exhaustion) and a slow,
    contended one can plateau at rung 1 — both are valid outcomes on the
    co-located config, where the knee is directional Track-B data, not a pass/fail
    (see ``sprint-change-proposal-2026-08-19.md``). The invariant is that the
    result is self-consistent, not that a machine-dependent knee exists.
    """
    for scenario_id, r in capacity_results.items():
        assert r.steps, f"{scenario_id}: ramp drove no rungs"
        # Machine-independent RS-liveness floor: the RS must have served real
        # goodput on at least one rung (achieved_rps is measured, not bookkeeping,
        # so this is not tautological). It catches a totally broken RS — zero
        # throughput, every request hanging — WITHOUT re-introducing an absolute
        # rps gate: a sub-threshold *absolute* throughput regression is
        # indistinguishable from a merely-contended runner here and is deferred to
        # Track C (isolated runner, sprint-change-proposal-2026-08-19), not gated.
        assert any(s.achieved_rps > 0 for s in r.steps), (
            f"{scenario_id}: RS served zero goodput on every rung — dead RS.\n"
            f"{render_capacity_report([r])}"
        )
        if r.found_breakpoint:
            assert r.breaking_target_rps is not None
            # Every rung before the breaking one sustained, so the recorded knee
            # target sits strictly below the breaking target (0 if it broke at
            # rung 1 — a valid, if contended, outcome; not asserted non-zero).
            assert r.knee_target_rps < r.breaking_target_rps
        else:
            # Clean exhaustion: no rung breached, so every step sustained and the
            # top sustained rung is a real (non-zero) goodput reading.
            assert all(not s.breached for s in r.steps), render_capacity_report([r])
            assert r.max_sustainable_rps > 0, (
                f"{scenario_id}: exhausted the ladder but recorded no sustained "
                f"goodput.\n{render_capacity_report([r])}"
            )


def test_knee_is_a_goodput_plateau_when_found(capacity_results):
    """When a ramp DID find a breakpoint, the breaking rung is a real saturation:
    achieved goodput fell below the offered rate, and a breach reason was recorded
    (not a spurious stop). Ramps that exhaust the ladder clean have no breaking
    rung to characterise and are skipped — their sustained-rung invariant is
    covered by :func:`test_sustained_rungs_tracked_the_offered_rate`."""
    for scenario_id, r in capacity_results.items():
        if not r.found_breakpoint:
            continue
        breaking = r.steps[-1]
        assert breaking.breached
        assert breaking.reasons
        assert breaking.achieved_rps < r.breaking_target_rps, (
            f"{scenario_id}: breaking rung {r.breaking_target_rps} achieved "
            f"{breaking.achieved_rps:.0f} rps — expected goodput below offered"
        )


def test_no_server_errors_under_saturation(capacity_results):
    """Even driven past its knee the RS must never 5xx — it rejects/serves
    cleanly under overload, it does not fault (design §5 correctness invariant)."""
    for scenario_id, r in capacity_results.items():
        offenders = [s for s in r.steps if s.server_errors]
        assert not offenders, (
            f"{scenario_id}: 5xx under load at rungs "
            f"{[(s.target_rps, s.server_errors) for s in offenders]}"
        )


def test_offered_rate_is_monotonic(capacity_results):
    """The ladder offered a strictly increasing arrival rate."""
    for scenario_id, r in capacity_results.items():
        targets = [s.target_rps for s in r.steps]
        assert targets == sorted(set(targets)), f"{scenario_id}: {targets}"


def test_sustained_rungs_tracked_the_offered_rate(capacity_results):
    """Every non-breaching rung delivered >= sustain_ratio of what it offered —
    the invariant that makes the last sustained rung a trustworthy knee."""
    ramps = {
        s.id: s.ramp for s in profile_scenarios(Profile.CAPACITY) if s.ramp is not None
    }
    for scenario_id, r in capacity_results.items():
        ratio = ramps[scenario_id].sustain_ratio
        for step in r.steps:
            if not step.breached:
                assert step.achieved_rps >= ratio * step.target_rps


def test_capacity_report_renders_each_scenario_outcome(capacity_results):
    """The artifact report names each scenario and renders its terminal outcome —
    a ``KNEE`` line when a breakpoint was found, or the explicit ``NO breakpoint
    within ladder`` line when the ramp exhausted the ladder clean."""
    for scenario_id, r in capacity_results.items():
        one = render_capacity_report([r])
        assert scenario_id in one
        terminal = "KNEE" if r.found_breakpoint else "NO breakpoint"
        assert terminal in one, one
