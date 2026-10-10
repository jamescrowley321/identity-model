"""Deterministic unit coverage for the capacity/breakpoint logic — TH-4.

These exercise the knee-detection math, the ramp ladder, the worker-sweep
derivation, and the report renderer as *pure functions* over constructed
results — no Locust, no booted RS — so they run in the normal unit suite and
pin the breakpoint semantics regardless of any measured load. The real ramp
(a booted RS driven to saturation) is proven in ``test_load_capacity.py``.
"""

from __future__ import annotations

import pytest

from .runner import (
    CapacityResult,
    CapacityStep,
    LoadResult,
    _breach_reasons,
    render_capacity_report,
    write_capacity_report,
)
from .scenarios import (
    SCENARIOS_BY_ID,
    Profile,
    RampSpec,
    Scenario,
    profile_scenarios,
    worker_scaling_scenarios,
)


pytestmark = pytest.mark.unit


def _result(
    *, rps: float, p99_ms: float = 5.0, failures: int = 0, s5xx: int = 0
) -> LoadResult:
    """A LoadResult carrying just the fields knee detection reads."""
    return LoadResult(
        scenario_id="C1",
        title="t",
        num_requests=1000,
        num_failures=failures,
        rps=rps,
        p50_ms=1.0,
        p95_ms=2.0,
        p99_ms=p99_ms,
        p999_ms=9.0,
        server_errors=s5xx,
        steady_state=True,
    )


# --- ladder ---------------------------------------------------------------


def test_targets_are_inclusive_of_stop():
    assert RampSpec(start_rps=1000, stop_rps=4000, step_rps=1000).targets() == (
        1000,
        2000,
        3000,
        4000,
    )


def test_targets_single_rung_when_start_equals_stop():
    assert RampSpec(start_rps=500, stop_rps=500, step_rps=500).targets() == (500,)


# --- breach detection -----------------------------------------------------


def test_no_breach_when_goodput_tracks_offered():
    ramp = RampSpec(start_rps=1000, stop_rps=8000, step_rps=1000)
    # 900 >= 0.85 * 1000; no ceilings tripped.
    assert _breach_reasons(_result(rps=900.0), 1000, ramp) == []


def test_goodput_plateau_breaches():
    ramp = RampSpec(start_rps=1000, stop_rps=8000, step_rps=1000)
    reasons = _breach_reasons(_result(rps=1100.0), 2000, ramp)  # 1100 < 0.85*2000
    assert len(reasons) == 1
    assert "goodput plateau" in reasons[0]


def test_p99_ceiling_breaches_only_when_set():
    offered = 1000
    hot = _result(rps=1000.0, p99_ms=120.0)
    assert _breach_reasons(hot, offered, RampSpec(1000, 8000, 1000)) == []
    reasons = _breach_reasons(hot, offered, RampSpec(1000, 8000, 1000, max_p99_ms=50.0))
    assert reasons == ["p99 120ms > 50ms"]


def test_error_budget_breaches():
    ramp = RampSpec(1000, 8000, 1000, max_error_rate=0.01)
    # 30/1000 = 0.03 > 0.01
    reasons = _breach_reasons(_result(rps=1000.0, failures=30), 1000, ramp)
    assert len(reasons) == 1
    assert "error-rate" in reasons[0]


def test_server_error_always_breaches_and_reasons_accumulate():
    ramp = RampSpec(1000, 8000, 1000, max_p99_ms=50.0, max_error_rate=0.01)
    reasons = _breach_reasons(
        _result(rps=100.0, p99_ms=200.0, failures=50, s5xx=3), 2000, ramp
    )
    # 5xx + plateau + p99 + error-rate all fire.
    assert len(reasons) == 4
    assert any("5xx" in r or "server error" in r for r in reasons)


# --- worker sweep ---------------------------------------------------------


def test_worker_sweep_derives_variants_per_count():
    base = SCENARIOS_BY_ID["C1"]
    variants = worker_scaling_scenarios(base, (1, 2, 4))
    assert [v.id for v in variants] == ["C1-w1", "C1-w2", "C1-w4"]
    assert [v.workers for v in variants] == [1, 2, 4]
    # The ramp itself is carried through unchanged.
    assert all(v.ramp == base.ramp for v in variants)


def test_worker_sweep_rejects_fixed_hold_scenario():
    fixed = SCENARIOS_BY_ID["S1"]
    assert fixed.ramp is None
    with pytest.raises(ValueError, match="ramp"):
        worker_scaling_scenarios(fixed, (1, 2))


# --- catalogue wiring -----------------------------------------------------


def test_capacity_profile_holds_only_ramp_scenarios():
    caps = profile_scenarios(Profile.CAPACITY)
    assert {s.id for s in caps} == {"C1", "C2"}
    assert all(s.ramp is not None for s in caps)


def test_fixed_hold_scenarios_have_no_ramp():
    for pid in (Profile.CI_SHORT, Profile.NIGHTLY, Profile.DIAGNOSTIC):
        assert all(s.ramp is None for s in profile_scenarios(pid))


# --- report ---------------------------------------------------------------


def _capacity_result(*, breaks_at: int | None) -> CapacityResult:
    steps = [
        CapacityStep(1000, 999.0, 5.0, 0.0, 0, breached=False),
        CapacityStep(
            2000,
            1100.0,
            9.0,
            0.0,
            0,
            breached=breaks_at is not None,
            reasons=["goodput plateau: 1100 rps < 1700 (85% of 2000 offered)"]
            if breaks_at is not None
            else [],
        ),
    ]
    return CapacityResult(
        scenario_id="C1",
        title="warm ramp",
        workers=1,
        steps=steps,
        max_sustainable_rps=999.0,
        knee_target_rps=1000,
        knee_p99_ms=5.0,
        breaking_target_rps=breaks_at,
        breach_reasons=steps[-1].reasons,
    )


def test_report_shows_knee_when_breakpoint_found():
    report = render_capacity_report([_capacity_result(breaks_at=2000)])
    assert "KNEE" in report
    assert "breaks at 2000 rps" in report
    assert "BREACH" in report


def test_report_flags_missing_breakpoint():
    report = render_capacity_report([_capacity_result(breaks_at=None)])
    assert "NO breakpoint within ladder" in report
    assert "raise stop_rps" in report


def test_found_breakpoint_property():
    assert _capacity_result(breaks_at=2000).found_breakpoint is True
    assert _capacity_result(breaks_at=None).found_breakpoint is False


def test_write_capacity_report_writes_rendered_report(tmp_path):
    """The artifact writer persists exactly what the renderer produces."""
    results = [_capacity_result(breaks_at=2000)]
    out = write_capacity_report(results, tmp_path / "capacity-report.txt")
    written = out.read_text(encoding="utf-8")
    assert written == render_capacity_report(results)
    assert "KNEE" in written
    assert "C1" in written


def test_write_capacity_report_creates_parent_dirs(tmp_path):
    """A nested artifact path is created rather than raising FileNotFoundError."""
    out = write_capacity_report(
        [_capacity_result(breaks_at=2000)], tmp_path / "nested" / "dir" / "report.txt"
    )
    assert out.is_file()
    assert out.parent == tmp_path / "nested" / "dir"


def test_capacity_scenarios_are_well_formed():
    for s in profile_scenarios(Profile.CAPACITY):
        assert isinstance(s, Scenario)
        assert s.ramp is not None
        assert s.ramp.start_rps < s.ramp.stop_rps
        assert s.ramp.rps_per_user > 0
        assert s.ramp.min_users > 0
        assert 0 < s.ramp.sustain_ratio <= 1.0


def test_users_scale_with_rate_above_the_floor():
    ramp = RampSpec(start_rps=500, stop_rps=8000, step_rps=500, rps_per_user=40.0)
    assert ramp.users_for(40) == ramp.min_users  # tiny rate clamps to the floor
    assert ramp.users_for(2000) == 50  # 2000 / 40
    # More offered load => a larger paced pool (never fewer users).
    assert ramp.users_for(4000) > ramp.users_for(2000)
