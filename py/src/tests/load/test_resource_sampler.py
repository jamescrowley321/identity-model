"""Deterministic unit coverage for the soak RSS/FD sampler — T313 (epic #462).

Pure-logic tests over the sampler: the summarize math (start/max/end, dead-sample
filtering), the :class:`ResourceSample` leak-signal properties, live sampling of
this very process, and the not-sampled (dead-pid) path. No booted RS and no Locust
— the real soak sampling is exercised in ``test_load_nightly.py``. Marked ``unit``
so it runs in the coverage-gated suite (psutil is a ``dev`` dependency).
"""

from __future__ import annotations

import os

import pytest

from .resource_sampler import (
    ResourceSample,
    ResourceSampler,
    sample_process_tree,
)
from .runner import (
    LoadResult,
    _maybe_sampler,
    render_soak_report,
    write_soak_report,
)


pytestmark = pytest.mark.unit

_MB = 1024 * 1024


def test_resource_sample_growth_and_sampled_properties():
    """Growth deltas and ``sampled`` are derived from the recorded extremes."""
    sample = ResourceSample(
        rss_start_mb=100.0,
        rss_max_mb=175.0,
        rss_end_mb=140.0,
        fd_start=20,
        fd_max=27,
        fd_end=24,
        num_samples=6,
    )
    assert sample.rss_growth_mb == pytest.approx(75.0)
    assert sample.fd_growth == 7
    assert sample.sampled is True


def test_resource_sample_zero_samples_is_not_sampled():
    """A window that captured nothing reports ``sampled == False`` (no data)."""
    assert ResourceSample(0.0, 0.0, 0.0, 0, 0, 0, 0).sampled is False


def test_summarize_computes_start_max_end_and_drops_dead_samples():
    """Summarize uses the first/peak/last *live* readings; dead (rss==0) drop out.

    The leading and trailing ``(0, 0)`` readings (the tree not yet up / already
    torn down) must not become the start/end, or a real leak would be masked by a
    zero baseline.
    """
    sampler = ResourceSampler(pid=1234)
    sampler._samples = [
        (0, 0),  # tree not observed yet — must be filtered
        (100 * _MB, 30),
        (180 * _MB, 42),  # peak
        (150 * _MB, 38),
        (0, 0),  # torn down — must be filtered
    ]
    result = sampler._summarize()
    assert result.num_samples == 3
    assert result.rss_start_mb == pytest.approx(100.0)
    assert result.rss_max_mb == pytest.approx(180.0)
    assert result.rss_end_mb == pytest.approx(150.0)
    assert result.fd_start == 30
    assert result.fd_max == 42
    assert result.fd_end == 38
    assert result.rss_growth_mb == pytest.approx(80.0)
    assert result.fd_growth == 12


def test_summarize_all_dead_yields_empty_unsampled():
    """Every reading dead => the empty, un-sampled result (not a fake zero trend)."""
    sampler = ResourceSampler(pid=1234)
    sampler._samples = [(0, 0), (0, 0)]
    assert sampler._summarize().sampled is False


def test_sample_process_tree_live_process_reports_memory():
    """Sampling this test process's tree yields real RSS (and non-negative FDs)."""
    rss, fds = sample_process_tree(os.getpid())
    assert rss > 0
    assert fds >= 0


def test_sample_process_tree_dead_pid_is_zero():
    """A pid with no process yields ``(0, 0)`` rather than raising."""
    # PIDs are bounded by /proc/sys/kernel/pid_max; this one is above any real pid.
    assert sample_process_tree(2**31 - 1) == (0, 0)


def test_sampler_context_manager_captures_live_process():
    """The context manager samples the running process and reports a trend."""
    with ResourceSampler(os.getpid(), interval=0.02) as sampler:
        _ = [i * i for i in range(200_000)]
    result = sampler.result
    assert result.sampled is True
    assert result.num_samples >= 1
    assert result.rss_max_mb > 0
    assert result.rss_growth_mb >= 0


def test_sampler_context_manager_dead_pid_is_unsampled():
    """A dead pid over the whole window produces the un-sampled empty result."""
    with ResourceSampler(2**31 - 1, interval=0.01) as sampler:
        pass
    assert sampler.result.sampled is False


def test_maybe_sampler_none_pid_yields_none():
    """The runner's opt-in helper is a no-op when no RS pid is supplied."""
    with _maybe_sampler(None) as sampler:
        assert sampler is None


def test_maybe_sampler_with_pid_yields_live_sampler():
    """A pid produces a live sampler whose result is populated on exit."""
    with _maybe_sampler(os.getpid()) as sampler:
        assert isinstance(sampler, ResourceSampler)
    assert sampler.result.sampled is True


def _load_result(scenario_id: str, resources: ResourceSample | None) -> LoadResult:
    """A minimal LoadResult carrying the fields the soak report reads."""
    return LoadResult(
        scenario_id=scenario_id,
        title=f"{scenario_id} soak",
        num_requests=100,
        num_failures=0,
        rps=100.0,
        p50_ms=1.0,
        p95_ms=2.0,
        p99_ms=3.0,
        p999_ms=4.0,
        server_errors=0,
        steady_state=True,
        resources=resources,
    )


def test_render_soak_report_shows_rss_fd_numbers_and_growth():
    """A sampled scenario's RSS/FD extremes and growth appear in the report."""
    sample = ResourceSample(
        rss_start_mb=120.0,
        rss_max_mb=155.0,
        rss_end_mb=140.0,
        fd_start=30,
        fd_max=41,
        fd_end=36,
        num_samples=8,
    )
    report = render_soak_report([_load_result("S7", sample)])
    assert "S7" in report
    assert "120.0" in report  # rss start
    assert "155.0" in report  # rss peak
    assert "35.0" in report  # rss growth (155 - 120)
    assert "11" in report  # fd growth (41 - 30); "S7" carries no stray "11"


def test_render_soak_report_marks_unsampled_scenarios():
    """An unsampled scenario is labelled, not fabricated as zero growth."""
    report = render_soak_report([_load_result("S12", None)])
    assert "S12" in report
    assert "not sampled" in report


def test_write_soak_report_persists_rendered_table(tmp_path):
    """The writer persists exactly the rendered soak table."""
    results = [_load_result("S4", ResourceSample(90.0, 92.0, 91.0, 20, 21, 20, 5))]
    out = write_soak_report(results, tmp_path / "soak-report.txt")
    written = out.read_text(encoding="utf-8")
    assert written == render_soak_report(results)
    assert "S4" in written
