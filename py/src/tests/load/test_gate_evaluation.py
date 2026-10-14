"""Deterministic unit coverage for the Track-A invariant gates — TH-4.3a.

`evaluate_gates` gained two machine-independent gates (LP-2 of the
`sprint-change-proposal-2026-08-19` correct-course): a wide-band two-class p95
latency ratio (S2's ES256/RS256) and a warm-all-hits cache invariant (S1/S2).
These tests inject a regression into a constructed :class:`LoadResult` and assert
the gate FIRES — a self-asserted green run is not proof that a gate can fail.

Pure functions over constructed results (no Locust, no booted RS), so they run in
the normal unit suite and pin the gate semantics regardless of any measured load.
"""

from __future__ import annotations

import pytest

from .runner import LoadResult, evaluate_gates
from .scenarios import SCENARIOS_BY_ID


pytestmark = pytest.mark.unit

# The request-count-independent healthy warm cache: hits accrued, misses at the
# single-cold-warmup bound. Reused so each test varies exactly one dimension.
_WARM_METRICS = {
    "disco_hits": 100,
    "jwks_hits": 100,
    "disco_misses": 1,
    "jwks_misses": 1,
}
# A healthy two-class p95 blend: ES256/RS256 ratio 1.5, well inside the band.
_HEALTHY_LATENCY = {
    "valid": {"p50": 1.0, "p95": 2.0, "p99": 3.0},
    "valid_es256": {"p50": 1.5, "p95": 3.0, "p99": 4.0},
}


def _result(
    scenario_id: str,
    *,
    latency_by_class: dict | None = None,
    cache_metrics: dict | None = None,
    server_errors: int = 0,
    num_failures: int = 0,
) -> LoadResult:
    """A LoadResult carrying only the fields the Track-A gates read (steady-state,
    no 5xx, no divergence) so the new gates are the sole variable."""
    return LoadResult(
        scenario_id=scenario_id,
        title=SCENARIOS_BY_ID[scenario_id].title,
        num_requests=1000,
        num_failures=num_failures,
        rps=500.0,
        p50_ms=1.0,
        p95_ms=2.0,
        p99_ms=3.0,
        p999_ms=4.0,
        server_errors=server_errors,
        steady_state=True,
        latency_by_class=latency_by_class or {},
        cache_metrics=cache_metrics
        if cache_metrics is not None
        else dict(_WARM_METRICS),
    )


def test_scenarios_carry_the_track_a_config() -> None:
    """Guard: the gates under test are actually wired to real scenarios, so a
    later refactor that drops the config makes these tests fail loudly."""
    assert SCENARIOS_BY_ID["S2"].alg_cost_band is not None
    assert SCENARIOS_BY_ID["S1"].warm_all_hits is True
    assert SCENARIOS_BY_ID["S2"].warm_all_hits is True


def test_healthy_s1_and_s2_pass_clean() -> None:
    """A well-formed warm result trips no Track-A gate."""
    assert evaluate_gates(_result("S1")) == []
    assert evaluate_gates(_result("S2", latency_by_class=_HEALTHY_LATENCY)) == []


def test_alg_cost_ratio_out_of_band_fires() -> None:
    """An ES256/RS256 p95 ratio blown past the band is a violation (regression)."""
    blown = {"valid": {"p95": 1.0}, "valid_es256": {"p95": 100.0}}
    violations = evaluate_gates(_result("S2", latency_by_class=blown))
    assert any("p95 ratio" in v and "alg-cost regression" in v for v in violations), (
        violations
    )


def test_alg_cost_ratio_missing_class_does_not_fire() -> None:
    """A degenerate/thin sample (a class absent) is not double-jeopardied here —
    presence is the reportable test's job; the band only catches a real ratio."""
    one_class = {"valid": {"p95": 2.0}}  # valid_es256 absent -> ratio None
    violations = evaluate_gates(_result("S2", latency_by_class=one_class))
    assert not any("p95 ratio" in v for v in violations), violations


def test_warm_all_hits_added_miss_fires() -> None:
    """A discovery/JWKS miss beyond the single cold warmup fails the warm gate."""
    leaky = {**_WARM_METRICS, "disco_misses": 5}
    violations = evaluate_gates(_result("S1", cache_metrics=leaky))
    assert any("added discovery misses" in v for v in violations), violations


def test_warm_all_hits_no_hits_fires_vacuous_guard() -> None:
    """An empty /metrics scrape must not pass the warm-cache gate vacuously."""
    violations = evaluate_gates(_result("S1", cache_metrics={}))
    assert any("no cache hits" in v for v in violations), violations


def test_gates_are_scoped_to_configured_scenarios() -> None:
    """A scenario without the band/flag (S3, cold) is untouched by the Track-A
    gates even with empty metrics and skewed latency — no accidental global gate."""
    skewed = {"valid": {"p95": 1.0}, "valid_es256": {"p95": 100.0}}
    result = _result("S3", latency_by_class=skewed, cache_metrics={})
    assert evaluate_gates(result) == []
