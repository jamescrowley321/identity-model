"""Real-Locust CI-short proof for the load suite — TH-1.5 (#474, epic #462).

This is the ``test`` phase's DoD entrypoint: a REAL Locust run (programmatic,
headless) driving the booted resource server (real uvicorn subprocess, real HTTP)
with the pre-minted replay pool, over the CI_SHORT scenario profile
(S1, S2, S3, S6, S8). A green *unit* run is not proof — this drives actual load
and scores real responses. (S4 TTL-rollover needs a >60s window per the 60s cache
TTL floor and lives in NIGHTLY; S5/S9/S10 are DIAGNOSTIC.)

Self-contained: the controllable mock OP is the design's failure-injection driver
(latency, key rotation, contention), so no external IdP is needed. The suite skips
cleanly in a plain unit env (``locust``/fastapi absent); run it via
``make test-harness-load`` under ``uv run --group load --all-packages``.

The ``locust`` availability check uses :func:`importlib.util.find_spec` and does
NOT import locust in this process: importing locust triggers gevent's
``monkey.patch_all()``, which would deadlock the in-process asyncio mock-OP server
thread the runner boots. Locust only ever runs in the runner's subprocess.
"""

from __future__ import annotations

import importlib.util
import os

import pytest


if importlib.util.find_spec("locust") is None:
    pytest.skip("locust (load group) not installed", allow_module_level=True)
pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

from .runner import evaluate_gates, run_profile, write_smoke_report
from .scenarios import Profile, profile_scenarios


pytestmark = pytest.mark.integration

_CI_SHORT_IDS = [s.id for s in profile_scenarios(Profile.CI_SHORT)]

# Where the fixture writes the per-scenario RPS/latency/gate table so CI can
# upload it as an artifact (the numbers the pass/fail assertions otherwise hide).
# The load-smoke job overrides it to the artifact path; local runs leave a
# gitignored file.
_SMOKE_REPORT_PATH = os.environ.get("HARNESS_SMOKE_REPORT", "load-smoke-report.txt")


@pytest.fixture(scope="module")
def ci_short_results():
    """Run the CI_SHORT profile once; share the per-scenario results.

    Each scenario boots its own mock OP + RS, so this is a few seconds per
    scenario — run once at module scope and assert over the results. The
    per-scenario summary is written to ``_SMOKE_REPORT_PATH`` before the
    assertions run, so the artifact exists even when a later assertion fails.
    """
    results = {result.scenario_id: result for result in run_profile(Profile.CI_SHORT)}
    write_smoke_report(list(results.values()), _SMOKE_REPORT_PATH)
    return results


def test_every_ci_short_scenario_ran(ci_short_results):
    """The profile executed exactly the CI-short catalogue (S1, S2, S3, S6, S8)."""
    assert set(ci_short_results) == set(_CI_SHORT_IDS)


def test_s2_alg_cost_ratio_is_reportable(ci_short_results):
    """S2 (design §4): the RS256-vs-ES256 warm cost ratio is computable.

    Per-class p95 latency is captured in the summary, so the ES256/RS256 ratio
    the scenario exists to report can actually be derived from the result (both
    classes drove load and the ratio is a positive, finite number).
    """
    s2 = ci_short_results["S2"]
    assert s2.requests_by_class.get("valid", 0) > 0, s2.requests_by_class
    assert s2.requests_by_class.get("valid_es256", 0) > 0, s2.requests_by_class
    ratio = s2.alg_cost_ratio("valid_es256", "valid")
    assert ratio is not None, s2.latency_by_class
    assert ratio > 0, s2.latency_by_class


@pytest.mark.parametrize("scenario_id", _CI_SHORT_IDS)
def test_scenario_drove_load_and_met_gates(ci_short_results, scenario_id):
    """Each scenario drove real requests and violated no SLO/correctness gate."""
    result = ci_short_results[scenario_id]
    assert result.num_requests > 0, f"{scenario_id} drove no load"
    # p999 (design §5) is captured from the run summary, not dropped — it is a
    # percentile so it must be >= p99 (a reverted/zeroed p999 field fails here).
    assert result.p999_ms >= result.p99_ms, (result.p999_ms, result.p99_ms)
    violations = evaluate_gates(result)
    assert not violations, "; ".join(violations)


def test_no_server_errors_anywhere(ci_short_results):
    """Design §5 hard invariant: ZERO 500s across the whole profile."""
    offenders = {
        sid: r.server_errors for sid, r in ci_short_results.items() if r.server_errors
    }
    assert not offenders, f"server errors (5xx): {offenders}"


def test_s3_cold_stampede_is_single_flight(ci_short_results):
    """S3: a cold burst must fetch discovery + JWKS exactly once each.

    The single-flight cache coalesces the concurrent cold-cache misses, so the
    mock-OP upstream counters must show one discovery fetch and one JWKS fetch
    for the whole stampede — the core anti-stampede proof (design §4 S3).
    """
    s3 = ci_short_results["S3"]
    assert s3.upstream_stats.get("discovery") == 1, s3.upstream_stats
    assert s3.upstream_stats.get("jwks") == 1, s3.upstream_stats


def test_s1_warm_cache_is_all_hits(ci_short_results):
    """S1: after warmup the measured window serves entirely from cache.

    The authoritative proof is the mock-OP upstream counters (reset after the
    warmup): ZERO discovery/JWKS fetches during the measured window — no cache
    miss ever reached upstream while load was driven.

    The RS-side per-process cache counters have no reset route, so they still
    carry the single cold warmup miss (one discovery + one JWKS fetch, coalesced
    by single-flight). The warm invariant is therefore that the measured window
    added NO misses of its own: discovery and JWKS misses stay at their
    cold-start bound of one each while hits accrue. That is asserted directly on
    the miss counts rather than via a hit *rate*, because a hit rate is
    volume-sensitive — ``hits / (hits + 2)`` only clears 0.99 once the window has
    driven ~200 requests. A slow, contended CI runner can spin the first Locust
    subprocess up so late that only a handful of requests land in the window; the
    lone warmup miss then dominates the cumulative rate and false-fails a cache
    that is genuinely warm. Bounding the miss counts is request-count-independent
    and captures the real property (the ``cache_hit_rate`` helper still covers the
    rate arithmetic in unit tests).
    """
    s1 = ci_short_results["S1"]
    assert s1.upstream_stats.get("discovery", 0) == 0, s1.upstream_stats
    assert s1.upstream_stats.get("jwks", 0) == 0, s1.upstream_stats
    m = s1.cache_metrics
    # The cache was actually exercised — guards against a broken ``/metrics``
    # scrape returning an empty dict and passing the miss bounds vacuously.
    assert m.get("disco_hits", 0) > 0, m
    assert m.get("jwks_hits", 0) > 0, m
    # No miss beyond the single cold warmup fetch: the measured window was all
    # hits (the request-count-independent form of ``cache_hit_rate`` ~ 1).
    assert m.get("disco_misses", 0) <= 1, m
    assert m.get("jwks_misses", 0) <= 1, m
