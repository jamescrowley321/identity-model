"""Real-Locust nightly soak proof for the load suite — TH-1.5 (#271, epic #462).

The scheduled counterpart to :mod:`test_load_ci_short`. Runs the NIGHTLY scenario
profile (S4 TTL-rollover — needs a >60s window past the 60s cache-TTL floor — plus
the S7 LRU-thrash and S11/S12 RSS/FD soak scenarios) with the same real-Locust-vs-
booted-RS machinery, but the long-window work that does not belong on the PR gate.

Scheduled by ``.github/workflows/nightly.yml``; run on demand via
``make test-harness-load-nightly`` under ``uv run --group load --all-packages``.

Self-contained (the controllable mock OP is the failure-injection driver — no
external IdP). See :mod:`test_load_ci_short` for why locust is never imported in
this process (gevent ``monkey.patch_all`` would deadlock the in-process mock OP).
"""

from __future__ import annotations

import importlib.util
import os

import pytest


if importlib.util.find_spec("locust") is None:
    pytest.skip("locust (load group) not installed", allow_module_level=True)
pytest.importorskip("fastapi_identity_model")
pytest.importorskip("uvicorn")

from .runner import evaluate_gates, run_profile, write_soak_report
from .scenarios import Profile, profile_scenarios


pytestmark = pytest.mark.integration

_NIGHTLY_IDS = [s.id for s in profile_scenarios(Profile.NIGHTLY)]

# Where the fixture writes the RSS/FD trend table so CI can upload it as an
# artifact (the numbers the pass/fail assertions otherwise hide). The nightly
# job overrides it to the artifact path; local runs leave a gitignored file.
_SOAK_REPORT_PATH = os.environ.get("HARNESS_SOAK_REPORT", "soak-report.txt")


@pytest.fixture(scope="module")
def nightly_results():
    """Run the NIGHTLY soak profile once; share the per-scenario results.

    Each scenario boots its own mock OP + RS. S4 alone runs past the 60s cache
    TTL, so this fixture takes minutes — module scope so it runs once. The RSS/FD
    trend is written to ``_SOAK_REPORT_PATH`` before the assertions run, so the
    artifact exists even when a later assertion fails.
    """
    results = {result.scenario_id: result for result in run_profile(Profile.NIGHTLY)}
    write_soak_report(list(results.values()), _SOAK_REPORT_PATH)
    return results


def test_every_nightly_scenario_ran(nightly_results):
    """The profile executed exactly the NIGHTLY soak catalogue (S4, S7, S11, S12)."""
    assert set(nightly_results) == set(_NIGHTLY_IDS)


@pytest.mark.parametrize("scenario_id", _NIGHTLY_IDS)
def test_soak_scenario_drove_load_and_met_gates(nightly_results, scenario_id):
    """Each soak scenario drove real requests and violated no SLO/correctness gate."""
    result = nightly_results[scenario_id]
    assert result.num_requests > 0, f"{scenario_id} drove no load"
    # p999 is a percentile so it must be >= p99 (a reverted/zeroed field fails here).
    assert result.p999_ms >= result.p99_ms, (result.p999_ms, result.p99_ms)
    violations = evaluate_gates(result)
    assert not violations, "; ".join(violations)


def test_no_server_errors_anywhere(nightly_results):
    """Design §5 hard invariant: ZERO 500s across the whole soak.

    Under a multi-minute soak this is the leak/exhaustion tripwire — a resource
    leak that eventually 500s (OOM, FD exhaustion, pool starvation) shows up here.
    """
    offenders = {
        sid: r.server_errors for sid, r in nightly_results.items() if r.server_errors
    }
    assert not offenders, f"server errors (5xx): {offenders}"


# A soak leak grows without bound; interpreter/allocator noise over a <=75s window
# does not. These ceilings are deliberately generous — they catch a runaway leak,
# not a few MB of arena churn. Precise per-scenario calibration from a baseline is
# T314b on the isolated runner (the dormant ``runner.GATES``, Track C); T313 proves
# the signal exists and is bounded.
_MAX_SOAK_RSS_GROWTH_MB = 128.0
_MAX_SOAK_FD_GROWTH = 64


@pytest.mark.parametrize("scenario_id", _NIGHTLY_IDS)
def test_soak_sampled_rss_and_fd(nightly_results, scenario_id):
    """Every soak scenario actually MEASURED the RS process tree (T313).

    Before T313, S11 ("RSS / FD soak") asserted nothing about RSS/FD — no field
    carried it. This is the mechanical proof the instrumentation captured a real,
    continuous trend (>=2 samples over the window) rather than a single reading.
    """
    result = nightly_results[scenario_id]
    resources = result.resources
    assert resources is not None, f"{scenario_id} was not resource-sampled"
    assert resources.sampled, f"{scenario_id} captured no live RSS/FD samples"
    assert resources.num_samples >= 2, (
        f"{scenario_id} sampled {resources.num_samples}x — expected a continuous "
        "trend over the run window"
    )
    assert resources.rss_max_mb > 0, f"{scenario_id} reported zero peak RSS"


@pytest.mark.parametrize("scenario_id", _NIGHTLY_IDS)
def test_soak_no_unbounded_resource_growth(nightly_results, scenario_id):
    """RSS and FD growth over the soak stay bounded — the cache-leak tripwire.

    A middleware cache that failed to evict (or an FD/connection leak to the OP)
    would grow RSS/FDs without bound over the window; a bounded cache stays flat.
    """
    resources = nightly_results[scenario_id].resources
    assert resources is not None, f"{scenario_id} was not resource-sampled"
    assert resources.sampled, f"{scenario_id} captured no live RSS/FD samples"
    assert resources.rss_growth_mb < _MAX_SOAK_RSS_GROWTH_MB, (
        f"{scenario_id} RSS grew {resources.rss_growth_mb:.1f}MB "
        f"({resources.rss_start_mb:.1f} -> {resources.rss_max_mb:.1f}) "
        f">= {_MAX_SOAK_RSS_GROWTH_MB}MB — possible memory leak"
    )
    assert resources.fd_growth < _MAX_SOAK_FD_GROWTH, (
        f"{scenario_id} FDs grew by {resources.fd_growth} "
        f"({resources.fd_start} -> {resources.fd_max}) "
        f">= {_MAX_SOAK_FD_GROWTH} — possible descriptor/connection leak"
    )
