"""Load/soak runner — TH-1.5 (#474 · epic #462, design §4/§5).

Orchestrates one scenario end to end: serve the mock OP over real HTTP, boot the
resource server under uvicorn against it, build the pre-minted replay pool, drive
load with a **real Locust run**, then collect the metrics design §5 asks for:
RPS, p50/p95/p99/p999, per-class latency (the S2 alg-cost ratio),
error-rate-by-class (expected rejections excluded), cache-hit rate (RS
``/metrics`` at workers=1) and upstream fetches per issuer (the mock OP's
in-process ``stats``).

Locust runs in a **subprocess** (``locust --headless -f locustfile.py``) rather
than programmatically: importing locust triggers gevent's ``monkey.patch_all()``,
which deadlocks the parent's in-process asyncio mock-OP server thread. Keeping
Locust out-of-process isolates gevent's patched world — the parent stays a plain
asyncio/threading process. The pre-minted pool crosses the boundary as a JSON file
(tokens are just strings); the run summary comes back the same way.

Each scenario runs against a **fresh** mock OP + RS so caches start empty and no
failure-injection state bleeds across scenarios.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

import httpx

from ..harness import serve_mock_op
from ..harness.corpus import CORPUS_AUDIENCE
from ..harness.rs_server import boot_rs_process
from .pool import build_load_pool
from .resource_sampler import ResourceSample, ResourceSampler
from .scenarios import (
    SCENARIOS_BY_ID,
    Profile,
    RampSpec,
    Scenario,
    profile_scenarios,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..harness.mock_op import MockOP
    from .pool import LoadPool


HTTP_SERVER_ERROR_FLOOR = 500
_LOCUSTFILE = Path(__file__).with_name("locustfile.py")
_LOCUST_GRACE = 60.0  # seconds of headroom over a scenario's run-time
# A window that recorded fewer than this many requests never really measured the
# RS — see _degenerate_window. The re-drive stretches the window by this factor so
# a cold-runner Locust startup cost is amortised on the second attempt.
_MIN_MEASURED_REQUESTS = 1
_DEGENERATE_RETRY_FACTOR = 3


@dataclass(frozen=True)
class Gate:
    """Absolute SLO thresholds for a scenario class — **Track C** only.

    These are *dormant by design* on the co-located shared runner, not "pending
    calibration": absolute p99/RPS on a box that shares cores between the
    generator, mock OP, and RS are contention noise, so any fixed threshold is
    either useless (loose) or flaky (tight). Shared CI instead gates on the
    machine-independent invariants in :func:`evaluate_gates` (5xx, status
    correctness, the S2 alg-cost ratio band, warm-all-hits — Track A). These
    absolute fields are populated only from a baseline on an owner-provisioned
    **isolated** runner, where the numbers are trustworthy (T314b → TH-4.5). See
    ``sprint-change-proposal-2026-08-19.md`` and ``src/tests/load/README.md``.
    """

    max_p99_ms: float | None = None
    min_rps: float | None = None
    max_error_rate: float | None = None
    min_cache_hit_rate: float | None = None


# Gate key -> absolute thresholds. Dormant on shared CI by design (Track C); the
# machine-independent gates that actually fail a shared-CI build live in
# evaluate_gates (Track A). Absolute bars are set only on an isolated runner.
GATES: dict[str, Gate] = {
    "warm": Gate(),
    "cold": Gate(),
}


@dataclass
class LoadResult:
    """The measured outcome of one scenario run."""

    scenario_id: str
    title: str
    num_requests: int
    num_failures: int
    rps: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    p999_ms: float
    server_errors: int
    steady_state: bool
    requests_by_class: dict[str, int] = field(default_factory=dict)
    failures_by_class: dict[str, int] = field(default_factory=dict)
    # class name -> {"p50", "p95", "p99"} ms; drives the S2 alg-cost ratio.
    latency_by_class: dict[str, dict[str, float]] = field(default_factory=dict)
    cache_metrics: dict[str, int] = field(default_factory=dict)
    upstream_stats: dict[str, int] = field(default_factory=dict)
    # RSS/FD trend of the RS process tree over the run (T313, soak scenarios).
    # ``None`` when the run was not resource-sampled (no RS pid was passed).
    resources: ResourceSample | None = None

    def alg_cost_ratio(self, numerator: str, denominator: str) -> float | None:
        """p95 latency ratio of two token classes (e.g. ES256 vs RS256, S2).

        Returns ``None`` when either class is absent or the denominator p95 is
        zero, so a missing/degenerate sample never fabricates a ratio.
        """
        num = self.latency_by_class.get(numerator, {}).get("p95")
        den = self.latency_by_class.get(denominator, {}).get("p95")
        if not num or not den:
            return None
        return num / den

    @property
    def error_rate(self) -> float:
        """Unexpected-status fraction (expected 401/403 rejections excluded)."""
        return self.num_failures / self.num_requests if self.num_requests else 0.0

    @property
    def cache_hit_rate(self) -> float:
        """Combined discovery+JWKS hit rate over the measured window (0..1).

        Returns ``0.0`` — not ``1.0`` — when the window recorded no counted
        cache activity (``total == 0``). An all-upstream-error window now counts
        its failed fetches as misses (see ``record_*_miss``), so ``total`` is
        non-zero there and the rate reflects the storm; the ``total == 0`` guard
        therefore only fires when nothing reached the counted cache paths at all,
        and reporting that as a perfect 100% would let a broken ``/metrics``
        scrape masquerade as a warm cache under a ``min_cache_hit_rate`` gate.
        """
        m = self.cache_metrics
        hits = m.get("disco_hits", 0) + m.get("jwks_hits", 0)
        misses = m.get("disco_misses", 0) + m.get("jwks_misses", 0)
        total = hits + misses
        return hits / total if total else 0.0


@dataclass
class CapacityStep:
    """One rung of a capacity ramp: what was offered vs what the RS delivered."""

    target_rps: int
    achieved_rps: float
    p99_ms: float
    error_rate: float
    server_errors: int
    breached: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class CapacityResult:
    """The outcome of one capacity/breakpoint ramp (TH-4).

    ``max_sustainable_rps`` is the achieved goodput of the last rung that met SLO
    — the knee. ``breaking_target_rps`` is the first offered rate that breached
    (``None`` when the ladder was exhausted without one, i.e. ``stop_rps`` is too
    low to find the knee — a result to act on, not a pass).
    """

    scenario_id: str
    title: str
    workers: int
    steps: list[CapacityStep]
    max_sustainable_rps: float
    knee_target_rps: int
    knee_p99_ms: float
    breaking_target_rps: int | None
    breach_reasons: list[str] = field(default_factory=list)

    @property
    def found_breakpoint(self) -> bool:
        """True when a rung breached SLO (the ramp actually reached the knee)."""
        return self.breaking_target_rps is not None


def _scrape_cache_metrics(base_url: str) -> dict[str, int]:
    try:
        resp = httpx.get(f"{base_url}/metrics", timeout=5.0)
        resp.raise_for_status()
        return {k: int(v) for k, v in resp.json().items()}
    except (httpx.HTTPError, ValueError):  # pragma: no cover - defensive
        return {}


def _warm_cache(base_url: str, token: str) -> None:
    """Prime the RS discovery+JWKS cache before a warm-scenario measurement."""
    with contextlib.suppress(httpx.HTTPError):
        httpx.get(
            f"{base_url}/protected",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )


def _run_locust(
    base_url: str,
    pool: LoadPool,
    *,
    users: int,
    run_seconds: int,
    throughput_per_user: float = 0.0,
    label: str = "run",
) -> dict:
    """Drive a real Locust run in a subprocess; return its summary dict.

    ``throughput_per_user`` > 0 selects the open-model ramp path: each user is
    paced to that many req/s (offered load = ``users * throughput_per_user``), so
    the process drives a *controlled arrival rate*. 0 keeps the closed-loop
    fixed-hold generator. ``label`` names the run in the no-summary error only.
    """
    run_seconds = max(1, run_seconds)
    with tempfile.TemporaryDirectory() as tmp:
        pool_file = Path(tmp) / "pool.json"
        result_file = Path(tmp) / "result.json"
        pool_file.write_text(
            json.dumps(
                [
                    {
                        "name": e.name,
                        "token": e.token,
                        "expected_status": e.expected_status,
                    }
                    for e in pool.entries
                ]
            )
        )
        cmd = [
            sys.executable,
            "-m",
            "locust",
            "--headless",
            "-f",
            str(_LOCUSTFILE),
            "-u",
            str(users),
            "-r",
            str(users),  # ramp all users in one second
            "-t",
            f"{run_seconds}s",
            "--host",
            base_url,
            "--loglevel",
            "WARNING",
            # Expected 401/403 rejections are scored as successes, but a
            # failure-injection scenario legitimately produces failures; let the
            # parent evaluate gates from the summary rather than the exit code.
            "--exit-code-on-error",
            "0",
        ]
        env = {
            "HARNESS_POOL_FILE": str(pool_file),
            "HARNESS_RESULT_FILE": str(result_file),
            # Empty string => closed-loop (locustfile leaves wait_time unset).
            "HARNESS_THROUGHPUT_PER_USER": (
                repr(throughput_per_user) if throughput_per_user > 0 else ""
            ),
        }
        completed = subprocess.run(  # noqa: S603 — fixed argv, no shell, test-only
            cmd,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=run_seconds + _LOCUST_GRACE,
            check=False,
        )
        if not result_file.exists():
            raise RuntimeError(
                f"locust produced no summary for {label} "
                f"(exit {completed.returncode}):\n{completed.stderr[-2000:]}"
            )
        return json.loads(result_file.read_text())


def run_scenario(
    scenario: Scenario, op: MockOP, base_url: str, *, rs_pid: int | None = None
) -> LoadResult:
    """Drive one scenario against an already-booted RS and mock OP.

    When ``rs_pid`` is given, the RS process tree's RSS/FD is sampled for the
    duration of the load run and attached to the result (``LoadResult.resources``)
    — the soak leak signal (T313). Omitting it (the default) leaves ``resources``
    ``None`` and runs exactly as before.
    """
    pool = build_load_pool(op, scenario.classes)

    # A warm scenario measures the hot-cache steady state: prime the cache with a
    # valid token, then zero the upstream counters so the measured window starts
    # clean. A cold scenario skips the warmup so its stampede fetches are counted.
    if scenario.gate == "warm":
        valid = next((e for e in pool.entries if e.name.startswith("valid")), None)
        if valid is not None:
            _warm_cache(base_url, valid.token)
    # Apply failure injection AFTER the pool is minted (valid tokens signed by the
    # published key) and after any warmup.
    if scenario.setup is not None:
        scenario.setup(op)
    op.stats.reset()

    with _maybe_sampler(rs_pid) as sampler:
        summary = _run_locust(
            base_url,
            pool,
            users=scenario.users,
            run_seconds=int(scenario.duration_seconds),
            label=scenario.id,
        )
        # A window that drove ~zero requests never measured the RS: on a
        # cold/contended runner Locust's subprocess startup (gevent monkey-patch +
        # import + connect) can consume the whole short window before any request
        # completes, yielding a degenerate 0-request summary that false-fails the
        # "drove load"/warm-cache gates. This startup flake is orthogonal to the
        # scenario type — a fast failure-injection scenario (S6 kid-rotation,
        # returning quick 401/200s) that recorded zero is just as degenerate as a
        # steady-state one. Re-drive once with a longer window — the caches are
        # already warm and the flake does not repeat — rather than trusting the
        # empty measurement.
        if _degenerate_window(summary):
            summary = _run_locust(
                base_url,
                pool,
                users=scenario.users,
                run_seconds=int(scenario.duration_seconds) * _DEGENERATE_RETRY_FACTOR,
                label=f"{scenario.id}:retry-degenerate-window",
            )
    return _to_result(
        scenario, summary, base_url, op, resources=sampler.result if sampler else None
    )


def _degenerate_window(summary: dict) -> bool:
    """True when a run recorded ~zero requests — a startup flake, not a measurement.

    Applies to *every* scenario, not just steady-state ones: the flake is Locust
    subprocess startup eating the window, orthogonal to scenario type, so a fast
    failure-injection scenario (e.g. S6, which is ``steady_state=False`` yet in the
    PR gate) that recorded zero requests is just as degenerate. Only a literally
    empty window (``< 1`` request) qualifies, so a ``steady_state=False`` scenario
    that legitimately drives a *few* requests (provider-slowness stalls) keeps its
    data — non-zero injection signal is never masked. If the re-drive is also
    empty, the empty summary stands and the caller's ``num_requests > 0`` gate
    fails as it should (a truly hung RS is a defect, not a flake).
    """
    return int(summary.get("num_requests", 0)) < _MIN_MEASURED_REQUESTS


@contextlib.contextmanager
def _maybe_sampler(rs_pid: int | None) -> Iterator[ResourceSampler | None]:
    """Yield a live :class:`ResourceSampler` for ``rs_pid``, or ``None``.

    Keeps :func:`run_scenario` branch-free: the ``with`` block samples when a pid
    is present and is a no-op otherwise.
    """
    if rs_pid is None:
        yield None
        return
    with ResourceSampler(rs_pid) as sampler:
        yield sampler


def _to_result(
    scenario: Scenario,
    summary: dict,
    base_url: str,
    op: MockOP,
    *,
    resources: ResourceSample | None = None,
) -> LoadResult:
    by_class = summary.get("by_class", {})
    return LoadResult(
        scenario_id=scenario.id,
        title=scenario.title,
        num_requests=int(summary.get("num_requests", 0)),
        num_failures=int(summary.get("num_failures", 0)),
        rps=float(summary.get("rps", 0.0)),
        p50_ms=float(summary.get("p50", 0.0)),
        p95_ms=float(summary.get("p95", 0.0)),
        p99_ms=float(summary.get("p99", 0.0)),
        p999_ms=float(summary.get("p999", 0.0)),
        server_errors=int(summary.get("server_errors", 0)),
        steady_state=scenario.steady_state,
        requests_by_class={n: v["requests"] for n, v in by_class.items()},
        failures_by_class={
            n: v["failures"] for n, v in by_class.items() if v["failures"]
        },
        latency_by_class={
            n: {p: float(v[p]) for p in ("p50", "p95", "p99") if p in v}
            for n, v in by_class.items()
        },
        cache_metrics=_scrape_cache_metrics(base_url),
        upstream_stats=op.stats.snapshot(),
        resources=resources,
    )


def evaluate_gates(result: LoadResult) -> list[str]:
    """Return SLO/correctness violations for a result (empty = passed).

    Two invariants hold regardless of threshold calibration: a scenario must emit
    ZERO server errors (500s — a real defect, design §5), and a *steady-state*
    scenario must have ZERO unexpected-status divergences (every class returned
    its expected 200/401/403). Perf thresholds are checked only once calibrated.
    """
    violations: list[str] = []
    if result.server_errors:
        violations.append(
            f"{result.scenario_id}: {result.server_errors} server error(s) "
            f"(>= {HTTP_SERVER_ERROR_FLOOR}) — must be 0"
        )
    if result.steady_state and result.num_failures:
        violations.append(
            f"{result.scenario_id}: {result.num_failures} unexpected status "
            f"divergence(s) under steady state ({result.failures_by_class})"
        )
    gate = GATES.get(_gate_key(result.scenario_id))
    if gate is not None:
        if gate.max_p99_ms is not None and result.p99_ms > gate.max_p99_ms:
            violations.append(
                f"{result.scenario_id}: p99 {result.p99_ms}ms > {gate.max_p99_ms}ms"
            )
        if gate.min_rps is not None and result.rps < gate.min_rps:
            violations.append(
                f"{result.scenario_id}: rps {result.rps:.1f} < {gate.min_rps}"
            )
        if gate.max_error_rate is not None and result.error_rate > gate.max_error_rate:
            violations.append(
                f"{result.scenario_id}: error-rate {result.error_rate:.4f} "
                f"> {gate.max_error_rate}"
            )
        if (
            gate.min_cache_hit_rate is not None
            and result.cache_hit_rate < gate.min_cache_hit_rate
        ):
            violations.append(
                f"{result.scenario_id}: cache-hit-rate {result.cache_hit_rate:.4f} "
                f"< {gate.min_cache_hit_rate}"
            )
    # Machine-independent Track-A gates (sprint-change-proposal-2026-08-19): these
    # fail on a real regression but never on runner noise, so they are safe on the
    # co-located shared CI where absolute p99/RPS thresholds cannot live.
    scenario = SCENARIOS_BY_ID.get(result.scenario_id)
    if scenario is not None:
        violations.extend(_alg_cost_band_violations(result, scenario))
        violations.extend(_warm_all_hits_violations(result, scenario))
    return violations


def _alg_cost_band_violations(result: LoadResult, scenario: Scenario) -> list[str]:
    """Flag a two-class p95 latency ratio outside its band (a gross asymmetry).

    A coarse tripwire (see :class:`AlgCostBand`): it catches a gross per-request
    cost asymmetry between the two algorithm paths, not a subtle verify-time
    regression (end-to-end p95 is ms-quantised and overhead-dominated). A
    degenerate/missing ratio (a class did not drive load, or its p95 is zero) is
    NOT flagged here — presence is asserted by the CI-short
    ``test_s2_alg_cost_ratio_is_reportable`` test — so the gate never
    double-jeopardies a thin sample.
    """
    band = scenario.alg_cost_band
    if band is None:
        return []
    ratio = result.alg_cost_ratio(band.num, band.den)
    if ratio is None:
        return []
    if not band.lo <= ratio <= band.hi:
        return [
            f"{result.scenario_id}: {band.num}/{band.den} p95 ratio {ratio:.3f} "
            f"outside [{band.lo}, {band.hi}] — alg-cost regression"
        ]
    return []


def _warm_all_hits_violations(result: LoadResult, scenario: Scenario) -> list[str]:
    """Flag a warm-all-hits scenario whose measured window was not all-hits.

    The request-count-independent form of the S1 warm invariant (#539) lifted into
    the gate path: the window must record cache hits and add no misses beyond the
    single cold warmup (≤1 discovery, ≤1 JWKS). Zero hits also fires — a broken
    ``/metrics`` scrape must not pass a warm-cache gate vacuously.
    """
    if not scenario.warm_all_hits:
        return []
    m = result.cache_metrics
    hits = m.get("disco_hits", 0) + m.get("jwks_hits", 0)
    if hits <= 0:
        return [
            f"{result.scenario_id}: warm-all-hits gate saw no cache hits "
            f"(metrics={m}) — cache not exercised or /metrics scrape broken"
        ]
    violations: list[str] = []
    if m.get("disco_misses", 0) > 1:
        violations.append(
            f"{result.scenario_id}: warm window added discovery misses "
            f"(disco_misses={m.get('disco_misses')} > 1)"
        )
    if m.get("jwks_misses", 0) > 1:
        violations.append(
            f"{result.scenario_id}: warm window added JWKS misses "
            f"(jwks_misses={m.get('jwks_misses')} > 1)"
        )
    return violations


def _gate_key(scenario_id: str) -> str:
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    return scenario.gate if scenario and scenario.gate else "warm"


def run_profile(profile: Profile) -> list[LoadResult]:
    """Run every scenario in *profile* against a fresh mock-OP-backed RS each.

    Each scenario gets its own in-process mock OP + booted RS so caches start
    empty and failure-injection state never bleeds across scenarios. The mock OP
    is the design's failure-injection driver (latency, 429, key rotation), so the
    self-contained CI_SHORT profile needs no external IdP — the node-oidc
    real-issuer leg (real minted tokens) is a separate test-phase concern.

    Capacity scenarios (``scenario.ramp is not None``) are skipped here — they
    are ramps, not fixed-hold runs; use :func:`run_capacity_profile`.
    """
    results: list[LoadResult] = []
    for scenario in profile_scenarios(profile):
        if scenario.ramp is not None:
            continue
        with _scenario_stack(workers=scenario.workers) as (op, base_url, rs_pid):
            results.append(run_scenario(scenario, op, base_url, rs_pid=rs_pid))
    return results


def _breach_reasons(result: LoadResult, target_rps: int, ramp: RampSpec) -> list[str]:
    """Why a ramp rung failed SLO (empty = it sustained the offered rate).

    A 5xx is a hard defect. The primary knee signal is a *goodput plateau*:
    achieved RPS falling below ``sustain_ratio * target`` means the RS stopped
    keeping up (a finite per-core verify rate) — the machine-independent
    breakpoint. The p99 ceiling and error budget are the secondary SLO breaches.
    """
    reasons: list[str] = []
    if result.server_errors:
        reasons.append(f"{result.server_errors} server error(s) (5xx)")
    floor = ramp.sustain_ratio * target_rps
    if result.rps < floor:
        reasons.append(
            f"goodput plateau: {result.rps:.0f} rps < "
            f"{floor:.0f} ({ramp.sustain_ratio:.0%} of {target_rps} offered)"
        )
    if ramp.max_p99_ms is not None and result.p99_ms > ramp.max_p99_ms:
        reasons.append(f"p99 {result.p99_ms:.0f}ms > {ramp.max_p99_ms:.0f}ms")
    if result.error_rate > ramp.max_error_rate:
        reasons.append(f"error-rate {result.error_rate:.4f} > {ramp.max_error_rate}")
    return reasons


def run_capacity_scenario(
    scenario: Scenario, op: MockOP, base_url: str
) -> CapacityResult:
    """Walk *scenario*'s arrival-rate ramp to the goodput knee (TH-4).

    Warms the cache (warm gate), applies any failure injection, then offers each
    rung of the ladder for ``step_seconds`` against the *same* booted RS — so the
    ramp measures one server heating up, not a cold restart per rung. Stops at
    the first rung that breaches SLO and records the previous rung as the knee.
    """
    ramp = scenario.ramp
    if ramp is None:  # pragma: no cover - guarded by the caller
        raise ValueError(f"{scenario.id}: not a capacity scenario (ramp is None)")

    pool = build_load_pool(op, scenario.classes)
    if scenario.gate == "warm":
        valid = next((e for e in pool.entries if e.name.startswith("valid")), None)
        if valid is not None:
            _warm_cache(base_url, valid.token)
    if scenario.setup is not None:
        scenario.setup(op)
    op.stats.reset()

    steps: list[CapacityStep] = []
    max_sustainable_rps = 0.0
    knee_target_rps = 0
    knee_p99_ms = 0.0
    breaking_target_rps: int | None = None
    breach_reasons: list[str] = []

    for target in ramp.targets():
        summary = _run_locust(
            base_url,
            pool,
            users=ramp.users_for(target),
            run_seconds=int(ramp.step_seconds),
            throughput_per_user=ramp.rps_per_user,
            label=f"{scenario.id}@{target}rps",
        )
        result = _to_result(scenario, summary, base_url, op)
        reasons = _breach_reasons(result, target, ramp)
        steps.append(
            CapacityStep(
                target_rps=target,
                achieved_rps=result.rps,
                p99_ms=result.p99_ms,
                error_rate=result.error_rate,
                server_errors=result.server_errors,
                breached=bool(reasons),
                reasons=reasons,
            )
        )
        if reasons:
            breaking_target_rps = target
            breach_reasons = reasons
            break
        max_sustainable_rps = result.rps
        knee_target_rps = target
        knee_p99_ms = result.p99_ms

    return CapacityResult(
        scenario_id=scenario.id,
        title=scenario.title,
        workers=scenario.workers,
        steps=steps,
        max_sustainable_rps=max_sustainable_rps,
        knee_target_rps=knee_target_rps,
        knee_p99_ms=knee_p99_ms,
        breaking_target_rps=breaking_target_rps,
        breach_reasons=breach_reasons,
    )


def run_capacity_profile(
    profile: Profile = Profile.CAPACITY,
) -> list[CapacityResult]:
    """Run every ramp scenario in *profile*, each against a fresh RS at its own
    worker count (the cross-worker scaling sweep boots 1/2/4 workers)."""
    results: list[CapacityResult] = []
    for scenario in profile_scenarios(profile):
        if scenario.ramp is None:
            continue
        # A ramp changes offered load each rung, so a whole-run RSS/FD trend is
        # not the breakpoint signal — capacity runs skip the sampler (the pid is
        # unused). Soak leak coverage is the fixed-hold path (``run_scenario``).
        with _scenario_stack(workers=scenario.workers) as (op, base_url, _rs_pid):
            results.append(run_capacity_scenario(scenario, op, base_url))
    return results


def render_capacity_report(results: list[CapacityResult]) -> str:
    """A human/artifact-readable capacity curve + knee summary per scenario."""
    lines: list[str] = []
    for r in results:
        lines.append(f"{r.scenario_id}  {r.title}  ({r.workers} worker[s])")
        lines.append(f"{'target':>8}{'rps':>9}{'p99ms':>8}{'err%':>7}  status")
        for s in r.steps:
            status = "BREACH — " + "; ".join(s.reasons) if s.breached else "sustained"
            lines.append(
                f"{s.target_rps:>8}{s.achieved_rps:>9.0f}{s.p99_ms:>8.1f}"
                f"{s.error_rate * 100:>7.2f}  {status}"
            )
        if r.found_breakpoint:
            lines.append(
                f"  KNEE: ~{r.max_sustainable_rps:.0f} rps sustained "
                f"(offered {r.knee_target_rps}, p99 {r.knee_p99_ms:.1f}ms); "
                f"breaks at {r.breaking_target_rps} rps — {'; '.join(r.breach_reasons)}"
            )
        else:
            top = r.steps[-1].target_rps if r.steps else 0
            lines.append(
                f"  NO breakpoint within ladder (sustained top rung {top} rps) — "
                f"raise stop_rps to find the knee"
            )
        lines.append("")
    return "\n".join(lines)


def _write_report(text: str, path: str | Path) -> Path:
    """Write *text* to *path* as UTF-8, creating parent dirs; return the path.

    UTF-8 is explicit (not the locale default) because both reports carry
    non-ASCII glyphs — the capacity report's ``—`` and the soak header's ``Δ`` —
    which would raise ``UnicodeEncodeError`` under a POSIX/ASCII CI locale.
    """
    out = Path(path)
    if out.parent != Path():
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out


def write_capacity_report(results: list[CapacityResult], path: str | Path) -> Path:
    """Render *results* and write the capacity report to *path*.

    The nightly ``load-capacity`` job sets ``HARNESS_CAPACITY_REPORT`` so this
    file can be uploaded as a downloadable artifact — the ramp curve + knee per
    scenario, which otherwise lives only in the job log.
    """
    return _write_report(render_capacity_report(results), path)


def render_soak_report(results: list[LoadResult]) -> str:
    """A human/artifact-readable RSS/FD trend table per soak scenario (T313).

    Turns the sampled ``LoadResult.resources`` into the numbers the pass/fail
    soak assertions hide: start/peak/end RSS (MB), FD counts, and the growth
    deltas that are the actual leak signal. An unsampled scenario is shown as
    ``not sampled`` rather than fabricated zeros.
    """
    lines = [
        "Soak RSS/FD trend (per scenario) — growth = peak - start",
        f"{'scenario':<9}{'rssMB0':>8}{'rssMBpk':>9}{'rssMBΔ':>8}"
        f"{'fd0':>6}{'fdPk':>6}{'fdΔ':>5}{'n':>5}  title",
    ]
    for r in results:
        res = r.resources
        if res is None or not res.sampled:
            lines.append(f"{r.scenario_id:<9}{'not sampled':>36}  {r.title}")
            continue
        lines.append(
            f"{r.scenario_id:<9}{res.rss_start_mb:>8.1f}{res.rss_max_mb:>9.1f}"
            f"{res.rss_growth_mb:>8.1f}{res.fd_start:>6}{res.fd_max:>6}"
            f"{res.fd_growth:>5}{res.num_samples:>5}  {r.title}"
        )
    return "\n".join(lines) + "\n"


def write_soak_report(results: list[LoadResult], path: str | Path) -> Path:
    """Render the soak RSS/FD trend and write it to *path*.

    The nightly ``load-soak`` job sets ``HARNESS_SOAK_REPORT`` so the RSS/FD
    numbers are uploaded as a downloadable artifact instead of being hidden
    behind a green pass/fail.
    """
    return _write_report(render_soak_report(results), path)


def render_smoke_report(results: list[LoadResult]) -> str:
    """A human/artifact-readable per-scenario summary for the CI_SHORT gate.

    Turns each scenario's throughput/latency/error/cache numbers — and its
    pass/fail gate verdict — into a table the PR-gate ``load-smoke`` job uploads
    as a downloadable artifact, so the per-PR load run leaves evidence behind
    instead of only a green check. The ``gate`` column flags PASS/FAIL; any
    violations are listed in full below the table.
    """
    lines = [
        "Load-smoke summary (CI_SHORT) — real Locust vs the booted RS, short hold",
        f"{'scenario':<9}{'reqs':>7}{'rps':>9}{'p50ms':>8}{'p95ms':>8}{'p99ms':>8}"
        f"{'p999ms':>9}{'err%':>7}{'5xx':>5}{'hit%':>7}  {'gate':<4} title",
    ]
    violations: list[str] = []
    for r in results:
        gate = evaluate_gates(r)
        violations.extend(gate)
        lines.append(
            f"{r.scenario_id:<9}{r.num_requests:>7}{r.rps:>9.1f}{r.p50_ms:>8.1f}"
            f"{r.p95_ms:>8.1f}{r.p99_ms:>8.1f}{r.p999_ms:>9.1f}"
            f"{r.error_rate * 100:>7.2f}{r.server_errors:>5}{r.cache_hit_rate * 100:>7.1f}"
            f"  {'FAIL' if gate else 'PASS':<4} {r.title}"
        )
    if violations:
        lines.append("")
        lines.append("Gate violations:")
        lines.extend(f"  - {v}" for v in violations)
    return "\n".join(lines) + "\n"


def write_smoke_report(results: list[LoadResult], path: str | Path) -> Path:
    """Render the CI_SHORT per-scenario summary and write it to *path*.

    The PR-gate ``load-smoke`` job sets ``HARNESS_SMOKE_REPORT`` so this table is
    uploaded as a downloadable artifact — the per-scenario RPS / latency /
    gate-verdict evidence that otherwise lives only in the job log.
    """
    return _write_report(render_smoke_report(results), path)


@contextlib.contextmanager
def _scenario_stack(workers: int = 1) -> Iterator[tuple[MockOP, str, int]]:
    """Fresh mock OP + booted RS for a single scenario (clean cache each time).

    Yields the RS's uvicorn master PID alongside the URL so the runner can sample
    the process tree's RSS/FD during the run (T313).
    """
    with (
        serve_mock_op() as op,
        boot_rs_process(
            issuer=op.issuer,
            audience=CORPUS_AUDIENCE,
            require_scope="read",
            workers=workers,
        ) as rs,
    ):
        yield op, rs.base_url, rs.pid
