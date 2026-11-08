"""Load/soak scenario catalogue — TH-1.5 (#474 · epic #462, design §4 S1-S12).

Each :class:`Scenario` is *data*: which token classes populate the replay pool,
what mock-OP failure injection to apply before the run, how much load to drive,
and which SLO gate (design §5) evaluates the result. The :mod:`runner` executes
a scenario; :mod:`pool` builds its token blend; :mod:`locustfile` drives it.

Scenarios are grouped into run **profiles**:

* ``CI_SHORT`` (S1, S2, S3, S6, S8) — the PR gate: short (~3s), deterministic,
  mock-OP-backed, self-contained (no Docker).
* ``DIAGNOSTIC`` (S5, S9, S10) — head-of-line / no-store / blocking-validator
  probes run on demand.
* ``NIGHTLY`` (S4, S7, S11, S12) — TTL-refresh / LRU-thrash / RSS-FD soak /
  multi-tenant runs. S4 lives here (not CI-short) because the cache enforces a
  60s minimum TTL (``core.jwks_cache.MIN_CACHE_TTL_SECONDS``), so a genuine
  TTL rollover cannot happen inside a ~3s CI-short window — it needs a >60s run.
* ``CAPACITY`` (C1, C2) — TH-4 breakpoint runs. Unlike every scenario above
  (which holds a fixed load), these carry a :class:`RampSpec` and walk the
  arrival rate up to the goodput knee; :func:`runner.run_capacity_scenario`
  drives them and records max-sustainable RPS + the knee. Co-located, so the
  knee is a directional ceiling + regression signal, not an absolute limit.

Gates come in two tiers (``sprint-change-proposal-2026-08-19.md``). Shared CI gates
on **machine-independent invariants** — 5xx, status correctness, single-flight, the
S2 alg-cost ratio band, warm-all-hits — asserted across :func:`runner.evaluate_gates`
(5xx, status, alg-cost band, warm-all-hits) and the CI-short tests (single-flight in
``test_s3_cold_stampede_is_single_flight``) — Track A, so a real regression fails but
runner noise never does. The **absolute** SLO thresholds
(:mod:`runner` ``GATES`` — ``max_p99_ms``/``min_rps``/…) stay dormant on the
co-located shared runner *by design* and are calibrated only on an isolated runner
(T314b → TH-4.5, Track C), where absolute p99/RPS are trustworthy.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from math import ceil
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ..harness.mock_op import MockOP


# HTTP status codes the RS returns for each token class (audience=mock-api,
# require_scope=read — the same RS contract the correctness matrix asserts).
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403


# Token class -> the status the booted RS returns in STEADY STATE (no failure
# injection). Validly signed, correctly scoped tokens reach ``/protected`` (200);
# every validation-failure class collapses to a uniform 401 (F-18); the
# ID-token-as-access class is rejected by the always-on F-07 negative defence;
# the scope-less token validates but fails ``require_scope`` (403).
EXPECTED_STATUS: dict[str, int] = {
    "valid": HTTP_OK,
    "valid_es256": HTTP_OK,
    "cnf_bound": HTTP_UNAUTHORIZED,
    "oversized": HTTP_OK,
    "multi_aud_untrusted": HTTP_OK,
    "id_as_access": HTTP_UNAUTHORIZED,
    "expired": HTTP_UNAUTHORIZED,
    "nbf_future": HTTP_UNAUTHORIZED,
    "wrong_iss": HTTP_UNAUTHORIZED,
    "wrong_aud": HTTP_UNAUTHORIZED,
    "tampered_sig": HTTP_UNAUTHORIZED,
    "unknown_kid": HTTP_UNAUTHORIZED,
    "wrong_alg": HTTP_UNAUTHORIZED,
    "alg_none": HTTP_UNAUTHORIZED,
    "scopeless": HTTP_FORBIDDEN,
}

# The eight validation-failure classes whose 401s are the CORRECT outcome, not
# an error — they are excluded from the error budget (design §5). ``id_as_access``
# (401) and ``scopeless`` (403) are expected rejections too, tracked by their own
# expected status above; a class is an error only when observed != expected.
EXPECTED_REJECTION_CLASSES = frozenset(
    {
        "expired",
        "nbf_future",
        "wrong_iss",
        "wrong_aud",
        "tampered_sig",
        "unknown_kid",
        "wrong_alg",
        "alg_none",
        "id_as_access",
        "scopeless",
    }
)

# A representative mixed blend for the rejection-under-contention scenario (S8):
# accepted classes interleaved with every rejection class.
MIXED_CLASSES: tuple[str, ...] = (
    "valid",
    "cnf_bound",
    "oversized",
    "multi_aud_untrusted",
    "id_as_access",
    "expired",
    "nbf_future",
    "wrong_iss",
    "wrong_aud",
    "tampered_sig",
    "unknown_kid",
    "wrong_alg",
    "alg_none",
    "scopeless",
)


class Profile(StrEnum):
    """A named set of scenarios run together."""

    CI_SHORT = "ci-short"
    DIAGNOSTIC = "diagnostic"
    NIGHTLY = "nightly"
    CAPACITY = "capacity"


@dataclass(frozen=True)
class RampSpec:
    """An open-model arrival-rate ramp for a capacity/breakpoint scenario (TH-4).

    The fixed-hold scenarios (``ramp=None``) drive a *closed-loop* generator —
    a fixed user count firing back-to-back — which self-throttles as latency
    rises and so hides the knee. A ramp instead holds a generous **paced** user
    pool and walks the *target arrival rate* upward one step at a time against
    the same warm RS, so offered load is controlled and the point where goodput
    stops tracking it (the knee) becomes visible.

    Each step offers ``target_rps`` for ``step_seconds`` by pacing every user at
    ``rps_per_user`` req/s (Locust ``constant_throughput``) and sizing the pool
    to ``target_rps / rps_per_user`` (see :meth:`users_for`) — a *rate-scaled*
    pool, not a fixed count. Fixed counts fail both ways: too few users cannot
    offer a high rate (a false generator-bound plateau), too many inflate p99
    with idle-greenlet queueing (measuring the generator, not the RS). A constant
    per-user pace keeps latency server-reflective at every rung. The runner walks
    ``start_rps → stop_rps`` in ``step_rps`` increments and stops at the first
    step that breaches (goodput plateau, p99 ceiling, or error budget), recording
    the last sustained step as the knee.

    Attributes:
        start_rps: First offered arrival rate (req/s).
        stop_rps: Last offered arrival rate; the ladder never exceeds it.
        step_rps: Arrival-rate increment between steps.
        step_seconds: How long to hold each step (>= a few seconds for a stable
            percentile sample).
        rps_per_user: Constant per-user arrival rate; the pool is sized to the
            target so pacing (hence measured latency) stays comparable across the
            ladder. ~40 rps/user was diagnosed as the co-located sweet spot.
        min_users: Floor on the pool so low rungs still have a few users.
        sustain_ratio: A step is goodput-saturated (plateau) when achieved RPS
            drops below ``sustain_ratio * target_rps`` — the primary,
            machine-independent knee signal (one core has a finite verify rate).
        max_p99_ms: Optional p99 latency ceiling; exceeding it breaches the step.
        max_error_rate: Unexpected-status fraction that breaches the step.
    """

    start_rps: int
    stop_rps: int
    step_rps: int
    step_seconds: float = 4.0
    rps_per_user: float = 40.0
    min_users: int = 4
    sustain_ratio: float = 0.85
    max_p99_ms: float | None = None
    max_error_rate: float = 0.01

    def targets(self) -> tuple[int, ...]:
        """The arrival-rate ladder, ``start_rps`` … ``stop_rps`` inclusive."""
        return tuple(range(self.start_rps, self.stop_rps + 1, self.step_rps))

    def users_for(self, target_rps: int) -> int:
        """Paced-user pool sized to offer *target_rps* at ``rps_per_user`` each.

        Scales the pool to the rate (not a fixed count) so per-user pacing — and
        therefore measured latency — stays server-reflective across the ladder.
        """
        return max(self.min_users, ceil(target_rps / self.rps_per_user))


@dataclass(frozen=True)
class AlgCostBand:
    """A machine-independent, **coarse** tripwire on the p95 ratio of two classes.

    The ratio of two classes measured in the **same** window is machine-independent
    (both ride the same contention), unlike absolute p95. But it is a blunt
    instrument, not a verify-cost gate: end-to-end p95 is dominated by non-crypto
    overhead and reported in whole milliseconds, so the healthy ES256/RS256 ratio
    sits pinned at ~1.0 (measured) and a *subtle* verify-time regression (sub-ms)
    does not move it at all. What a modest band DOES catch is a **gross per-request
    cost asymmetry** between the two algorithm paths — e.g. one path accidentally
    doing per-request keygen or IO, adding whole milliseconds to only that class.
    It does NOT catch a subtle verify regression, nor a **common-mode** slowdown
    (both classes move together, ratio unchanged); those need absolute latency on
    the isolated runner (Track C, ``sprint-change-proposal-2026-08-19.md``). A
    coarse regression tripwire, NOT an SLO.

    Attributes:
        num: Numerator token class (e.g. ``"valid_es256"``).
        den: Denominator token class (e.g. ``"valid"``).
        lo: Inclusive lower bound on ``num_p95 / den_p95``.
        hi: Inclusive upper bound on ``num_p95 / den_p95``.
    """

    num: str
    den: str
    lo: float
    hi: float


# A pre-run hook mutating the mock OP (failure injection) before load starts.
SetupHook = Callable[["MockOP"], None]


@dataclass(frozen=True)
class Scenario:
    """One load/soak scenario (design §4).

    Attributes:
        id: Stable scenario id (``"S1"``…``"S12"``).
        title: Human-readable description.
        profile: The run profile this scenario belongs to.
        classes: Token classes blended into the replay pool.
        users: Concurrent Locust users.
        duration_seconds: How long to hold load.
        setup: Optional mock-OP failure injection applied before the run.
        steady_state: When ``True`` a class observed != its ``EXPECTED_STATUS``
            is an error; when ``False`` (active failure injection) the per-class
            status distribution is *reported* but not asserted, because the
            expected status is transient and calibrated in the ``test`` phase.
        gate: SLO gate key (design §5) or ``None`` while uncalibrated.
        workers: uvicorn worker count for the booted RS (the cross-worker
            scaling sweep boots the same ramp at 1/2/4 workers).
        ramp: An open-model arrival-rate ramp (TH-4). When set the scenario is a
            capacity/breakpoint run driven by :func:`runner.run_capacity_scenario`
            (walk arrival rate to the knee); when ``None`` it is a fixed-hold run
            driven by :func:`runner.run_scenario` (the ``users``/``duration``
            closed-loop path). The two are mutually exclusive.
        alg_cost_band: Optional machine-independent gate on a two-class p95 latency
            ratio (Track A). Set on scenarios that blend two token algorithms so a
            cost-ratio regression FAILS ``evaluate_gates`` rather than only being
            reported (e.g. S2's ES256/RS256).
        warm_all_hits: When ``True`` the measured window must serve entirely from a
            warm cache — ``evaluate_gates`` requires cache hits with no new misses
            beyond the single cold warmup (the request-count-independent invariant
            from #539). Only for warm scenarios whose classes are all cache-friendly
            (no unknown-kid/no-store injection); leave ``False`` otherwise.
        notes: What the scenario proves.
    """

    id: str
    title: str
    profile: Profile
    classes: tuple[str, ...]
    users: int = 8
    duration_seconds: float = 3.0
    setup: SetupHook | None = field(default=None, repr=False)
    steady_state: bool = True
    gate: str | None = None
    workers: int = 1
    ramp: RampSpec | None = None
    alg_cost_band: AlgCostBand | None = None
    warm_all_hits: bool = False
    notes: str = ""


def _no_store_discovery(op: MockOP) -> None:
    """S9: force the discovery document to be re-fetched on every request."""
    op.controls.discovery_cache_control = "no-store"


def _rotate_unpublished(op: MockOP) -> None:
    """S6: rotate the active signing key WITHOUT publishing it, so freshly
    minted tokens present an unknown ``kid`` until the cooldown recovers."""
    op.rotate_keys(publish=False)


def _inject_latency(op: MockOP) -> None:
    """S5: add upstream latency so a cache-miss fetch stalls the single-flight
    holder (head-of-line blocking)."""
    op.controls.latency_seconds = 0.25


def _short_ttl(op: MockOP) -> None:
    """S4: advertise the shortest cacheable TTL so a >60s soak crosses the cache
    TTL boundary and forces a single-flight refresh mid-load.

    ``max-age=60`` is the floor the cache honours (values below
    ``core.jwks_cache.MIN_CACHE_TTL_SECONDS`` are clamped up to 60s), so this is
    the tightest rollover achievable — which is why S4 is a NIGHTLY (>60s)
    scenario, not a CI-short one."""
    op.controls.discovery_cache_control = "max-age=60"
    op.controls.jwks_cache_control = "max-age=60"


# The scenario catalogue. S1, S2, S3, S6, S8 form CI_SHORT; S5/S9/S10 DIAGNOSTIC;
# S4/S7/S11/S12 NIGHTLY. Deep mid-run dynamics (S4 TTL rollover, S6 rotation
# storm, S11 soak RSS/FD trends) are calibrated in the test phase; the setup
# hooks here apply the pre-run failure-injection state each scenario needs.
SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="S1",
        title="warm RPS ceiling (valid RS256, hot cache)",
        profile=Profile.CI_SHORT,
        classes=("valid",),
        gate="warm",
        warm_all_hits=True,
        notes="find the warm p99 knee and RPS/worker with a fully hot cache",
    ),
    Scenario(
        id="S2",
        title="alg cost (RS256 vs ES256, warm)",
        profile=Profile.CI_SHORT,
        classes=("valid", "valid_es256"),
        gate="warm",
        warm_all_hits=True,
        # Coarse asymmetry tripwire: the healthy ES256/RS256 p95 ratio is pinned at
        # ~1.0 (measured), so a >3x whole-ms swing means one path is doing gross
        # per-request work the other isn't. Deliberately flake-safe, not tight; it
        # does NOT catch subtle or common-mode verify regressions (those are
        # Track C, isolated runner).
        alg_cost_band=AlgCostBand("valid_es256", "valid", 0.33, 3.0),
        notes="report AND coarsely gate the ES256/RS256 warm-validation cost ratio",
    ),
    Scenario(
        id="S3",
        title="cold stampede (empty cache, burst)",
        profile=Profile.CI_SHORT,
        classes=("valid",),
        users=16,
        gate="cold",
        notes="a burst against an empty cache must fetch discovery+JWKS once "
        "each (single-flight) — asserted via the mock-OP /_stats counters",
    ),
    Scenario(
        id="S4",
        title="TTL refresh under load (60s TTL rollover)",
        profile=Profile.NIGHTLY,
        classes=("valid",),
        duration_seconds=75.0,
        setup=_short_ttl,
        gate="cold",
        notes="over a >60s soak the min-TTL (60s) discovery/JWKS entries expire "
        "mid-load; the rollover must stay single-flight (upstream re-fetch "
        "bounded to ~1 per TTL window, not per request) and spike no errors. "
        "NIGHTLY because the 60s cache-TTL floor cannot roll over in a CI-short "
        "(~3s) window — calibrated nightly",
    ),
    Scenario(
        id="S5",
        title="provider-slowness head-of-line blocking",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        setup=_inject_latency,
        steady_state=False,
        gate="cold",
        notes="the single-flight holder retries with backoff while holding the "
        "fetch lock — bound the cohort stall, capture 503-vs-401",
    ),
    Scenario(
        id="S6",
        title="kid-rotation storm + unknown-kid flood",
        profile=Profile.CI_SHORT,
        classes=("valid", "unknown_kid"),
        setup=_rotate_unpublished,
        steady_state=False,
        gate="cold",
        notes="unknown-kid flood must recover within ~1 cooldown, cap upstream "
        "fetches, and 401 cleanly with no 500s",
    ),
    Scenario(
        id="S7",
        title="LRU thrash > 64 issuers",
        profile=Profile.NIGHTLY,
        classes=("valid",),
        duration_seconds=10.0,
        gate="warm",
        notes="bounded memory under > 64 distinct issuers; eviction purges the "
        "single-flight sidecar (calibrated nightly)",
    ),
    Scenario(
        id="S8",
        title="rejection correctness & uniformity under contention",
        profile=Profile.CI_SHORT,
        classes=MIXED_CLASSES,
        users=16,
        gate="warm",
        notes="every class returns its correct status under contention, F-18 "
        "uniform 401 body, F-07 reject, F-02 reject, ZERO 500s",
    ),
    Scenario(
        id="S9",
        title="discovery no-store (re-fetch every request)",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        setup=_no_store_discovery,
        steady_state=False,
        gate="cold",
        notes="no-store discovery collapses throughput (re-fetch per request) "
        "while JWKS stays cached",
    ),
    Scenario(
        id="S10",
        title="blocking claims_validator (event-loop stall) — DEFERRED BACKLOG",
        profile=Profile.DIAGNOSTIC,
        classes=("valid",),
        steady_state=False,
        gate="warm",
        notes="DEFERRED BACKLOG, de-scoped from the S1-S12 coverage matrix "
        "(sprint-change-proposal-2026-08-19): proving a synchronous custom claims "
        "validator stalls the loop (vs an async one) needs a blocking validator "
        "wired into the RS app — a separate feature, not yet implemented. "
        "DIAGNOSTIC-only, never gated; drives no assertion. Do NOT treat as "
        "coverage.",
    ),
    Scenario(
        id="S11",
        title="RSS / FD soak",
        profile=Profile.NIGHTLY,
        classes=("valid",),
        duration_seconds=30.0,
        gate="warm",
        notes="flat RSS/FD for a single issuer; bounded churn at 64 issuers "
        "(calibrated nightly)",
    ),
    Scenario(
        id="S12",
        title="multi-tenant + issuer mix-up",
        profile=Profile.NIGHTLY,
        classes=("valid", "wrong_iss"),
        gate="warm",
        notes="dct/tenants LRU survival (TH-2.1) + RFC 9207 cross-issuer "
        "rejection (TH-2.2) under load (calibrated nightly)",
    ),
    # --- Capacity / breakpoint (TH-4) ---------------------------------------
    # These do NOT hold a fixed load: their ``ramp`` walks the arrival rate up
    # until the single-worker RS stops keeping up. The recorded knee is where a
    # co-located run saturates — a DIRECTIONAL ceiling + regression signal, not
    # the RS's absolute isolated limit (which needs a deployed target). Stop is
    # 8000 rps so a 1-worker CPython RS256 verifier plateaus well inside the
    # ladder; the runner stops early at the first breach, so the ladder length
    # bounds — not fixes — the run time.
    Scenario(
        id="C1",
        title="warm ramp-to-breakpoint (valid RS256, hot cache)",
        profile=Profile.CAPACITY,
        classes=("valid",),
        gate="warm",
        workers=1,
        ramp=RampSpec(start_rps=500, stop_rps=8000, step_rps=500, max_error_rate=0.02),
        notes="warm the cache, then ramp arrival rate to the goodput knee; "
        "records max-sustainable RPS + p99 at the knee for one worker",
    ),
    Scenario(
        id="C2",
        title="cold ramp-to-breakpoint (empty cache at ramp start)",
        profile=Profile.CAPACITY,
        classes=("valid",),
        gate="cold",
        workers=1,
        ramp=RampSpec(start_rps=500, stop_rps=8000, step_rps=500, max_error_rate=0.02),
        notes="no warmup: the first step pays discovery+JWKS single-flight, then "
        "the ramp finds the knee — a lower knee than C1 quantifies cold cost",
    ),
)

# id -> Scenario, for lookup by the runner and tests.
SCENARIOS_BY_ID: dict[str, Scenario] = {s.id: s for s in SCENARIOS}


def profile_scenarios(profile: Profile) -> list[Scenario]:
    """The scenarios that belong to *profile*, in catalogue order."""
    return [s for s in SCENARIOS if s.profile is profile]


def worker_scaling_scenarios(
    base: Scenario, worker_counts: tuple[int, ...]
) -> list[Scenario]:
    """Derive one ramp scenario per worker count for the cross-worker sweep.

    The scaling sweep re-runs the *same* ramp at 1/2/4 workers to show goodput
    scales with cores (design §5/§10: expect >= ~0.8x linear until the box's own
    cores saturate). Requires ``base.ramp`` — a fixed-hold scenario has no ramp
    to sweep. Each variant's id is suffixed ``-w<N>`` so results stay distinct.
    """
    if base.ramp is None:
        raise ValueError(f"{base.id}: worker sweep needs a ramp scenario")
    return [
        replace(base, id=f"{base.id}-w{n}", workers=n, title=f"{base.title} [{n}w]")
        for n in worker_counts
    ]
