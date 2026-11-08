# Load / Soak Suite (TH-1.5)

A Locust-driven load and soak harness for the token-validation stack (#474, epic
#462, design §4/§5). It swarms the booted `fastapi-identity-model` resource
server (RS) with a **pre-minted token pool** — mint each token class once, replay
it many times — because real IdPs rate-limit per-request minting while JWT
validation is stateless, so replay is valid load. Each run reports RPS, latency
percentiles, error-rate-by-class, cache-hit rate, and upstream discovery/JWKS
fetch volume.

**Split of responsibility:** pytest owns correctness and deterministic behaviour
proofs (LRU, mix-up, `private_key_jwt`); this suite owns load and soak.

## Layout

| Module | Role |
|--------|------|
| `scenarios.py` | The S1–S12 catalogue (S1–S9, S11, S12 implemented; **S10 is deferred backlog, not coverage** — see below), run profiles, and the expected-status map (authoritative profile split — see below). |
| `pool.py` | The pre-minted replay pool (mint once, replay many). |
| `locustfile.py` | A standalone Locust file the runner drives as a subprocess. |
| `runner.py` | Orchestration (fresh mock OP + booted RS per scenario), metric collection, and SLO gate evaluation. |
| `resource_sampler.py` | Samples the booted RS's process tree (master + workers) RSS/FD during a soak — the memory/descriptor-leak signal (T313). |
| `test_load_ci_short.py` | The CI-short pytest entrypoint (real Locust run over the CI_SHORT profile). |
| `test_load_nightly.py` | The NIGHTLY soak pytest entrypoint (`make test-harness-load-nightly`). |
| `test_load_capacity.py` | The CAPACITY ramp-to-breakpoint pytest entrypoint (`make test-harness-load-capacity`). |

## How to run

```bash
make test-harness-load
```

which runs the CI-short profile through a real Locust process against the booted
RS + mock OP (equivalent command, run from `py/`):

```bash
uv run --group load --all-packages pytest src/tests/load/test_load_ci_short.py \
    -m integration -p no:benchmark -v
```

Two things make the invocation non-obvious:

- **`load` dependency group.** Locust lives in the opt-in `load` group
  (`uv run --group load …`), not the root test dependencies. Locust pulls in
  gevent, which monkey-patches the stdlib, so it must stay out of the default
  environment. The suite skips cleanly (`importlib.util.find_spec("locust")`)
  when the group is not installed.
- **Locust runs OUT of process.** The runner drives Locust as a `subprocess`
  (`locust --headless -f locustfile.py`) and **never imports it in-process**.
  Importing locust triggers gevent's `monkey.patch_all()`, which deadlocks the
  parent's in-process asyncio mock-OP server thread. Keeping Locust in its own
  process isolates gevent's patched world; the pre-minted pool and the run
  summary cross the process boundary as JSON files.

Each scenario runs against a **fresh** mock OP + RS, so caches start empty and no
failure-injection state bleeds across scenarios.

### Nightly / on-demand profiles

`make test-harness-load-nightly` runs the NIGHTLY soak profile (S4/S7/S11/S12)
via `test_load_nightly.py`; it is scheduled daily by the `load-soak` job in
`.github/workflows/nightly.yml` (#271). The DIAGNOSTIC profile has no make
target or test entrypoint — run it (or any profile) directly via `run_profile`
from `py/`:

```bash
uv run --group load --all-packages python -c \
  'from src.tests.load.runner import run_profile; from src.tests.load.scenarios import Profile; \
   [print(r) for r in run_profile(Profile.DIAGNOSTIC)]'
```

## Profile split

Scenarios are grouped into three run profiles. The authoritative assignment lives
in `scenarios.py`; this table mirrors it.

| Profile | Scenarios | Purpose |
|---------|-----------|---------|
| **CI_SHORT** | S1, S2, S3, S6, S8 | The PR gate: short (~3s), deterministic, mock-OP-backed, self-contained (no Docker). |
| **DIAGNOSTIC** | S5, S9, S10 | Head-of-line / no-store / blocking-validator probes, run on demand. |
| **NIGHTLY** | S4, S7, S11, S12 | TTL-refresh / LRU-thrash / RSS-FD soak / multi-tenant runs, scheduled nightly (`make test-harness-load-nightly`, #271). |
| **CAPACITY** | C1, C2 | TH-4 open-model ramp-to-breakpoint: walk arrival rate to the goodput knee. Nightly (`make test-harness-load-capacity`). Fixed-hold scenarios above never ramp. |

| ID | Title | Profile | Proves |
|----|-------|---------|--------|
| S1 | warm RPS ceiling (valid RS256, hot cache) | CI_SHORT | warm p99 knee + RPS/worker with a fully hot cache |
| S2 | alg cost (RS256 vs ES256, warm) | CI_SHORT | the ES256/RS256 warm-validation cost ratio |
| S3 | cold stampede (empty cache, burst) | CI_SHORT | single-flight: a cold burst fetches discovery + JWKS once each |
| S4 | TTL refresh under load (60s TTL rollover) | NIGHTLY | mid-load TTL rollover stays single-flight, spikes no errors |
| S5 | provider-slowness head-of-line blocking | DIAGNOSTIC | bounded cohort stall while the single-flight holder retries |
| S6 | kid-rotation storm + unknown-kid flood | CI_SHORT | unknown-kid flood recovers within ~1 cooldown, caps upstream fetches, 401s cleanly |
| S7 | LRU thrash > 64 issuers | NIGHTLY | bounded memory under > 64 distinct issuers |
| S8 | rejection correctness & uniformity under contention | CI_SHORT | every class returns its correct status, uniform 401 body, zero 500s |
| S9 | discovery no-store (re-fetch every request) | DIAGNOSTIC | no-store discovery collapses throughput while JWKS stays cached |
| S10 | blocking claims_validator (event-loop stall) | DIAGNOSTIC | **DEFERRED BACKLOG — not implemented, excluded from coverage** (see below) |
| S11 | RSS / FD soak | NIGHTLY | flat RSS/FD for a single issuer — sampled via `resource_sampler.py`, asserted bounded (T313) |
| S12 | multi-tenant + issuer mix-up | NIGHTLY | tenant LRU survival + RFC 9207 cross-issuer rejection under load |
| C1 | warm ramp-to-breakpoint (hot cache) | CAPACITY | warm goodput knee + max-sustainable RPS / worker |
| C2 | cold ramp-to-breakpoint (empty cache) | CAPACITY | cold-cache knee; the C1↔C2 gap quantifies cold cost |

Two placement notes:

- **S4 is NIGHTLY-only.** The cache enforces a hard 60s minimum TTL
  (`core.jwks_cache.MIN_CACHE_TTL_SECONDS`), so a genuine TTL rollover cannot
  happen inside a ~3s CI-short window — S4 needs a >60s run.
- **S10 is deferred backlog, not coverage.** Proving a synchronous custom claims
  validator stalls the event loop needs a blocking validator wired into the RS
  app — a separate feature that does not exist yet. S10 is therefore **de-scoped
  from the S1–S12 coverage matrix** (11 scenarios are implemented) and kept only
  as a tracked backlog marker: DIAGNOSTIC-only, never gated, drives no assertion.
  Implementing it requires a blocking-validator RS app + a scenario that asserts
  the loop stall vs an async validator. Do **not** treat it as coverage.

## Capacity / breakpoint (TH-4)

Every S1–S12 scenario holds a **fixed** load and reports a settled number — good
for correctness and regression, useless for "where does it fall over?" A fixed
closed-loop generator self-throttles as latency rises, hiding the knee. The
CAPACITY profile answers the capacity question with an **open-model ramp**:

```bash
make test-harness-load-capacity   # C1 (warm) + C2 (cold), real booted RS
```

- **Open model, not closed loop.** Each rung offers a *target arrival rate* by
  pacing users at a constant `rps_per_user` (Locust `constant_throughput`) and
  sizing the pool to the rate (`RampSpec.users_for`). A fixed user count fails
  both ways — too few can't offer high rates (a false generator-bound plateau),
  too many inflate p99 with idle-greenlet queueing (measuring the generator, not
  the RS). ~40 rps/user is the diagnosed co-located sweet spot.
- **Knee detection.** The runner walks `start_rps → stop_rps` against the *same*
  warm RS and stops at the first rung that breaches. The primary, machine-
  independent signal is a **goodput plateau**: achieved RPS falling below
  `sustain_ratio × target` means one CPython worker hit its finite verify rate.
  A p99 ceiling and error budget are the secondary breaches. The last sustained
  rung is the knee (`max_sustainable_rps`, `knee_p99_ms`); `render_capacity_report`
  emits the full curve.
- **Cross-worker sweep.** `worker_scaling_scenarios(base, (1, 2, 4))` re-runs a
  ramp at N workers to show goodput scales with cores.

**These numbers are DIRECTIONAL, not absolute.** The generator, the in-process
mock OP, and the RS share one runner, so the knee is where *that co-located
config* saturates — a real ceiling relative to itself and a solid regression
signal, but **not** the RS's isolated limit. That needs a deployed target (RS as
a real service, distributed generator over a network), which is out of scope
here. Every report line says so.

The nightly `load-capacity` job runs on the **free** GitHub-hosted `ubuntu-latest`
(4-vCPU/16GB on this public repo) and **uploads the ramp curve as a
`capacity-report` artifact** for trend-tracking. No paid larger runner is
used — directional-on-free is the accepted trade-off; a true isolated ceiling
would need the deployed-target lab above, not a bigger CI box.

## Calibrated SLO baseline

The numbers below are measured from a DoD Locust run of `run_profile(CI_SHORT)`
with 1 worker (mock OP + booted RS, no Docker). They are the baseline the SLO
gates are calibrated against.

| Scenario | req | fail | RPS | p50 | p95 | p99 | 5xx | upstream fetches |
|----------|-----|------|-----|-----|-----|-----|-----|------------------|
| S1 warm RPS ceiling (valid RS256) | 4755 | 0 | 1644.6 | 4ms | 7ms | 10ms | 0 | 0 (all cache hits) |
| S2 alg cost (RS256 vs ES256) | 4488 | 0 | 1553.4 | 4ms | 7ms | 9ms | 0 | 0 |
| S3 cold stampede (single-flight) | 4676 | 0 | 1618.2 | 8ms | 13ms | 24ms | 0 | discovery=1, jwks=1 (coalesced) |
| S6 kid-rotation storm | 6049 | 0 | 2088.3 | 3ms | 7ms | 13ms | 0 | discovery=1, jwks=8 (~1/cooldown) |
| S8 rejection uniformity under contention | 6568 | 0 | 2273.1 | 5ms | 14ms | 19ms | 0 | discovery=0, jwks=2 |

**Headline:** warm p99 ~9–10ms, cold-stampede p99 ~24ms, RPS/worker
~1550–2270, and **zero 5xx / zero unexpected failures** across every scenario.
S3 proves single-flight directly: 4676 concurrent cold requests coalesce to
exactly **1** discovery + **1** JWKS upstream fetch.

### Gate model: invariant (A) vs reported (B) vs isolated-runner SLO (C)

The suite
gates on what is **mechanically stable** on the co-located shared runner and only
*reports* what is not. Absolute p99/RPS on a box that shares cores between the
generator, mock OP, and RS are contention noise, so they are never a shared-CI
pass/fail.

**Track A — invariant gates** (fail a shared-CI build; machine-independent; asserted
today; never flake on runner noise):

| Gate | Rule |
|------|------|
| 5xx count | `== 0` (hard) |
| steady-state status-correctness | every class returns its expected 200/401/403; expected 401/403 rejections stay out of the error budget |
| single-flight | cold-stampede upstream fetches `== 1` discovery + 1 JWKS per issuer (S3) |
| warm-all-hits | S1/S2 measured window adds no miss beyond the cold warmup, hits > 0 (`evaluate_gates`; #539 form) |
| S2 alg-cost ratio | ES256/RS256 p95 ratio within a **coarse** band `[0.33, 3.0]` — a ratio is machine-independent (healthy is pinned ~1.0), so this catches a **gross per-request cost asymmetry** (e.g. one path doing per-request keygen/IO), NOT a subtle or common-mode verify regression (those are Track C — end-to-end p95 is ms-quantised and overhead-dominated) |

**Track B — reported, not gated** (uploaded as artifacts; never a shared-CI pass/fail):
absolute RPS, p50–p999 latency, the capacity knee, and the RSS/FD trend. Their
absolute values are directional on a co-located box, so they live in the smoke /
capacity / soak report artifacts for review and trend — not in a threshold.

**Track C — absolute SLO gates** (isolated runner only; **T314b → TH-4.5**): the
`runner.GATES` (`max_p99_ms`/`min_rps`/`max_error_rate`/`min_cache_hit_rate`) stay
**dormant** (`None`) on shared CI *by design* — they are populated only from a
baseline on an owner-provisioned isolated runner, where absolute numbers are
trustworthy. The proposed starting bars below are headroomed from the co-located
baseline above and are **directional only** until then:

| Proposed bar (Track C — isolated runner) | Target |
|------|--------|
| warm `max_p99` | ≤ 50ms |
| cold-stampede `max_p99` | ≤ 200ms |
| min RPS | ≥ 800 / worker |
| max error-rate | ≤ 0.001 (0.1%) — excludes expected 401s |
| min cache-hit-rate | ≥ 0.99 (read at `workers=1`) |

## Soak RSS/FD instrumentation (T313)

The soak scenarios (S4, S7, S11, S12) exist to prove the middleware's caches are
**bounded** — a long run against many issuers must not leak memory or file
descriptors. That claim needs a measurement, so the fixed-hold path
(`run_scenario`) samples the booted RS's process tree while the scenario runs and
attaches the trend to `LoadResult.resources` (a `ResourceSample`).

- **Whole tree, not one PID.** `boot_rs` runs uvicorn with `--workers N`, so the
  request handlers are child processes; `sample_process_tree` sums the master and
  its recursive children. `boot_rs_process` exposes the master PID (`boot_rs`
  stays a thin URL-only wrapper for the ~dozen callers that don't need it).
- **Growth, not an absolute ceiling.** The signal is `rss_growth_mb` /
  `fd_growth` (peak − start) over the window. A delta is machine-independent — a
  real leak grows on any box — whereas an absolute RSS number depends on the
  interpreter build. The nightly test asserts each soak (a) actually captured a
  continuous trend (≥2 live samples — the mechanical proof S11 now measures
  something) and (b) stayed under a generous growth ceiling (the leak tripwire).
- **Capacity ramps skip it.** A ramp changes offered load each rung, so a
  whole-run RSS/FD trend is not its breakpoint signal; only the fixed-hold soaks
  are sampled.

The growth ceilings are intentionally generous (catch a runaway leak, not arena
churn) — a Track-A tripwire, not a calibrated bound. Precise per-scenario
thresholds calibrated from a baseline are **T314b** on the isolated runner (the
dormant `runner.GATES`, Track C); T313 establishes the signal.

## Metrics sources

- **Latency / RPS / per-class p50-p99** — Locust's own aggregate + per-class
  stats, serialised from `locustfile.py`.
- **Cache-hit rate** — scraped from the RS `/metrics` endpoint (the per-process
  `get_cache_counters()` snapshot). Read at `workers=1` for an exact rate; across
  `--workers N` each worker keeps its own counters, so aggregate externally.
- **Upstream fetches per issuer** — the mock OP's in-process `/_stats` counters,
  reset after any warmup so the measured window is clean. These are the
  authoritative single-flight proof.
- **RSS / FD trend** — `resource_sampler.py` samples the RS process tree (master
  + workers) on a background thread over the soak window; `LoadResult.resources`
  carries start/peak/end RSS (MB) and FD counts. The leak signal is the growth
  delta.
