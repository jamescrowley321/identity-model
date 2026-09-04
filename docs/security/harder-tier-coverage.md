# Harder-Tier Test Coverage Matrix

This is the **living coverage matrix** for Epic 23 (*Test Hardening — harder
test tiers & coverage*, issue #614). It records, per hardening story, what the
"harder tier" (integration / OIDF-conformance / E2E-harness / cross-language /
mutation) actually exercises and — for each executable artifact — whether it is
**configured, nightly-only** (report-and-upload, does not block a release) or
**release-gated** (a red result blocks the tag).

It is the human-readable companion to the mechanical gates (`make
security-gate`, the `conformance` workflow, the mutation gates). A story's cell
is only "done" when its harder-tier artifact is wired, running, and this matrix
records its gating status truthfully.

**Provenance:** each story task (T231–T237) flips its own row in the same PR
that lands the wiring. Do not mark a row `release-gated` unless the artifact is
green and its CI step has **no** `continue-on-error`.

## How to read this

| Column | Meaning |
| ------ | ------- |
| **Story** | The Epic 23 story (23.1–23.7) and its task. |
| **Tier** | The harder tier the story lands (conformance / integration / harness / cross-language / mutation). |
| **Artifact** | The make target / CI job / plan that executes it. |
| **Gating** | `release-gated` (red blocks the tag), `nightly-only` (configured, report-and-upload), or `explicit-skip` (precondition absent → loud skip, never a silent pass). |
| **Status** | `shipped` (wired + running) or `pending` (task not yet landed). |

## Story 23.1 — OIDF conformance run profiles (T231, #607)

Wires the configured-but-unrun OIDF plans into make targets + the `conformance`
workflow (nightly `schedule` + release `workflow_call`). Hosted certification
bundles are produced by `conformance-hosted.yml` (`workflow_dispatch`).

| Plan | Make target | Local suite (`conformance.yml`) | Gating | Green? |
| ---- | ----------- | ------------------------------- | ------ | ------ |
| `dynamic-rp` | `conformance-test-dynamic` | run + export + upload | **release-gated** | ✅ 10/0 (2 skip) |
| `rpinitiated-logout-rp` | `conformance-test-logout` | run + export + upload | **release-gated** | ✅ 2/0 (1 skip) |
| `fapi2-rp` | `conformance-test-fapi2` | run + export + upload | nightly-only (DEC-001) | ⚠️ 21/22 |
| `fapi2-message-signing-rp` | `conformance-test-fapi2` | run + export + upload | nightly-only (DEC-001) | ⚠️ 27/28 |
| `backchannel-logout-rp` | `conformance-test-logout` | run + export + upload | nightly-only (DEC-001) | ⚠️ 7/8 |
| `fapi2-mtls-rp` | `conformance-test-fapi2-mtls` | **explicit skip** | explicit-skip | n/a (RFC 8705 mTLS terminator not provisioned) |

**Status: shipped.** All six plans are wired; evidence (`conformance/results/*-latest.json`
+ HTML `-report.zip` + hosted `--export-zip` bundles) is uploaded `if: always()`.
The two green plans are hard release gates; the three with a single known-red leg
are report-only per **DEC-001** (below); mTLS is a loud explicit skip.

### DEC-001 — report-only until proven green (never gate a release on a red leg)

- **Decision:** a newly-wired conformance plan is only promoted to a hard release
  gate (no `continue-on-error`) once it proves **green** against the local OIDF
  suite. Until then it runs report-only: the step executes, uploads evidence, and
  emits a loud `::warning::` naming the red leg and its follow-up task, but does
  **not** block the release tag.
- **Why:** the alternative (gate on a plan with a known-red leg) would either
  block every release on a pre-existing harness bug, or pressure someone to make
  the leg "green" without fixing it — a green-theater risk. Report-only keeps the
  signal honest and loud while the real fix is tracked, and never silent-passes.
- **Applies to (2026-09-03 local OIDF run):**
  - `fapi2-rp` (21/22) and `fapi2-message-signing-rp` (27/28) — the
    `invalid-alternate-alg` negative test is INTERRUPTED: the RP-harness
    alg-rejection flow does not drive that leg to a verdict. Tracked as
    `fix:conformance-fapi2-invalid-alt-alg`.
  - `backchannel-logout-rp` (7/8) — `rpinitlogout-wrong-alg` expects the
    `backchannel_logout_uri` to return **400** for a wrong-alg logout token; the
    harness returns a non-400. Tracked as `fix:conformance-backchannel-wrong-alg`.
- **Known limitation (tracked follow-up):** `continue-on-error` is applied at the
  **plan** granularity, so it also un-gates the *other* (currently passing)
  FAPI-specific negative tests in the two `fapi2-*` plans (alg:none rejection,
  `invalid-iss` / `invalid-aud` / `invalid-nonce`, JARM signature/iss/aud/exp). A
  regression in those would report `FAILED` in the nightly run but would not block
  a release tag. Core alg:none / kty / audience validation *is* separately
  release-gated by `basic-rp` + the `src/tests/security/` unit suite, so only the
  FAPI-specific surface is exposed. Narrowing the tolerance to the single
  known-red leg (split the plan, or post-process the results JSON to fail on any
  `FAILED`/`INTERRUPTED` other than `invalid-alternate-alg`) is tracked as
  `fix:conformance-fapi2-narrow-report-only`.
- **Reversibility:** trivial — delete the `continue-on-error: true` line on a plan
  once its follow-up fix lands and it proves green, and flip its **Gating** cell
  above to `release-gated`.

## Stories 23.2–23.7 — pending

| Story | Task | Tier | Artifact | Gating | Status |
| ----- | ---- | ---- | -------- | ------ | ------ |
| 23.2 — executable spec vectors | T232 (#608) | cross-language conformance | `tools/spec_coverage_gate.py` + py/go/rust runners | (tbd) | pending |
| 23.3 — middleware auth-bypass harness | T233 (#609) | E2E harness | booted-RS auth-bypass regressions | (tbd) | pending |
| 23.4 — discovery-policy rotation harness | T234 (#610) | E2E harness | `mock_op.py` key-rotation | (tbd) | pending |
| 23.5 — Go/Rust RS harness | T235 (#611) | cross-language harness | `make test-harness-{go,rust}` | (tbd) | pending |
| 23.6 — cross-language mutation gates | T236 (#612) | mutation | mutmut / `cargo-mutants` / `gremlins` | (tbd) | pending |
| 23.7 — cross-language provider breadth | T237 (#613) | integration | Rust Keycloak/IdentityServer + Python IdentityServer legs | (tbd) | pending |

Each row is flipped to `shipped` with its concrete artifact + gating status by
the task that lands it.
