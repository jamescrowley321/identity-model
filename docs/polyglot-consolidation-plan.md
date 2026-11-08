# Polyglot Consolidation Plan — `identity-model` → `py-identity-model`

**Status:** Design of record. Decided 2026-08-17 (James). Supersedes the prior
"PIM into the polyglot monorepo" direction (see _Reversal_). Build orchestrator
(`moon`) validated by spike 2026-08-17.

> **Current state.** The consolidation has landed: the repo is now
> `jamescrowley321/identity-model` with `/py`, `/go`, `/rust`, `/spec`, `/infra`,
> `/conformance` (plus a placeholder `/node`), per-project `moon.yml` files and
> `.moon/`. The Go module path is `github.com/jamescrowley321/identity-model/go`.
> Two details differ from the plan below: Go and Rust are versioned by
> `python-semantic-release` (`tools/semantic-release-go.toml`,
> `tools/semantic-release-rust.toml`), not GoReleaser / `cargo-release`; and
> release routing is **scope-based** (`tools/release_parsers.py`), with
> `release.yml` path-guarding only `node/**`, `spec/**` and `infra/**`.

## Decision

Move `jamescrowley321/identity-model` (Go + Rust) **into**
`jamescrowley321/py-identity-model` (PIM). **PIM is the surviving repo** — it keeps its
git history, release tags, OIDF certification, and PyPI pipelines. `identity-model`'s
history is expendable (0 tags, never released, not prod-ready). Package naming stays
`{py,go,rs}-identity-model` at the package level.

Top-level layout is a clean per-language split — **`/py`, `/go`, `/rust`** — **not** a
root uv workspace. `moon` orchestrates the polyglot repo; each language keeps its native
toolchain (`uv`+semantic-release, `go`, `cargo`).

## Reversal — why this inverts the prior plan

The earlier decision (2026-08-01, reaffirmed 2026-08-12 in PR #72) was the opposite: move
PIM **into** `identity-model` because that repo was the purpose-built polyglot shell
(`spec/` + `infra/`). That would have moved the **certified, PyPI-published, 329-tag**
artifact into a **0-tag** shell — disrupting exactly the cert lineage + release pipelines
the same memo flagged as the thing to protect. Keeping PIM stationary as the survivor
makes OIDF cert continuity a non-issue and leaves both PyPI pipelines untouched.

### What the reversal trades away (accepted)

1. **Re-home the polyglot shell.** `identity-model`'s `spec/` neutral-vector conformance
   contract, `infra/` shared IdP fixtures, and Go/Rust CI move **into** PIM rather than
   being inherited for free. This is the real work.
2. **Go import-path break.** `github.com/jamescrowley321/identity-model/go` →
   `github.com/jamescrowley321/py-identity-model/go` (and again at the rename). Accepted
   (0 consumers, not prod); document in `go/README.md` + CHANGELOG.
3. **Stale planning artifacts.** PR #72's docs now describe the opposite direction → fixed
   in the retirement step.

## Surviving hard constraint (carried forward)

Do **not** duplicate internal conformance vectors across the three languages. Build them
**once**: language-neutral vectors + fixtures + canonical-error-code outcomes in `spec/`;
a **thin per-language executor**; a **coverage gate** (every language executes every
vector id). PIM's external OIDF-cert `conformance/` harness is a *different* (black-box)
kind of testing — keep it.

## Target layout (in `py-identity-model`)

```
/py                     # Python core moved out of root src/ ; owns uv + semantic-release
/go                     # from identity-model; module → …/py-identity-model/go
/rust                   # from identity-model; crate rs-identity-model
/spec                   # from identity-model — neutral conformance vectors (single source)
/infra                  # MERGE identity-model infra/ + PIM test-fixtures/ → one IdP fixture set
/conformance            # PIM OIDF cert harness — unchanged; identity-model rp-go folded in
.moon/                  # workspace + toolchain config (orchestration only)
moon.yml (per project)  # /py, /go, /rust each define delegating tasks
```

No root uv workspace. `pyproject.toml` and all Python packaging live under `/py`.

## Build orchestration — `moon` (validated)

`moon` sits **on top** of the native toolchains (`toolchain: 'system'` tasks that shell
out to `uv`/`go`/`cargo`); it does not replace them, which is what keeps PIM's publishing
intact. Spike (moon 2.5.1, real Py+Go+Rust projects) confirmed:

- `moon run :test` orchestrates all three in parallel.
- Content-hash **caching**: unchanged re-run served from cache.
- **Selective re-run / affected-detection**: change only `/rust` → Go+Py cached, only Rust
  re-runs; `moon ci --base <ref>` flags affected projects from the git diff.

Reference config is ~6 lines per project. Two gotchas locked in from the spike:

1. **Gitignore `.moon/cache/`** — tracked cache files poison affected-detection.
2. **Tighten Python task `inputs` to `src/**/*.py`** and gitignore `__pycache__`/`*.pyc` —
   otherwise `.pyc` churn defeats caching and shows Python as spuriously affected.

Complementary: pin toolchain versions with `.moon/toolchain.yml` (or add `mise`/`proto`
later if we want shared version pinning across contributors). Rejected alternatives:
Bazel/Pants (fight Python-wheel/PyPI + Rust; Pants Rust is experimental), Nx (Node runtime;
Go/Rust are community plugins), Turborepo (JS-centric), Earthly (OSS frozen, Cloud shut
down 2025).

## Tagging strategy (changes during the reorg)

Bare `{version}` tags (PIM's 329 existing tags) collide once three languages version
independently. New scheme — **prefixed, per-language**:

| Language | Tool | Tag format | Note |
|---|---|---|---|
| Python | `python-semantic-release` (kept) | `py-v{version}` | change `tag_format`; **seed `py-v3.10.0`** at current HEAD so the next bump computes |
| Go | GoReleaser | `go/vX.Y.Z` | **forced** — a subdir Go module only resolves from `<subdir>/vX.Y.Z` tags |
| Rust | `cargo-release` → crates.io | `rust-vX.Y.Z` | |

`python-semantic-release` stays through the reorg (keeps publishing working). Revisit
`release-please` (unifies all three as independent components, handles the Go subdir tag
format) only at/after the rename.

## Release & CI

- **Python:** existing semantic-release → PyPI, re-pointed at `/py`, `tag_format` changed.
  Path-guard so `go/**`/`rust/**`/`spec/**`/`infra/**` commits never cut a PyPI release.
- **Go / Rust:** GoReleaser / cargo-release, path-filtered.
- **CI:** `dorny/paths-filter` (or `moon ci --base`) so only affected languages run; bring
  the docker IdP fixture matrix up **once**, shared across suites.
- **Secrets:** consolidate DESCOPE mgmt key, conformance token, PyPI/crates OIDC publish.

## Migration sequence (James's ordering)

Migration mechanic is trivial — IM's blame is expendable, so bring its tree in as ordinary
new-file commits (no `git-filter-repo`/subtree).

1. **Move IM in + kill duplicated test infra.** Land `/go` + `/rust` + `/spec`; merge
   `infra/` + `test-fixtures/` into one IdP fixture set; wire Python's thin executor onto
   `spec/` vectors + coverage gate. (No reorg of Python yet.)
2. **In-place reorg + keep publishing green.** Move Python into `/py`; add `moon`
   workspace + per-project tasks; re-point `python-semantic-release` at `/py`; change the
   tag scheme (seed `py-v3.10.0`); add Go/Rust release + path-filtered CI. Verify a
   dry-run publishes exactly as today.
3. **Rename the repo + fix references.** Rename `py-identity-model`; update PyPI **Trusted
   Publishing** (OIDC is keyed to repo+workflow — the rename requires re-config), `project.urls`,
   README badges, Go module path (again), crates metadata. PyPI **project name is
   unchanged** by a repo rename. Archive `identity-model` read-only + pointer; repoint
   ralph loops/`PROMPT.md`; fix the stale PR-#72 planning artifacts.

## Sequencing vs. in-flight work

PIM `main` is quiescent (just merged #532) — a good window. `identity-model`'s Rust-Extended
loop + K3–K6 and PIM's #476 FAPI2 epic must pause/rebase onto new paths (short freeze; land
step 1–2, then relaunch pointed at `/py|/go|/rust|/spec`). PIM #462 E2E harness is largely
delivered → low collision.

## Risk register

| Risk | Mitigation |
|---|---|
| Re-homing `spec/`+`infra/`+CI is the real cost | Isolated in step 1; keep the surface small |
| Accidental PyPI release from a go/rust commit | Path-guard `release.yml`; dry-run before first real publish |
| `tag_format` change strands semantic-release's "last release" | Manually seed `py-v3.10.0` at current HEAD (owner OK'd) |
| Repo rename breaks PyPI Trusted Publishing | Re-config the OIDC publisher as part of step 3; rename last |
| Go consumers break on module-path change | None in prod (0 tags); documented |
| Active loops strand on old paths | Freeze window; relaunch against new paths after step 2 |
