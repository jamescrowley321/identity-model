You are in a self-referential implementation loop. Each iteration you execute ONE phase of ONE task, then end your response. The loop gives you a fresh context each iteration — persist all state to files.

## Context

Target repo: `identity-model` at `~/repos/auth/identity-model` (private, `jamescrowley321/identity-model`).

This loop implements the **Rust Core Tier** (Epic 4, stories 4.2–4.6) of the multi-language identity-model OIDC/OAuth2 client library. Story 4.1 (scaffolding) already shipped **and is merged to `main`** — `rust/` has `Cargo.toml`, `src/lib.rs`, per-module stubs (`src/discovery/mod.rs`, `src/jwks/mod.rs`, `src/jwt/mod.rs`, `src/token/mod.rs`, `src/userinfo/mod.rs`), `src/error.rs` (`IdentityError`), `tests/scaffolding.rs`, and `examples/basic_setup.rs`; it builds clean. Each story fills in one module idiomatically and proves parity against the cross-language conformance spec in `spec/` and the shared provider in `infra/`. This mirrors the completed Go core tier (`go/pkg/*`) — read those packages for the reference behavior.

Epic source of truth: `~/repos/auth/identity-stack-planning/_bmad-output/planning-artifacts/epics/epic-4-core-rust.md`
Cross-language contract: `spec/capabilities.md` + `spec/conformance/*.json` (read from the per-task worktree — see below).

## Running

Run the loop from a **dedicated orchestrator worktree in `/tmp`**, never from `~/repos/auth/identity-model` — the owner works in that checkout by hand, so the loop must stay isolated from it. `PROMPT.md` and `.claude/task-state.md` live in the orchestrator worktree for the whole run.

```bash
# One-time: create the orchestrator worktree off main.
# The 4.1 scaffold (rust/, spec/, infra/, ralph.yml, Makefile) is already on main.
cd ~/repos/auth/identity-model
git fetch origin
git worktree add /tmp/im-rust-orch -b ralph/rust-core origin/main

# Run the loop from inside that worktree
cd /tmp/im-rust-orch
cp ~/repos/auth/identity-stack-planning/_bmad-output/implementation-artifacts/ralph-prompts/identity-model-rust-core.md PROMPT.md
ralph run
```

`ORCH_WORKTREE` = `/tmp/im-rust-orch`. The prompt must remain copied in as `PROMPT.md` for the whole run (ralph re-reads it from CWD each iteration); the planning-repo copy is the source of truth. The orchestrator worktree only hosts the loop — per-task implementation happens in its own `/tmp/im-rust-4X` worktree (created by `setup`) off the task's base branch. When the loop finishes, remove it: `cd ~/repos/auth/identity-model && git worktree remove /tmp/im-rust-orch`.

## CRITICAL: No Auto-Merge

**DO NOT merge any PR.** The owner manually reviews and merges every PR this loop creates. The `complete` phase must NOT call `gh pr merge` — no `--auto`, no merge queue. Only mark the task done, clean up, and move on.

## Dependency Model — Base-Branch Chaining

The Rust modules build on each other (jwt needs jwks; token/userinfo need discovery types). Because PRs are NOT auto-merged, each task branches off the **previous task's branch**, not `main`, and opens its PR with `--base <previous_branch>`. This produces a clean reviewable stack the owner merges bottom-up. The 4.1 scaffold is already on `main`, so the first task (R4.2) bases off `main`. Per the Step 3 rule, once a base branch has been merged to `main`, later tasks MAY base off `main` instead — so this self-corrects as the owner lands the stack.

## Task Queue

| Task | Story | Branch | Base branch | Description | Status |
|------|-------|--------|-------------|-------------|--------|
| R4.2 | 4.2 | feat/rust-discovery | main | OIDC Discovery client — `src/discovery`: async fetch + validate + TTL cache (`tokio::sync::RwLock`) | pending |
| R4.3 | 4.3 | feat/rust-jwks | feat/rust-discovery | JWKS client + key resolution — `src/jwks`: fetch, cache, resolve by kid, forced refresh (RSA + EC) | pending |
| R4.4 | 4.4 | feat/rust-jwt | feat/rust-jwks | JWT validation — `src/jwt`: signature + registered claims, alg=none reject, nonce, clock skew | pending |
| R4.5 | 4.5 | feat/rust-token | feat/rust-jwt | Client credentials + auth code + PKCE — `src/token` | pending |
| R4.6 | 4.6 | feat/rust-userinfo | feat/rust-token | UserInfo endpoint — `src/userinfo`: fetch claims + sub consistency | pending |

## Step 1: Determine Context

1. Read `~/repos/auth/CLAUDE.md` for workspace commands and git conventions.
2. Read `~/repos/auth/identity-model/CONTRIBUTING.md` for repo workflow (branching, conventional commits, conformance loop).
3. Read `~/repos/auth/identity-stack-planning/_bmad-output/planning-artifacts/epics/epic-4-core-rust.md` for the story acceptance criteria.

## Step 2: Determine What To Do

Read `ORCH_WORKTREE/.claude/task-state.md` (i.e. `/tmp/im-rust-orch/.claude/task-state.md`).

- **Does not exist** → Pick up next task (Step 3).
- **phase is `complete`** → Mark the task `done` in the queue in THIS file, clean up the worktree, delete task-state.md, pick up next task (Step 3).
- **Any other phase** → Execute that one phase (Step 4).

## Step 3: Pick Up Next Task

Find the first `pending` row in the Task Queue.

- If none remain → output: <promise>LOOP_COMPLETE</promise>
- Otherwise:
  1. Determine the base branch from the queue's "Base branch" column. If that base branch's PR has already been merged to `main`, you MAY base off `main` instead (cleaner). Otherwise base off the branch as listed.
  2. Create `ORCH_WORKTREE/.claude/task-state.md` (`/tmp/im-rust-orch/.claude/task-state.md`):
     ```
     task_id: R4.X
     story: 4.X
     repo: identity-model
     branch: <branch from queue>
     base_branch: <base branch from queue>
     worktree: /tmp/im-rust-4X
     phase: setup
     ```
  3. Execute the `setup` phase, then end your response.

## Step 4: Execute ONE Phase

Read `phase` from task-state.md. Execute ONLY that phase. When done, update the `phase` field to the next phase and end your response.

**All work after `setup` happens in the worktree** — `cd` to the `worktree:` path first.

Phase order: `setup → analyze → implement → test → review → review-fix → pr → ci → complete`

Read the shared phase file for each phase from:
`~/repos/auth/identity-stack-planning/_bmad-output/implementation-artifacts/ralph-prompts/phases/<phase>.md`

### Phase overrides

**setup** — Follow `phases/setup.md`. Repo root `~/repos/auth/identity-model`. Create the worktree off `base_branch`: `git worktree add -b <branch> <worktree> <base_branch>` (fetch first). All Rust work happens in `<worktree>/rust`.

**analyze** — Follow `phases/analyze.md`, plus:
1. Read the matching story section in `epic-4-core-rust.md` — every acceptance-criteria checkbox is a requirement.
2. Read the conformance definition for this capability in `<worktree>/spec/conformance/*.json` and the fixtures in `<worktree>/spec/test-fixtures/`. **All six core conformance files already exist** (`discovery.json`, `jwks.json`, `validation.json`, `client-credentials.json`, `authorization-code.json`, `userinfo.json`) — do NOT author new conformance JSON; your job is to make Rust satisfy the existing IDs. Map each ID to a Rust test.
3. Read the **completed Go package** for this capability (`go/pkg/<discovery|jwks|jwt|token|userinfo>`) as the reference implementation — same conformance IDs, same provider quirks. Read the Rust scaffold: `rust/src/<module>/mod.rs`, `rust/src/error.rs` (`IdentityError` variants), `rust/src/lib.rs` re-exports, and any Rust module already implemented earlier in this stack (its patterns: builders, error variants, `tokio::sync::RwLock` cache).
4. Plan must list: exact files to create/modify, the **builder / options API surface**, unit test cases (map each to ACs + conformance IDs), and the `#[ignore]`-gated integration tests against `infra/` node-oidc-provider.

**implement** — Follow `phases/implement.md`, plus:
- Idiomatic async Rust: `reqwest` (rustls-tls, already a dep) for HTTP, `tokio` runtime, `serde`/`serde_json` for models, `thiserror` (`IdentityError`) for errors, `tokio::sync::RwLock` for the TTL caches (discovery, JWKS), **builder patterns** for client/options config (`ValidationOptions`, `TokenClient`, etc.). JWT via `jsonwebtoken` (already a dep). For PKCE use `sha2` + `base64` (add as deps).
- **Toolchain: edition 2024, MSRV = the value already in `rust/Cargo.toml` (`rust-version = "1.91"`). Do NOT downgrade to the epic's stale "1.75"** — edition 2024 requires ≥1.85 and the scaffold is already pinned higher. Keep `rustls-tls` (never default openssl).
- Add deps with `cargo add`; commit `Cargo.toml` **and** `Cargo.lock`. CI caching keys on the Rust workspace.
- `cd <worktree>/rust && cargo build && cargo clippy --all-targets -- -D warnings && cargo fmt --check` clean before every commit (fix formatting with `cargo fmt`). Never `git add .` — add specific files.
- As each capability's conformance passes, flip its **Rust** column from `planned` → `implemented` in `<worktree>/spec/capabilities.md`.
- Conventional commits: `feat(rust): <description>`.

**test** — Follow `phases/test.md`, plus:
- Unit tests under `#[cfg(test)]` cover every AC and reference the conformance IDs in a comment (e.g. `// DISC-003`). Use `#[tokio::test]` for async cases; mock HTTP with a dev-dependency (`wiremock` or `mockito` — add to `[dev-dependencies]`). Use RFC 7636 Appendix B vectors for PKCE S256.
- **Integration tests live in `rust/tests/<capability>.rs` and MUST be marked `#[ignore]`.** The unit `rust` CI job runs bare `cargo test` with **no provider running** — un-ignored provider-dependent tests would fail it. `#[ignore]` keeps that job green, while the dedicated **`rust-integration` CI job** (compose up node-oidc → `make test-integration-rust`, i.e. `cargo test -- --ignored`) actually runs them. They gate the `conformance` job, so they MUST pass.
- Read provider config from env, reusing the repo's `TEST_*` convention (the `.env.node-oidc` profile the Makefile sources): `TEST_DISCO_ADDRESS` (derive `jwks_uri` / `token_endpoint` / `userinfo_endpoint` from the fetched discovery doc — there is no separate `TEST_JWKS_ADDRESS` locally), `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET`, `TEST_SCOPE`, `TEST_PKCE_PUBLIC_CLIENT_ID`, `TEST_REDIRECT_URI`. Skip gracefully if `TEST_DISCO_ADDRESS` is unset.
- Run integration locally: `make infra-up` (node-oidc :9000 + IdentityServer :9001) then `make test-integration-rust` (or `cd rust && cargo test -- --ignored`); `make infra-down` after.
- `cargo test` (unit, no `--ignored`) must pass before pushing.

**review** — Follow `phases/review.md`. Reviewers: **Blind Hunter + Edge Case Hunter + Acceptance Auditor** (templates in `ralph-prompts/review-agents/`). Acceptance Auditor must verify every story AC and conformance ID is covered.

**review-fix** — Follow `phases/review-fix.md`. No overrides.

**pr** — Follow `phases/pr.md`, plus:
- Repo `jamescrowley321/identity-model`. **Open with `--base <base_branch>`** (the chained parent, not main, unless the parent is already merged).
- Title: `feat(rust): <description>`. Body lists the story, ACs covered, conformance IDs, and review summary.
- **No auto-merge flags.**

**ci** — Follow `phases/ci.md`. Repo `jamescrowley321/identity-model`. Max 3 CI fix attempts. Three gates must pass: the **`rust`** job (`cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` + `cargo test`), the **`rust-integration`** job (local node-oidc provider), and the **`conformance`** aggregation gate.
- CI now runs on **every PR regardless of base branch** (the `pull_request` base-branch filter was removed in the pre-loop infra change), so the stacked PRs R4.3–R4.6 get full CI even before the stack lands on `main` — wait for the checks and fix them like any other task; don't proceed to `complete` on red.
- The `changes` paths-filter only runs the `rust` / `rust-integration` jobs when `rust/**` (or shared `spec/` / `infra/`) changed; your PRs touch `rust/`, so both run.

**complete** — **OVERRIDE: do NOT merge the PR.**
1. Mark the task `done` in the queue in THIS file.
2. `cd ~/repos/auth/identity-model && git worktree remove <worktree> --force`
3. Delete `.claude/task-state.md`.
4. Output: <promise>TASK COMPLETE</promise>

## Rules

- Execute ONE phase per iteration, then end — fresh context prevents drift.
- NEVER commit to `main`; always feature branches in worktrees. (Do not rely on a git hook; the worktree-per-task model is what keeps `main` clean.)
- All work after setup happens in the worktree.
- Follow the conformance spec in `spec/` — implementation must satisfy the existing conformance IDs, not just compile. Do NOT author new conformance JSON (all six core files already exist).
- Idiomatic async Rust: `reqwest`+`rustls`, `tokio`, `serde`, `thiserror`, builder patterns, `tokio::sync::RwLock` caches. Edition 2024, MSRV per `Cargo.toml` (do not downgrade).
- Conventional commits (`feat(rust):` / `test(rust):` / `fix(rust):`).
- Run `cargo build && cargo clippy --all-targets -- -D warnings && cargo fmt --check` before committing, `cargo test` before pushing.
- Integration tests are `#[ignore]`-gated so the unit `rust` job's bare `cargo test` stays green; the `rust-integration` job runs them with the provider up.
- If stuck 3+ iterations on the same phase: set task to `blocked`, clean up the worktree, delete task-state.md, move on.
- **NEVER merge PRs — the owner reviews and merges manually.**
