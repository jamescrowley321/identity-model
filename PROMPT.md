You are in a self-referential implementation loop. Each iteration you execute ONE phase of ONE task, then end your response. The loop gives you a fresh context each iteration — persist all state to files.

## Context

Target repo: `identity-model` at `~/repos/auth/identity-model` (private, `jamescrowley321/identity-model`).

This loop implements the **Go Core Tier** (Epic 3, stories 3.2–3.6) of the multi-language identity-model OIDC/OAuth2 client library. Story 3.1 (scaffolding) already shipped. Each story is a greenfield Go package under `go/pkg/`, implemented idiomatically and validated against the cross-language conformance spec in `spec/` and the shared provider in `infra/`.

Epic source of truth: `~/repos/auth/identity-stack-planning/_bmad-output/planning-artifacts/epics/epic-3-core-go.md`
Cross-language contract: `~/repos/auth/identity-model/spec/capabilities.md` + `spec/conformance/*.json`

## CRITICAL: No Auto-Merge

**DO NOT merge any PR.** The owner manually reviews and merges every PR this loop creates. The `complete` phase must NOT call `gh pr merge` — no `--auto`, no merge queue. Only mark the task done, clean up, and move on.

## Dependency Model — Base-Branch Chaining

The Go packages build on each other (jwt needs jwks; token/userinfo need discovery types). Because PRs are NOT auto-merged, each task branches off the **previous task's branch**, not `main`, and opens its PR with `--base <previous_branch>`. This produces a clean reviewable stack the owner merges bottom-up. The first task (G3.2) bases off `main`.

## Task Queue

| Task | Story | Branch | Base branch | Description | Status |
|------|-------|--------|-------------|-------------|--------|
| G3.2 | 3.2 | feat/go-discovery | main | OIDC Discovery client — `pkg/discovery`: fetch + validate + TTL cache + singleflight | pending |
| G3.3 | 3.3 | feat/go-jwks | feat/go-discovery | JWKS client + key resolution — `pkg/jwks`: fetch, cache, resolve by kid, forced refresh | pending |
| G3.4 | 3.4 | feat/go-jwt | feat/go-jwks | JWT validation — `pkg/jwt`: signature + registered claims, alg=none reject, nonce | pending |
| G3.5 | 3.5 | feat/go-token | feat/go-jwt | Client credentials + auth code + PKCE — `pkg/token` | pending |
| G3.6 | 3.6 | feat/go-userinfo | feat/go-token | UserInfo endpoint — `pkg/userinfo`: fetch claims + sub consistency | pending |

## Step 1: Determine Context

1. Read `~/repos/auth/CLAUDE.md` for workspace commands and git conventions.
2. Read `~/repos/auth/identity-model/CONTRIBUTING.md` for repo workflow (branching, conventional commits, conformance loop).
3. Read `~/repos/auth/identity-stack-planning/_bmad-output/planning-artifacts/epics/epic-3-core-go.md` for the story acceptance criteria.

## Step 2: Determine What To Do

Read `~/repos/auth/identity-model/.claude/task-state.md`.

- **Does not exist** → Pick up next task (Step 3).
- **phase is `complete`** → Mark the task `done` in the queue in THIS file, clean up the worktree, delete task-state.md, pick up next task (Step 3).
- **Any other phase** → Execute that one phase (Step 4).

## Step 3: Pick Up Next Task

Find the first `pending` row in the Task Queue.

- If none remain → output: <promise>LOOP_COMPLETE</promise>
- Otherwise:
  1. Determine the base branch from the queue's "Base branch" column. If that base branch's PR has already been merged to `main`, you MAY base off `main` instead (cleaner). Otherwise base off the branch as listed.
  2. Create `~/repos/auth/identity-model/.claude/task-state.md`:
     ```
     task_id: G3.X
     story: 3.X
     repo: identity-model
     branch: <branch from queue>
     base_branch: <base branch from queue>
     worktree: /tmp/im-go-3X
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

**setup** — Follow `phases/setup.md`. Repo root `~/repos/auth/identity-model`. Create the worktree off `base_branch`: `git worktree add -b <branch> <worktree> <base_branch>` (fetch first). All Go work happens in `<worktree>/go`.

**analyze** — Follow `phases/analyze.md`, plus:
1. Read the matching story section in `epic-3-core-go.md` — every acceptance-criteria checkbox is a requirement.
2. Read the conformance definitions for this capability in `spec/conformance/*.json` and the fixtures in `spec/test-fixtures/`.
3. Read the existing `go/pkg/<package>/doc.go` and any sibling packages already implemented (their patterns: functional options, error types, singleflight).
4. Plan must list: exact files to create/modify, the functional-options API surface, unit test cases (map each to ACs + conformance IDs), and the `integration`-tagged tests against `infra/` node-oidc-provider.

**implement** — Follow `phases/implement.md`, plus:
- Idiomatic Go: `net/http` stdlib, functional options (`WithTimeout`, `WithCacheTTL`, `WithHTTPClient`), `golang.org/x/sync/singleflight` for fetch dedup, JOSE via `go-jose/v4` or `golang-jwt/v5`.
- Add deps with `go get`; commit `go.mod`/`go.sum`. Once deps exist, CI caching keys on `go/go.sum`.
- `cd <worktree>/go && go build ./... && go vet ./... && gofmt -l .` clean before every commit. Never `git add .` — add specific files.
- Conventional commits: `feat(go): <description>`.

**test** — Follow `phases/test.md`, plus:
- Unit tests cover every AC and reference the conformance IDs (e.g. `// DISC-003`). Use RFC 7636 Appendix B vectors for PKCE.
- Integration tests behind `//go:build integration`; bring up `infra/` (`cd infra && docker compose up -d`) and run `go test -tags=integration ./...`.
- `go test ./...` (unit) must pass before pushing.

**review** — Follow `phases/review.md`. Reviewers: **Blind Hunter + Edge Case Hunter + Acceptance Auditor** (templates in `ralph-prompts/review-agents/`). Acceptance Auditor must verify every story AC and conformance ID is covered.

**review-fix** — Follow `phases/review-fix.md`. No overrides.

**pr** — Follow `phases/pr.md`, plus:
- Repo `jamescrowley321/identity-model`. **Open with `--base <base_branch>`** (the chained parent, not main, unless the parent is already merged).
- Title: `feat(go): <description>`. Body lists the story, ACs covered, conformance IDs, and review summary.
- **No auto-merge flags.**

**ci** — Follow `phases/ci.md`. Repo `jamescrowley321/identity-model`. Max 3 CI fix attempts. The `go` job (build/vet/test/golangci-lint) and the `conformance` gate must pass.

**complete** — **OVERRIDE: do NOT merge the PR.**
1. Mark the task `done` in the queue in THIS file.
2. `cd ~/repos/auth/identity-model && git worktree remove <worktree> --force`
3. Delete `.claude/task-state.md`.
4. Output: <promise>TASK COMPLETE</promise>

## Rules

- Execute ONE phase per iteration, then end — fresh context prevents drift.
- NEVER commit to `main`; always feature branches in worktrees. (A local `pre-push` hook enforces this.)
- All work after setup happens in the worktree.
- Follow the conformance spec in `spec/` — implementation must satisfy the conformance IDs, not just compile.
- Conventional commits (`feat(go):` / `test(go):` / `fix(go):`).
- Run `go build ./... && go vet ./...` before committing, `go test ./...` before pushing.
- If stuck 3+ iterations on the same phase: set task to `blocked`, clean up the worktree, delete task-state.md, move on.
- **NEVER merge PRs — the owner reviews and merges manually.**
