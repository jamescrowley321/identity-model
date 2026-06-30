# Contributing to identity-model

## Workflow

- **Never commit directly to `main`.** All changes go through a feature branch and a pull request.

  > This repo is **private on a free plan**, where GitHub's server-side branch protection and rulesets are unavailable. As a local guardrail, a tracked `pre-push` hook blocks direct pushes to `main`. Enable it once after cloning:
  >
  > ```bash
  > git config core.hooksPath .githooks
  > ```
  >
  > This is local-only (not server-enforced). For real server-side enforcement, upgrade to GitHub Pro or make the repo public, then add a ruleset requiring PRs + the `conformance` status check.

- Branch naming: `<type>/<short-description>` (e.g. `feat/go-discovery-client`, `docs/spec-jwks`).
- Conventional commits (Angular convention): `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `ci:`, `build:`, `test:`, `style:`, `perf:`.
- At least one approving review and green CI before merge.

## Monorepo CI

CI uses **path filters** — a job runs only when its language directory (or shared `spec/` / `infra/`) changes:

| Change touches | Jobs that run |
|----------------|---------------|
| `go/**` | Go (build, vet, lint, test) |
| `rust/**` | Rust (fmt, clippy, test) |
| `spec/**` or `infra/**` | All language jobs (shared contract changed) |

Each language must keep its toolchain check green:

| Language | Local check |
|----------|-------------|
| Go (1.26+) | `cd go && go build ./... && go vet ./... && go test ./...` |
| Rust (MSRV 1.91) | `cd rust && cargo fmt --check && cargo clippy -- -D warnings && cargo test` |

## Conformance

Behavioral parity across languages is enforced by the shared specification in [`spec/`](spec/). When you implement or change a capability:

1. Update or add the test definition in `spec/conformance/<capability>.json`.
2. Implement the capability in your language against those definitions.
3. Update the capability's per-language status in `spec/capabilities.md`.
4. Run the integration suite against the shared provider in `infra/`.

## Adding a New Language

1. Scaffold a top-level `<lang>/` directory with a dependency manifest, source dir, test dir, and README.
2. Add a path-filtered CI job mirroring the existing ones.
3. Add the language column to `spec/capabilities.md` and the language matrix in the root `README.md`.
4. Implement a conformance test runner that consumes `spec/conformance/*.json`.
