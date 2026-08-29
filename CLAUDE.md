# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

py-identity-model is a production-grade OIDC/OAuth2.0 helper library for Python that provides JWT decoding, token generation, and validation. It offers both synchronous and asynchronous APIs with full OpenID Connect Discovery 1.0 and RFC 7517 (JWKS) compliance.

**Key Design Philosophy:**
- **Dual API Design**: Synchronous (`py_identity_model`) and asynchronous (`py_identity_model.aio`) APIs with shared business logic
- **Thread Safety**: Sync API uses thread-local storage for HTTP clients; async API uses singleton with lock protection
- **Modular Architecture**: Clean separation between HTTP layer, business logic (`core/`), and API surface
- **Production Ready**: Used in production for years as foundation for Flask/FastAPI middleware

**Future Vision:**
- **Monorepo Evolution**: Project will evolve into a monorepo structure with separate packages for framework-specific middleware
- **Framework Packages**: Planned packages include `fastapi-identity-model`, `flask-identity-model`, etc.
- **Code Reuse**: Examples should reuse shared code to demonstrate future package structure and minimize duplication

## Mandatory Workflow Rules

**CRITICAL: Follow these rules for every change. No exceptions.**

1. **Always work on a feature branch** — never commit directly to `main`. Create a branch from `main` before starting work:
   ```bash
   git checkout -b feat/my-feature main
   ```

2. **Always run `make lint` before committing** — this runs all pre-commit hooks (ruff lint, ruff format, pyrefly typecheck, pytest coverage). If `ruff format` modifies files, re-stage them and commit again. Do NOT use `--no-verify` to skip hooks.
   ```bash
   make lint                    # Run BEFORE every commit
   ```

3. **Run `make pre-push` when explicitly requested** — this runs integration, conformance, and Docker example tests. It is NOT required before every push (CI covers this). Only run when the user asks for full validation:
   ```bash
   make pre-push    # Runs: lint + node-oidc integration + conformance harness + examples
   ```

4. **Always run integration tests locally before pushing changes to `src/tests/integration/conftest.py`, any test fixture, or shared test utilities.** `make lint` only covers unit tests; `pytest --collect-only` only imports fixtures and does NOT exercise fixture network code paths or cross-worker xdist behavior. Use the credentials-free local fixture:
   ```bash
   make test-integration-node-oidc   # Local Docker fixture, no credentials needed
   ```
   For changes that affect provider-specific behavior, also run `make test-integration-ory` and/or `make test-integration-descope`. Do NOT push fixture/conftest changes solely on the strength of lint passing — relying on CI to catch fixture regressions wastes a review cycle.

5. **Use conventional commits** — commit messages must follow the Angular convention (see Git Workflow section below). Commits to `main` trigger semantic-release version bumps.

6. **Create a PR for all changes** — push the feature branch and open a PR against `main`. PR titles **must** follow conventional commit format (e.g., `feat(discovery): add metadata support`, `fix: handle missing kid`, `ci: update actions`).

## Repository Layout

This repository is a **polyglot monorepo**. The Python package lives under
**`py/`**; Go, Rust, the shared conformance `spec/`, and the shared IdP
fixtures `infra/` are siblings at the root:

```
py/      # Python core (src/, packages/, tools/, pyproject.toml, uv.lock) — this package
go/      # Go library     rust/    # Rust library
spec/    # cross-language conformance vectors    infra/   # shared IdP docker fixtures
conformance/  # OIDF certification harness (Python)
```

**Every path below that starts `src/…`, `packages/…`, or `tools/…` lives under
`py/`.** Run Python tooling from `py/` (`cd py && uv run …`) or, preferably, via
the repo-root `Makefile` targets, which already `cd` into `py/` for you
(`make lint`, `make test-unit`, `make test-fastapi`, `make spec-coverage`,
`make test-integration-*`). The shared `.env.*` provider profiles stay at the
repo root (they are read by the Python, Go, and Rust suites alike).

## Architecture

### Module Structure

```
py/src/py_identity_model/
├── sync/                    # Synchronous API implementations
│   ├── http_client.py      # Thread-local HTTP client (threading.local)
│   ├── discovery.py        # Sync discovery document operations
│   ├── jwks.py             # Sync JWKS operations
│   ├── token_client.py     # Sync token endpoint operations
│   ├── token_validation.py # Sync token validation
│   └── userinfo.py         # Sync UserInfo endpoint operations
├── aio/                     # Asynchronous API implementations
│   ├── http_client.py      # Singleton async HTTP client (lock-protected)
│   ├── discovery.py        # Async discovery document operations
│   ├── jwks.py             # Async JWKS operations
│   ├── token_client.py     # Async token endpoint operations
│   ├── token_validation.py # Async token validation
│   └── userinfo.py         # Async UserInfo endpoint operations
├── core/                    # Shared business logic (protocol-agnostic)
│   ├── models.py           # Request/Response models (dataclasses)
│   ├── discovery_logic.py  # Discovery document parsing/validation
│   ├── jwks_logic.py       # JWKS parsing/validation logic
│   ├── token_validation_logic.py  # JWT validation orchestration
│   ├── token_client_logic.py      # Token request logic
│   ├── userinfo_logic.py   # UserInfo request logic
│   ├── validators.py       # Input validation utilities
│   ├── error_handlers.py   # HTTP error response handling
│   ├── parsers.py          # JSON/text parsing utilities
│   ├── response_processors.py     # Response processing utilities
│   ├── jwt_helpers.py      # JWT decoding helpers
│   ├── mtls.py             # mTLS client auth + cert-bound token validation (RFC 8705)
│   └── http_utils.py       # HTTP configuration utilities
├── exceptions.py            # All exception types
├── identity.py             # ClaimsPrincipal/ClaimsIdentity models
├── ssl_config.py           # SSL certificate configuration
├── oidc_constants.py       # Protocol constants
└── jwt_claim_types.py      # Standard JWT claim names
```

### Critical Architectural Patterns

1. **HTTP Client Management**
   - **Sync API**: Each thread gets its own HTTP client via `threading.local()`. See `sync/http_client.py:get_http_client()`
   - **Async API**: Single shared client per process with lock-protected initialization. See `aio/http_client.py:get_async_http_client()`
   - Both use `httpx` with connection pooling and configurable timeouts/retries

2. **Business Logic Separation**
   - All protocol logic lives in `core/` modules and is shared between sync/async
   - Sync/async modules are thin wrappers that handle I/O and call core logic
   - Core functions are pure (no I/O) and return result objects or raise exceptions

3. **Caching Strategy**
   - Discovery documents and JWKS are cached per-process with an explicit **TTL + LRU** cache (an `OrderedDict` bounded to `DEFAULT_MAX_CACHE_ENTRIES` = 64), **not** `functools.lru_cache`/`async_lru.alru_cache`. Cache *policy* lives in `core/jwks_cache.py`; the sync/async cache stacks live in `sync/token_validation.py` and `aio/token_validation.py`.
   - Entries expire on a TTL resolved from `Cache-Control: max-age` → env override (`DISCO_CACHE_TTL` / `JWKS_CACHE_TTL`) → built-in default, clamped to `[60s, 86400s]`. Concurrent misses are coalesced into a single upstream fetch via per-URI striped locks.
   - Per-process cache hit/miss/refresh counters are exposed via `core/cache_metrics.py` (`get_cache_counters()`, re-exported at the top level); the async cache paths are instrumented. Clear caches with `clear_discovery_cache()` / `clear_jwks_cache()` (async variants must be `await`ed).
   - All caches are per-process, not shared across processes

4. **Error Handling**
   - Per-feature error handlers in `core/error_handlers.py` (e.g., `handle_discovery_error()`, `handle_token_error()`, `handle_userinfo_error()`)
   - Structured exceptions in `exceptions.py` (all inherit from `PyIdentityModelException`)
   - Error responses follow OIDC/OAuth2 error formats

## Development Commands

### Setup
```bash
cd py && uv sync            # Install dependencies (run from py/)
```

### Testing
```bash
# Run all tests (unit + integration)
make test

# Run only unit tests (fast, no external dependencies)
make test-unit

# Run integration tests against ORY identity provider
make test-integration-ory   # Requires environment variables (see CI)

# Run integration tests against local identity server
make test-integration-local # Requires .env.local file

# Run example integration tests (spins up Docker containers)
make test-examples

# Run the TH-1.5 CI-short load profile (real Locust vs the booted RS + mock OP)
make test-harness-load       # Opt-in `load` group (locust); Locust runs out-of-process

# Run all tests including examples
make test-all

# Run a single test file
cd py && uv run pytest src/tests/unit/test_discovery.py -v

# Run a specific test
cd py && uv run pytest src/tests/unit/test_discovery.py::test_function_name -v
```

**Coverage Requirements**: All test commands enforce 80% minimum coverage (enforced by pytest + pre-commit).

### Linting
```bash
# Run all pre-commit hooks (ruff format, ruff check, pyrefly typecheck, coverage)
make lint

# Auto-fix linting issues
cd py && uv run ruff check --fix src/
```

### Building
```bash
# Build distribution packages
make build-dist             # Creates wheel and sdist in dist/
```

## Git Workflow

### Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) with Angular convention for semantic versioning automation. All commit messages must follow this format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Required Components:**
- **type**: The type of change (see allowed types below)
- **subject**: Short description in imperative mood (e.g., "add feature" not "added feature")

**Optional Components:**
- **scope**: Module or component affected (e.g., `discovery`, `jwks`, `token-validation`, `userinfo`)
- **body**: Detailed explanation with bullet points if needed
- **footer**: Breaking changes, issue references

**Allowed Types** (from `pyproject.toml`):
- `feat`: New feature (triggers minor version bump)
- `fix`: Bug fix (triggers patch version bump)
- `perf`: Performance improvement (triggers patch version bump)
- `docs`: Documentation changes only
- `test`: Adding or updating tests
- `build`: Build system or dependencies
- `ci`: CI/CD pipeline changes
- `chore`: Maintenance tasks, tooling
- `refactor`: Code refactoring without changing behavior
- `style`: Code style/formatting changes

**Example:** `git commit -m "feat(discovery): add OAuth 2.0 server metadata support"`

Breaking changes: `feat(api)!: <msg>` + `BREAKING CHANGE:` in footer. Use heredoc for multi-line: `git commit -m "$(cat <<'EOF' ... EOF)"`

### Branch Naming

Format: `<type>/<short-description>` (e.g., `feat/descope-integration`, `fix/jwks-key-rotation`). Type must match conventional commit types above.

## Key Implementation Details

### Testing Patterns

- **Unit tests**: Use `respx` to mock HTTP in `src/tests/unit/`. Sync tests use `@respx.mock` decorator, async tests use `@pytest.mark.asyncio` class + `@respx.mock` on methods.
- **Integration tests**: Test against real identity providers in `src/tests/integration/`. Session-scoped fixtures in `conftest.py` cache discovery docs, JWKS, and tokens to avoid rate limits.
- **Coverage**: Minimum 80% coverage required (enforced by pytest and pre-commit)

### HTTP Configuration

Environment variables (see `core/http_utils.py`):
- `HTTP_TIMEOUT`: Request timeout in seconds (default: 30.0)
- `HTTP_RETRY_COUNT`: Max retries for rate-limited requests (default: 3)
- `HTTP_RETRY_BASE_DELAY`: Base delay for exponential backoff (default: 1.0)
- `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`: Custom CA bundle paths

### SSL/TLS Configuration

The library supports custom SSL certificates via environment variables. Priority order:
1. `SSL_CERT_FILE` (httpx native, recommended)
2. `REQUESTS_CA_BUNDLE` (backward compatibility)
3. `CURL_CA_BUNDLE` (httpx fallback)
4. System defaults

See `ssl_config.py` for implementation details.

## Common Pitfalls

1. **Don't mix sync and async**: Never call sync functions from async code or vice versa. Use the appropriate API for your context.
2. **Don't bypass core logic**: Always implement business logic in `core/` first, then wrap in sync/async layers.
3. **Don't share state between threads**: The sync API uses thread-local storage for a reason. Global state breaks thread safety.
4. **Don't forget to close responses**: HTTP responses must be fully consumed (`response.read()` or `response.json()`) to return connections to the pool. Sync wrappers call `response.close()` explicitly.
5. **Always add type hints**: This codebase requires comprehensive type annotations for all functions and classes.

## Workspace Packages

This repo is a `uv` workspace. Besides the core `py-identity-model` library
(`py/src/py_identity_model/`), it ships framework packages under `py/packages/`:

- **`py/packages/fastapi-identity-model/`** — FastAPI OIDC middleware + relying-party
  login router, built on the core library. Independently versioned and published.
  - Test + typecheck: `make test-fastapi`. Build: `make build-fastapi`.
  - **Released automatically** by semantic-release: `feat(fastapi)`/`fix(fastapi)`
    commits on `main` bump the package's own version (config in the package
    `pyproject.toml`, invoked by the `release-fastapi-version` job in
    `release.yml`); the resulting `fastapi-identity-model-v*` tag triggers
    `.github/workflows/release-fastapi.yml`, which publishes to PyPI via
    trusted publishing.
  - **Commit convention:** scope every commit that belongs to a non-Python
    release track. A custom scope-routed parser (`tools/release_parsers.py`)
    drops commits scoped `(fastapi)`, `(go)`, `(rust)`, `(node)`, `(spec)`, or
    `(infra)` from the core `py-identity-model` pipeline (and the fastapi
    pipeline keeps only `(fastapi)`), so e.g. `feat(go)` or `feat(fastapi)`
    never bumps the Python library. Python releases use the `py-v{version}`
    tag format; Go/Rust use `go/vX.Y.Z` / `rust-vX.Y.Z`. The routing is
    scope-based, not path-based: an **unscoped** `feat:` touching only `go/`
    would still bump the core, so the scope is load-bearing. The release
    workflow path-guards `node/**` `spec/**` `infra/**` (no versioner ⇒ skip)
    as a second line of defence, but **not** `go/**` / `rust/**`, whose version
    jobs must run on native-only pushes — for those, the scope is the *only*
    guard.

The Go and Rust libraries are **also released automatically**, mirroring the
fastapi package — merging a `feat(go)`/`feat(rust)` (or `fix(...)`) commit to
`main` auto-tags and publishes, no manual tagging:

- **`go/`** (Go library `github.com/jamescrowley321/identity-model/go`) — the
  `release-go-version` job (`release.yml`, after the fastapi job) runs
  semantic-release with `tools/semantic-release-go.toml` on `(go)`-scoped
  commits. A Go library has no version file, so the version *is* the
  `go/v{version}` tag (subdir-module format); the pushed tag triggers
  `release-go.yml` (build/verify + GitHub Release; a Go module ships as source
  via the proxy, nothing to publish).
- **`rust/`** (crate `rs-identity-model`) — the `release-rust-version` job
  (after the go job) runs semantic-release with `tools/semantic-release-rust.toml`
  on `(rust)`-scoped commits, bumping `rust/Cargo.toml`; the pushed
  `rust-v{version}` tag triggers `release-rust.yml`, which publishes to
  crates.io (needs the `CARGO_REGISTRY_TOKEN` secret). The version job also
  syncs the crate's own entry in `rust/Cargo.lock`.

The four version jobs run as a **serial chain** (`release` → fastapi → go →
rust), each pulling `main` before it versions, so the release pipelines never
push to `main` concurrently.

## Version Management

The project uses semantic versioning with python-semantic-release:
- Version is defined in `pyproject.toml:project.version`
- Commit messages follow Angular convention (feat:, fix:, docs:, etc.)
- Pre-releases use `-rc.N` suffix on non-main branches
- Main branch releases are stable versions

For pre-release testing, see `docs/pre-release-guide.md`.
