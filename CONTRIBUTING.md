# Contributing to identity-model

Thank you for your interest in contributing! This repository is a polyglot
monorepo containing three native OIDC/OAuth 2.0 client libraries — Python
(`py-identity-model` plus the `fastapi-identity-model` middleware package), Go,
and Rust — held to a single shared behavioral contract in
[`spec/`](https://github.com/jamescrowley321/identity-model/tree/main/spec).
This document covers the development workflow for all of them.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.12 or higher and [uv](https://github.com/astral-sh/uv) (Python library, docs, tooling)
- Go (see `go/go.mod` for the required version) — only for Go changes
- Rust (see `rust/README.md` for the MSRV) — only for Rust changes
- Docker (integration-test identity providers and the conformance suite)
- Git

### Repository layout

```
identity-model/
├── py/           Python library + fastapi-identity-model package (uv, PyPI)
│   ├── src/py_identity_model/    library source
│   ├── src/tests/                unit / integration / security / benchmark tests
│   └── packages/fastapi-identity-model/
├── go/           Go library (module github.com/jamescrowley321/identity-model/go)
├── rust/         Rust library (crate rs-identity-model)
├── spec/         cross-language capability spec + conformance vectors
├── infra/        shared local identity-provider fixtures (docker compose)
├── conformance/  OpenID Foundation conformance-suite harness
├── docs/         mkdocs documentation site
└── Makefile      wraps the common flows for every language
```

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/identity-model.git
   cd identity-model
   ```

2. **Install uv** (if not already installed)
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **Install Python dependencies** (both packages)
   ```bash
   cd py && uv sync --all-packages && cd ..
   ```

4. **Install pre-commit hooks**
   ```bash
   uv run --project py pre-commit install
   ```

## Development Workflow

### Code Style and Conventions

- **Python**: [Ruff](https://github.com/astral-sh/ruff) for linting and formatting
  (line length 88), [pyrefly](https://pyrefly.org/) for type checking. All code
  must include comprehensive type hints and Google-style docstrings for public
  classes and functions. Imports are sorted by Ruff.
- **Go**: `gofmt`, `go vet`, and `golangci-lint` (config in `go/.golangci.yml`).
- **Rust**: `cargo fmt` and `cargo clippy -- -D warnings`.

### Running Tests

All targets run from the repository root; `make help` lists everything.

Python — full suite (unit + integration) with the coverage gate:
```bash
make test
```

Python — unit tests only:
```bash
make test-unit
```

Python — integration tests against a specific provider (Docker fixtures are
started automatically where needed):
```bash
make test-integration-node-oidc   # node-oidc-provider (local Docker)
make test-integration-keycloak    # Keycloak (local Docker)
make test-integration-local       # your own provider via .env.local
make test-integration-ory         # Ory
make test-integration-descope     # Descope
```

Go and Rust:
```bash
make lint-go                # vet + golangci-lint + race-enabled unit tests
make test-integration-go    # Go integration suite against the shared fixtures
cd rust && cargo test       # Rust unit tests
make test-integration-rust  # Rust live integration suite
```

Cross-language conformance (every language must pass every shared vector):
```bash
make spec-coverage
```

Run specific Python tests (from `py/`):
```bash
uv run pytest src/tests/unit/test_discovery.py -v
uv run pytest src/tests/unit/test_discovery.py::test_specific_function -v
```

### Code Formatting and Linting

Run all pre-commit checks (Ruff lint + format, pyrefly, coverage):
```bash
make lint
```

### Pre-commit Hooks

Pre-commit hooks run automatically when you commit. They will:
- Format code with Ruff
- Check for linting issues
- Validate type hints with pyrefly
- Check for common issues

If pre-commit fails, fix the issues and commit again.

## Making Changes

### Branch Naming

Use descriptive branch names with prefixes:
- `feat/` - New features (e.g., `feat/add-token-introspection`)
- `fix/` - Bug fixes (e.g., `fix/token-validation-bug`)
- `docs/` - Documentation changes (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring (e.g., `refactor/base-classes`)
- `test/` - Test improvements (e.g., `test/add-integration-tests`)
- `chore/` - Maintenance tasks (e.g., `chore/update-dependencies`)

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `perf`: Performance improvements
- `style`: Code style changes (formatting, etc.)

**Examples:**
```
feat(token): add token introspection endpoint support

fix(validation): handle missing kid in JWT header

docs(readme): add examples for token validation

test(discovery): add integration tests for discovery endpoint
```

PRs are squash-merged, and the **PR title becomes the commit message that
drives Python releases** — so the title itself must be a valid conventional
commit line. A `feat:`/`fix:` title cuts a new PyPI release when it merges;
use `docs:`, `test:`, `ci:`, or `chore:` for changes that should not.

### Pull Request Process

1. **Create a feature branch** from `main`
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Write or update tests** to cover your changes
   - Unit tests for new functionality
   - Integration tests proving the behavior against a real provider
   - Shared `spec/` vectors when the change affects cross-language behavior

4. **Update documentation** if needed
   - Update the docs site (`docs/`) and per-language READMEs for new features
   - Update docstrings for changed functions/classes
   - Add examples if appropriate

5. **Run tests and linting**
   ```bash
   make test
   make lint
   ```

6. **Commit your changes** with clear commit messages

7. **Push to your fork**
   ```bash
   git push origin feat/your-feature-name
   ```

8. **Create a Pull Request** on GitHub
   - Use a conventional-commit title (it becomes the squash commit)
   - Reference related issues (e.g., "Closes #123")
   - Describe what changes you made and why
   - Include examples if adding new features

### Pull Request Guidelines

- **Keep PRs focused**: One feature or fix per PR
- **Write clear descriptions**: Explain what and why, not just how
- **Include tests**: All new code should have tests
- **Update documentation**: Keep docs in sync with code changes
- **Follow the style guide**: Use Ruff for consistent formatting
- **Be responsive**: Address review feedback promptly

## Testing Requirements

### Test Coverage

- The Python suite enforces a **minimum 80% coverage gate** (`make test` fails below it)
- All new features must include tests
- Bug fixes should include regression tests
- Behavioral claims need integration tests against a real provider — green
  unit tests alone are not sufficient for protocol behavior

### Test Types

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test complete flows against real identity providers
   (the shared fixtures in `infra/`, or live providers)
3. **Conformance Tests**: The shared `spec/` vectors (all languages) and the
   OpenID Foundation conformance suite (`conformance/`)

### Writing Tests

Use pytest and follow these conventions:

```python
import pytest
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document


def test_discovery_document_success():
    """Test successful discovery document retrieval."""
    request = DiscoveryDocumentRequest(address="https://example.com/.well-known/openid-configuration")
    response = get_discovery_document(request)

    assert response.is_successful
    assert response.issuer is not None


def test_discovery_document_invalid_url():
    """Test discovery document with invalid URL."""
    request = DiscoveryDocumentRequest(address="invalid-url")
    response = get_discovery_document(request)

    assert not response.is_successful
    assert response.error is not None
```

## Documentation

### Docstring Format

Use Google-style docstrings:

```python
def validate_token(jwt: str, token_validation_config: TokenValidationConfig, disco_doc_address: str) -> dict:
    """Validate a JWT token against the provided configuration.

    Args:
        jwt: The JWT token string to validate.
        token_validation_config: Configuration for token validation.
        disco_doc_address: Address of the OpenID Connect discovery document.

    Returns:
        Dictionary containing the validated JWT claims.

    Raises:
        PyIdentityModelException: If token validation fails.

    Examples:
        >>> config = TokenValidationConfig(perform_disco=True, audience="my-api")
        >>> claims = validate_token(token, config, "https://auth.example.com")
        >>> print(claims["sub"])
    """
    # Implementation
```

### Building Documentation

Build the documentation locally:
```bash
make docs-serve
```

Then visit http://127.0.0.1:8000 to view the docs. `make docs-build` runs the
same strict build CI uses.

## Release Process

Each language releases on its own cadence. Version numbers follow
[Semantic Versioning](https://semver.org/).

### Python (`py-identity-model` on PyPI)

Releases are automated with semantic-release. When commits land on `main`,
it analyzes the (squash) commit messages to determine the version bump,
updates `py/pyproject.toml` and `py/CHANGELOG.md`, pushes a `py-v{version}`
tag, and the tag triggers publishing to PyPI.

### Go (`github.com/jamescrowley321/identity-model/go`)

A Go release is a `go/vX.Y.Z` tag — the subdirectory-module format `go get`
requires. Pushing the tag verifies the library and cuts a GitHub Release.

### Rust (`rs-identity-model` on crates.io)

A Rust release is a `rust-vX.Y.Z` tag matching the version in
`rust/Cargo.toml`. Pushing the tag publishes the crate to crates.io and cuts
a GitHub Release.

### Pre-releases

Every pull request automatically gets a GitHub pre-release build of the
Python package (an `-rc` version tied to the PR), with install instructions
posted as a PR comment — useful for testing a change in a real environment
before it merges. See the
[Pre-release Testing Guide](https://jamescrowley321.github.io/identity-model/pre-release-guide/)
for details.

## Roadmap

See the [project roadmap](https://jamescrowley321.github.io/identity-model/py_identity_model_roadmap/)
and [GitHub issues](https://github.com/jamescrowley321/identity-model/issues)
for planned features and current priorities.

## Getting Help

- **Issues**: Open an issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the [docs](https://jamescrowley321.github.io/identity-model/)

## Recognition

Contributors will be recognized in the project documentation and release notes. Thank you for helping make identity-model better!

## License

By contributing to identity-model, you agree that your contributions will be licensed under the Apache License 2.0.

## AI-Assisted Contributions

Contributions that use AI tools (GitHub Copilot, Claude Code, ChatGPT, Cursor, the Ralph loop, `pi`, etc.) are welcome. We apply the same quality standards to all contributions regardless of how they were authored.

### Requirements for AI-assisted PRs

- **All CI checks must pass** — lint, tests, security scans. No exceptions.
- **Audit disclosure is required.** Every AI-assisted PR must record, in the PR description's **AI provenance** block, the **harness/agent(s)** and the **model(s)** used to produce the change (for example: harness `Claude Code`, model `claude-opus-4-8`; or harness `ralph-orchestrator + pi`, model `z-ai/glm-5.2`).
- **A human is accountable.** A named human must review the change and attest to it. The submitter is responsible for the correctness, security, and quality of the code regardless of whether it was AI-generated.
- **Advisory-only AI.** AI output — including automated review — is advisory until a human attests. A green check is not sign-off.

### What we look for

- No hallucinated APIs, invented SDK methods, or fabricated citations.
- Tests actually run and cover the new functionality.
- Documentation is accurate and complete.
