# py-identity-model Makefile
# Run `make help` to see all available targets.

CONFORMANCE_SERVER ?= https://www.certification.openid.net/
ACTION ?= create

# The Python package lives under py/ (CONS-2.1). Two uv invocation modes:
#   UVPY   — cwd=py/, for commands whose paths are Python-package-internal
#            (src/tests, packages/…); the shared .env.* profiles at the repo
#            root are reached as ../.env.* .
#   UVROOT — cwd=repo-root, py/ env, for commands whose paths are repo-root
#            relative (conformance/, spec/, root .env globbing, mkdocs.yml).
UVPY := uv run --directory py
UVROOT := uv run --project py

# ── Build ────────────────────────────────────────────────────────────

.PHONY: build-dist
build-dist: ## Build wheel and sdist
	cd py && uv sync && uv build

.PHONY: upload-dist
upload-dist: ## Publish package to PyPI
	cd py && uv publish

# ── Lint ─────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run all pre-commit hooks (ruff, pyrefly, coverage)
	$(UVROOT) pre-commit run -a

# ── Tests ────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests (unit + integration)
	$(UVPY) pytest src/tests -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-unit
test-unit: ## Run unit tests only
	$(UVPY) pytest src/tests -m unit -v -n auto --cov=src/py_identity_model --cov-report=term-missing --cov-report=html --cov-fail-under=80 --ignore=src/tests/benchmarks -p no:benchmark

.PHONY: test-integration-local
test-integration-local: ## Run integration tests against local provider
	$(UVPY) pytest src/tests -m integration --env-file=../.env.local -v -n auto -p no:benchmark

.PHONY: test-integration-ory
test-integration-ory: ## Run integration tests against Ory
	$(UVPY) pytest src/tests -m integration -v -n auto -p no:benchmark

.PHONY: test-integration-descope
test-integration-descope: ## Run integration tests against Descope
	@echo "Running integration tests against Descope..."
	$(UVPY) pytest src/tests -m integration $(if $(wildcard .env.descope),--env-file=../.env.descope) -v -n auto -p no:benchmark

# ── Shared IdP fixtures (infra/) ─────────────────────────────────────
# One compose file serves every language suite; targets start only the
# provider(s) they need. See infra/README.md.
INFRA_COMPOSE := docker compose -f infra/docker-compose.yml

.PHONY: infra-up
infra-up: ## Start the Go/Rust default provider pair (node-oidc :9010 + IdentityServer :9001)
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider identityserver

.PHONY: infra-down
infra-down: ## Stop all infra/ fixture providers
	$(INFRA_COMPOSE) down

.PHONY: test-integration-node-oidc
test-integration-node-oidc: ## Run integration tests against node-oidc-provider
	@echo "Starting node-oidc-provider fixture..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider
	@echo "Running integration tests against node-oidc-provider..."
	$(UVPY) pytest src/tests -m integration --env-file=../.env.node-oidc -v || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-integration-keycloak
test-integration-keycloak: ## Run integration tests against Keycloak
	@echo "Starting Keycloak fixture..."
	$(INFRA_COMPOSE) up -d --build --wait keycloak
	@echo "Running integration tests against Keycloak..."
	$(UVPY) pytest src/tests -m integration --env-file=../.env.keycloak -v || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-integration-go
test-integration-go: ## Run Go integration tests against node-oidc (defaults) + IdentityServer profile
	@echo "Starting node-oidc-provider + IdentityServer fixtures..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider identityserver
	@echo "Running Go integration tests (node-oidc default profile)..."
	(cd go && go test -tags=integration -count=1 ./...) || \
		($(INFRA_COMPOSE) down && exit 1)
	@echo "Running Go integration tests (IdentityServer profile)..."
	set -a && . ./.env.identityserver && set +a && (cd go && go test -tags=integration -count=1 ./...) || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: lint-rust
lint-rust: ## rustfmt check + clippy (warnings as errors) for the Rust library
	cd rust && cargo fmt --all --check
	cd rust && cargo clippy --all-targets --all-features -- -D warnings

.PHONY: audit-rust
audit-rust: ## Supply-chain scan of the Rust crate (cargo-deny: advisories/licenses/bans/sources)
	cd rust && cargo deny check

.PHONY: test-integration-rust
test-integration-rust: ## Run Rust live integration tests (#[ignore]-gated) against node-oidc
	@echo "Starting node-oidc-provider fixture..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider
	@echo "Running Rust live integration tests..."
	set -a && . ./.env.node-oidc && set +a && (cd rust && cargo test -- --ignored) || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-harness-rs
test-harness-rs: ## Boot the RS (uvicorn) against node-oidc and run the TH-1.2 real-HTTP proof
	@echo "Starting node-oidc-provider fixture..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider
	@echo "Booting fastapi-identity-model RS under uvicorn (real HTTP)..."
	$(UVPY) --all-packages pytest src/tests/integration/test_rs_boot.py -m integration --env-file=../.env.node-oidc -v || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-harness-matrix
test-harness-matrix: ## Run the TH-1.3 token correctness matrix (mock-OP forged corpus + node-oidc leg) through the booted RS
	@echo "Starting node-oidc-provider fixture..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider
	@echo "Running the correctness matrix through the booted RS (real HTTP)..."
	$(UVPY) --all-packages pytest src/tests/integration/test_correctness_matrix.py -m integration --env-file=../.env.node-oidc -v || \
		($(INFRA_COMPOSE) down && exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-harness-cross-issuer
test-harness-cross-issuer: ## Real cross-issuer proof: a token from one Docker IdP (node-oidc/Keycloak) is rejected by an RS trusting the other
	@echo "Starting node-oidc + Keycloak fixtures side by side..."
	$(INFRA_COMPOSE) up -d --build --wait node-oidc-provider keycloak
	@echo "Cross-presenting real tokens across issuers through the booted RS..."
	$(UVPY) --all-packages pytest src/tests/integration/test_cross_issuer_real_idps.py -m integration -v || \
		($(INFRA_COMPOSE) down; exit 1)
	$(INFRA_COMPOSE) down

.PHONY: test-harness-load
test-harness-load: ## Run the TH-1.5 CI-short load profile (real Locust vs the booted RS + mock OP)
	@echo "Driving the CI-short Locust profile through the booted RS (real HTTP)..."
	$(UVPY) --group load --all-packages pytest src/tests/load/test_load_ci_short.py \
		-m integration -p no:benchmark -v

.PHONY: test-harness-load-nightly
test-harness-load-nightly: ## (nightly) Long TTL-rollover / LRU-thrash / RSS-FD soak profile (S4/S7/S11/S12)
	@echo "Driving the NIGHTLY soak profile (design §4 S4/S7/S11/S12) through the booted RS..."
	$(UVPY) --group load --all-packages pytest src/tests/load/test_load_nightly.py \
		-m integration -p no:benchmark -v

.PHONY: test-harness-load-capacity
test-harness-load-capacity: ## (TH-4) Open-model ramp-to-breakpoint: find the goodput knee (C1/C2)
	@echo "Ramping arrival rate to the goodput knee (co-located = directional numbers)..."
	$(UVPY) --group load --all-packages pytest src/tests/load/test_load_capacity.py \
		-m integration -p no:benchmark -v

.PHONY: test-benchmark
test-benchmark: ## Run benchmarks
	$(UVPY) pytest src/tests/benchmarks -v --benchmark-only --benchmark-sort=name

.PHONY: test-examples
test-examples: ## Run example integration tests (Docker)
	@echo "Running example integration tests..."
	cd py/examples && ./run-tests.sh

.PHONY: test-all
test-all: test test-examples ## Run all tests including examples

# ── fastapi-identity-model package ───────────────────────────────────

.PHONY: test-fastapi
test-fastapi: ## Typecheck + unit-test the fastapi-identity-model package (80% coverage)
	cd py && uv sync --all-packages
	$(UVPY) --no-sync pyrefly check packages/fastapi-identity-model/fastapi_identity_model/
	$(UVPY) --no-sync pytest packages/fastapi-identity-model/tests -v -n auto -p no:benchmark \
		--cov=fastapi_identity_model --cov-report=term-missing --cov-fail-under=80

.PHONY: build-fastapi
build-fastapi: ## Build the fastapi-identity-model wheel + sdist
	cd py && uv build --package fastapi-identity-model

# ── Security gate ────────────────────────────────────────────────────

.PHONY: spec-coverage
spec-coverage: ## CONS-1.5: run the py/go/rust /spec vector runners + 100% per-language coverage gate
	$(UVROOT) python tools/spec_coverage_gate.py

.PHONY: publish-parity
publish-parity: ## CONS-2.5: prove the /py build packages byte-for-byte vs the latest PyPI release
	$(UVPY) python tools/publish_parity.py --package py-identity-model
	$(UVPY) python tools/publish_parity.py --package fastapi-identity-model

.PHONY: mutation-security
mutation-security: ## Mutation-test changed security modules vs BASE (Epic 19 G.1)
	$(UVPY) python tools/mutation_security.py

.PHONY: security-gate
security-gate: mutation-security ## Aggregate mechanical security gate (Epic 19 G.5)

# ── Pre-push ────────────────────────────────────────────────────────

.PHONY: pre-push
pre-push: lint test-fastapi test-integration-node-oidc test-integration-keycloak test-integration-go test-integration-rust conformance-test-harness test-examples ## Full local validation before push

# ── Docs ─────────────────────────────────────────────────────────────

.PHONY: docs-serve
docs-serve: ## Serve mkdocs documentation locally
	$(UVROOT) --group docs mkdocs serve

.PHONY: docs-build
docs-build: ## Build mkdocs documentation
	$(UVROOT) --group docs mkdocs build --strict

# ── Utilities ────────────────────────────────────────────────────────

.PHONY: provider-matrix
provider-matrix: ## Show provider capability matrix from discovery documents
	$(UVROOT) python py/src/tests/integration/provider_matrix.py

.PHONY: generate-token
generate-token: ## Generate a sample JWT token
	$(UVPY) python examples/generate_token.py

.PHONY: ci-setup
ci-setup: ## CI environment setup (uv is provided by astral-sh/setup-uv)
	cd py && uv venv && uv sync --all-packages

# ── Conformance ──────────────────────────────────────────────────────

.PHONY: conformance-build
conformance-build: ## Build conformance suite containers
	docker compose -f conformance/docker-compose.yml build

.PHONY: conformance-up
conformance-up: ## Start conformance suite and RP harness
	docker compose -f conformance/docker-compose.yml up -d --build --wait
	@# docker --wait only checks container healthchecks; the conformance suite's
	@# TLS listener and the RP harness's /health endpoint can still be cold for
	@# several seconds after that. Poll them at the application level to match
	@# the readiness gate CI applies (.github/workflows/conformance.yml) so
	@# `make conformance-test` is not flaky from a cold start.
	@echo "Waiting for conformance suite at https://localhost.emobix.co.uk:8443..."
	@for i in $$(seq 1 60); do \
	  HTTP_CODE=$$(curl -sk -o /dev/null -w '%{http_code}' https://localhost.emobix.co.uk:8443/ || echo 000); \
	  if [ "$$HTTP_CODE" -ge 200 ] 2>/dev/null && [ "$$HTTP_CODE" -lt 400 ] 2>/dev/null; then \
	    echo "Conformance suite is ready (HTTP $$HTTP_CODE)"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 60 ]; then \
	    echo "Timed out waiting for conformance suite"; \
	    docker compose -f conformance/docker-compose.yml logs server; \
	    exit 1; \
	  fi; \
	  sleep 5; \
	done
	@echo "Waiting for RP harness at http://localhost:8888/health..."
	@for i in $$(seq 1 30); do \
	  if curl -sf http://localhost:8888/health > /dev/null 2>&1; then \
	    echo "RP harness is ready"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 30 ]; then \
	    echo "Timed out waiting for RP harness"; \
	    docker compose -f conformance/docker-compose.yml logs rp; \
	    exit 1; \
	  fi; \
	  sleep 2; \
	done
	@echo "Waiting for fastapi RP harness at http://localhost:8889/health..."
	@for i in $$(seq 1 30); do \
	  if curl -sf http://localhost:8889/health > /dev/null 2>&1; then \
	    echo "fastapi RP harness is ready"; \
	    break; \
	  fi; \
	  if [ "$$i" -eq 30 ]; then \
	    echo "Timed out waiting for fastapi RP harness"; \
	    docker compose -f conformance/docker-compose.yml logs rp-fastapi; \
	    exit 1; \
	  fi; \
	  sleep 2; \
	done

.PHONY: conformance-down
conformance-down: ## Tear down conformance suite
	docker compose -f conformance/docker-compose.yml down -v

.PHONY: conformance-test
conformance-test: $(if $(HOSTED),,conformance-up) ## Run conformance tests (HOSTED=1 for hosted suite)
ifdef HOSTED
	$(UVROOT) python conformance/run_tests.py --plan basic-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/basic-rp-latest.json --export-zip conformance/results/hosted/basic-rp-export.zip --rp-logs-zip conformance/results/hosted/basic-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	$(UVROOT) python conformance/run_tests.py --plan config-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/config-rp-latest.json --export-zip conformance/results/hosted/config-rp-export.zip --rp-logs-zip conformance/results/hosted/config-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	$(UVROOT) python conformance/run_tests.py --plan form-post-basic-rp --suite-url "$(CONFORMANCE_SERVER)" --output conformance/results/hosted/form-post-basic-rp-latest.json --export-zip conformance/results/hosted/form-post-basic-rp-export.zip --rp-logs-zip conformance/results/hosted/form-post-basic-rp-rp-logs.zip --publish "$(or $(PUBLISH),none)" --verbose
	@echo "Hosted conformance tests complete. Results in conformance/results/hosted/"
else
	$(UVROOT) python conformance/run_tests.py --plan basic-rp --output conformance/results/basic-rp-latest.json --verbose
	$(UVROOT) python conformance/run_tests.py --plan config-rp --output conformance/results/config-rp-latest.json --verbose
	$(UVROOT) python conformance/run_tests.py --plan form-post-basic-rp --output conformance/results/form-post-basic-rp-latest.json --verbose
	@echo "Conformance tests complete. Results in conformance/results/"
endif

.PHONY: conformance-test-fastapi
conformance-test-fastapi: conformance-up ## Run fastapi-identity-model package regression against the local suite
	$(UVROOT) python conformance/run_tests.py --plan fastapi-basic-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-basic-rp-latest.json --verbose
	$(UVROOT) python conformance/run_tests.py --plan fastapi-config-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-config-rp-latest.json --verbose
	$(UVROOT) python conformance/run_tests.py --plan fastapi-form-post-basic-rp --rp-url http://localhost:8889 --output conformance/results/fastapi-form-post-basic-rp-latest.json --verbose
	@echo "fastapi-identity-model conformance regression complete. Results in conformance/results/"

.PHONY: conformance-test-harness
conformance-test-harness: ## Run conformance harness unit tests (parser + callback)
	$(UVROOT) --with fastapi --with httpx --with python-multipart --with respx pytest conformance/tests/ -v

.PHONY: conformance-token
conformance-token: ## Manage OIDF API token (ACTION=create|show|env)
ifeq ($(ACTION),show)
	$(UVROOT) conformance/scripts/rotate_conformance_token.py --dry-run --show-token
else ifeq ($(ACTION),env)
	@echo "export CONFORMANCE_TOKEN=$$(hcp vault-secrets secrets open CONFORMANCE_TOKEN --app py-identity-model --format json | jq -r '.static_version.value')"
	@echo "# Run the above command, or: eval \$$(make conformance-token ACTION=env)"
else
	@echo "Launching browser for certification.openid.net login..."
	@echo "First run: sign in via Google/GitLab in the browser window."
	@echo "Subsequent runs: session is cached in ~/.cache/py-identity-model/playwright-profile/"
	$(UVROOT) conformance/scripts/rotate_conformance_token.py
endif

# ── Help ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
