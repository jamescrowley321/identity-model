COMPOSE := docker compose -f infra/docker-compose.yml
GO_INTEGRATION := go test -tags=integration -count=1

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "%-34s %s\n", $$1, $$2}'

# ── Local provider stack ─────────────────────────────────────────────

.PHONY: infra-up
infra-up: ## Build and start local providers (node-oidc-provider :9000, IdentityServer :9001)
	$(COMPOSE) up -d --build --wait

.PHONY: infra-down
infra-down: ## Stop local providers
	$(COMPOSE) down

# ── Tests ────────────────────────────────────────────────────────────

.PHONY: test-go
test-go: ## Go unit tests
	cd go && go test ./...

.PHONY: test-integration-node-oidc
test-integration-node-oidc: ## Go integration tests vs local node-oidc-provider (stack must be up)
	set -a && . ./.env.node-oidc && set +a && cd go && $(GO_INTEGRATION) ./...

.PHONY: test-integration-identityserver
test-integration-identityserver: ## Go integration tests vs local IdentityServer (stack must be up)
	set -a && . ./.env.identityserver && set +a && cd go && $(GO_INTEGRATION) ./...

.PHONY: test-integration-local
test-integration-local: ## Full local matrix: compose up, test both providers, compose down
	$(COMPOSE) up -d --build --wait
	$(MAKE) test-integration-node-oidc test-integration-identityserver || ($(COMPOSE) down && exit 1)
	$(COMPOSE) down

# Cloud providers are rate-limited; -p 1 serializes the per-package test
# binaries so parallel packages do not hammer the token endpoint.
.PHONY: test-integration-ory
test-integration-ory: ## Go integration tests vs Ory cloud (.env.ory or TEST_* env)
	@if [ -f .env.ory ]; then set -a && . ./.env.ory && set +a; fi; \
	if [ -z "$$TEST_DISCO_ADDRESS" ]; then echo "SKIP: Ory not configured (create .env.ory or export TEST_*)"; exit 0; fi; \
	cd go && $(GO_INTEGRATION) -p 1 ./...

.PHONY: test-integration-descope
test-integration-descope: ## Go integration tests vs Descope cloud (.env.descope or TEST_* env)
	@if [ -f .env.descope ]; then set -a && . ./.env.descope && set +a; fi; \
	if [ -z "$$TEST_DISCO_ADDRESS" ]; then echo "SKIP: Descope not configured (create .env.descope or export TEST_*)"; exit 0; fi; \
	cd go && $(GO_INTEGRATION) -p 1 ./...

.PHONY: pre-push
pre-push: test-go test-integration-local ## Full local validation before pushing
