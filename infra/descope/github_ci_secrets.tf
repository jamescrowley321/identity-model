# Extended CI secret management.
#
# The existing github.tf writes Descope-derived credentials to the
# `github_actions_secret` scope so workflows triggered by human PRs and
# pushes can reach the Descope integration tests. This file adds two
# things that file doesn't cover:
#
# 1. A parallel set of `github_dependabot_secret` resources mirroring every
#    CI secret into the Dependabot event scope. Dependabot-authored PRs run
#    under a separate secret scope from regular workflow_dispatch/pull_request
#    events, and without these mirrors the Ory + Descope integration tests
#    fail every dependabot PR, which blocks auto-merge.
#
# 2. The Ory integration test credentials (`TEST_*`), which previously had
#    no declarative source. These values live in the local `.env` at the
#    repo root (provisioned once via the Ory dashboard).

locals {
  # Parse ../../.env (repo root) into a map of VAR => value. Handles the
  # common `KEY=value` and `KEY="value"` forms. Skips blanks and comments.
  env_file_lines = [
    for line in split("\n", file("${path.module}/../../.env")) :
    line
    if length(regexall("^[A-Z_][A-Z0-9_]*=", line)) > 0
  ]

  env_vars = {
    for line in local.env_file_lines :
    split("=", line)[0] => trim(
      join("=", slice(split("=", line), 1, length(split("=", line)))),
      "\"'"
    )
  }

  # Ory / local fixture credentials mirrored to CI. These map 1:1 to the
  # `TEST_*` secret names referenced in .github/workflows/ci.yml.
  ory_test_secrets = {
    TEST_DISCO_ADDRESS = local.env_vars["TEST_DISCO_ADDRESS"]
    TEST_JWKS_ADDRESS  = local.env_vars["TEST_JWKS_ADDRESS"]
    TEST_CLIENT_ID     = local.env_vars["TEST_CLIENT_ID"]
    TEST_CLIENT_SECRET = local.env_vars["TEST_CLIENT_SECRET"]
    TEST_SCOPE         = local.env_vars["TEST_SCOPE"]
    TEST_AUDIENCE      = lookup(local.env_vars, "TEST_AUDIENCE", "")
    TEST_EXPIRED_TOKEN = lookup(local.env_vars, "TEST_EXPIRED_TOKEN", "")
  }

  # Descope-derived CI secrets — source of truth is the existing resources
  # in github.tf. Re-declared here only so the dependabot mirrors can
  # iterate over a single merged map.
  descope_ci_secrets = {
    DESCOPE_DISCO_ADDRESS = "https://api.descope.com/${var.project_id}/.well-known/openid-configuration"
    DESCOPE_JWKS_ADDRESS  = "https://api.descope.com/${var.project_id}/.well-known/jwks.json"
    DESCOPE_CLIENT_ID     = descope_access_key.m2m.client_id
    DESCOPE_CLIENT_SECRET = descope_access_key.m2m.cleartext
    DESCOPE_SCOPE         = "openid"
    DESCOPE_AUDIENCE      = var.project_id
    DESCOPE_EXPIRED_TOKEN = trimspace(data.local_file.expired_token.content)
  }

  # Full set of secrets that must exist in BOTH the actions and dependabot
  # scopes for every CI stage to pass on a dependabot-authored PR.
  dependabot_mirrored_secrets = merge(
    local.ory_test_secrets,
    local.descope_ci_secrets,
  )
}

# --------------------------------------------------------------------------
# Actions scope: new secrets only (existing Descope secrets stay in github.tf).
# --------------------------------------------------------------------------

resource "github_actions_secret" "ory_test" {
  for_each        = local.ory_test_secrets
  repository      = var.github_repository
  secret_name     = each.key
  plaintext_value = each.value
}

# --------------------------------------------------------------------------
# Dependabot scope: mirror everything — Descope and Ory — so the full CI
# matrix passes on dependabot PRs and auto-merge can actually fire.
# --------------------------------------------------------------------------

# nonsensitive() is required because the merged map contains values derived
# from descope_access_key.m2m.cleartext (marked sensitive by the Descope
# provider). Terraform refuses sensitive values in for_each even though
# only the keys (secret names) appear in the plan — the values are still
# write-only in the GitHub provider schema and never shown in output.
resource "github_dependabot_secret" "ci" {
  for_each        = nonsensitive(local.dependabot_mirrored_secrets)
  repository      = var.github_repository
  secret_name     = each.key
  plaintext_value = each.value
}
