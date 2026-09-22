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
#    no declarative source. They are workspace inputs — see variables.tf for
#    why they are no longer read from the repo-root `.env`.

locals {
  # Ory / local fixture credentials mirrored to CI. These map 1:1 to the
  # `TEST_*` secret names referenced in .github/workflows/ci.yml. They used to
  # be parsed out of the repo-root `.env`, which no remote runner can see.
  ory_test_secrets = {
    TEST_DISCO_ADDRESS = var.test_disco_address
    TEST_JWKS_ADDRESS  = var.test_jwks_address
    TEST_CLIENT_ID     = var.test_client_id
    TEST_CLIENT_SECRET = var.test_client_secret
    TEST_SCOPE         = var.test_scope
    TEST_AUDIENCE      = var.test_audience
    TEST_EXPIRED_TOKEN = var.test_expired_token
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
    DESCOPE_EXPIRED_TOKEN = var.descope_expired_token
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

  # Backstop for the per-variable validations in variables.tf. Those cover the
  # inputs that exist today; this covers whatever is added to these maps
  # tomorrow, including values derived from other resources rather than from
  # variables. A blank write is unrecoverable: GitHub secrets are write-only,
  # so the previous value cannot be read back to restore it.
  #
  # TEST_AUDIENCE is the single exemption -- an empty audience is a real
  # configuration for this suite, not a missing value. See variables.tf.
  lifecycle {
    precondition {
      condition     = each.key == "TEST_AUDIENCE" || length(trimspace(each.value)) > 0
      error_message = "Refusing to write an empty value to CI secret ${each.key}: GitHub secrets are write-only, so this would silently destroy the live value and leave the suite it feeds skipping green."
    }
  }
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

  # Backstop for the per-variable validations in variables.tf. Those cover the
  # inputs that exist today; this covers whatever is added to these maps
  # tomorrow, including values derived from other resources rather than from
  # variables. A blank write is unrecoverable: GitHub secrets are write-only,
  # so the previous value cannot be read back to restore it.
  #
  # TEST_AUDIENCE is the single exemption -- an empty audience is a real
  # configuration for this suite, not a missing value. See variables.tf.
  lifecycle {
    precondition {
      condition     = each.key == "TEST_AUDIENCE" || length(trimspace(each.value)) > 0
      error_message = "Refusing to write an empty value to CI secret ${each.key}: GitHub secrets are write-only, so this would silently destroy the live value and leave the suite it feeds skipping green."
    }
  }
}
