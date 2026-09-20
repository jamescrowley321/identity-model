# Push Descope credentials to GitHub Actions so CI stays in sync
# whenever resources are recreated.
#
# Every resource here carries the same precondition as the for_each writers in
# github_ci_secrets.tf, and it has to be here rather than only on the mirror.
# These are the ACTIONS-scope secrets the integration-tests-descope job reads,
# and two of them (client id, client secret) come from
# `descope_access_key.m2m`, whose attributes are UNKNOWN at plan time when the
# key is recreated. An unknown value defers its check to apply, and Terraform
# applies independent resources concurrently -- so the mirror aborting is no
# protection: the unguarded actions-scope write can land first. GitHub secrets
# are write-only, so that write is unrecoverable.

resource "github_actions_secret" "descope_disco_address" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_DISCO_ADDRESS"
  plaintext_value = "https://api.descope.com/${var.project_id}/.well-known/openid-configuration"

  lifecycle {
    precondition {
      condition     = length(trimspace(var.project_id)) > 0
      error_message = "Refusing to write an empty DESCOPE_DISCO_ADDRESS: the secret is write-only, so this would destroy the live value."
    }
  }
}

resource "github_actions_secret" "descope_jwks_address" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_JWKS_ADDRESS"
  plaintext_value = "https://api.descope.com/${var.project_id}/.well-known/jwks.json"

  lifecycle {
    precondition {
      condition     = length(trimspace(var.project_id)) > 0
      error_message = "Refusing to write an empty DESCOPE_JWKS_ADDRESS: the secret is write-only, so this would destroy the live value."
    }
  }
}

resource "github_actions_secret" "descope_client_id" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_CLIENT_ID"
  plaintext_value = descope_access_key.m2m.client_id

  lifecycle {
    precondition {
      condition     = length(trimspace(descope_access_key.m2m.client_id)) > 0
      error_message = "Refusing to write an empty DESCOPE_CLIENT_ID: the secret is write-only, so this would destroy the live value."
    }
  }
}

resource "github_actions_secret" "descope_client_secret" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_CLIENT_SECRET"
  plaintext_value = descope_access_key.m2m.cleartext

  lifecycle {
    precondition {
      condition     = length(trimspace(descope_access_key.m2m.cleartext)) > 0
      error_message = "Refusing to write an empty DESCOPE_CLIENT_SECRET: the secret is write-only, so this would destroy the live value."
    }
  }
}

resource "github_actions_secret" "descope_scope" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_SCOPE"
  plaintext_value = "openid"
}

resource "github_actions_secret" "descope_audience" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_AUDIENCE"
  plaintext_value = var.project_id

  lifecycle {
    precondition {
      condition     = length(trimspace(var.project_id)) > 0
      error_message = "Refusing to write an empty DESCOPE_AUDIENCE: the secret is write-only, so this would destroy the live value."
    }
  }
}

# The expired token is an input, not something minted here.
#
# This was a `local-exec` provisioner that curled the access-key exchange,
# wrote the JWT to ${path.module}/expired_token.txt, and read it back through
# `data "local_file"`. The provisioner runs on APPLY and the data source is
# read on PLAN, the file is gitignored, and HCP rebuilds its run environment
# every run — so it only ever worked from one directory on one laptop.
#
# It also failed open: the command ended in `.get('sessionJwt','')`, so any API
# error wrote an EMPTY token and the apply went green while blanking the
# DESCOPE_EXPIRED_TOKEN secret. The variable has a non-empty validation instead.
resource "github_actions_secret" "descope_expired_token" {
  repository      = var.github_repository
  secret_name     = "DESCOPE_EXPIRED_TOKEN"
  plaintext_value = var.descope_expired_token

  lifecycle {
    precondition {
      condition     = length(trimspace(var.descope_expired_token)) > 0
      error_message = "Refusing to write an empty DESCOPE_EXPIRED_TOKEN: the secret is write-only, so this would destroy the live value."
    }
  }
}
