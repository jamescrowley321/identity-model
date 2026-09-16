variable "project_id" {
  type        = string
  description = "Shared Descope project ID (from identity-stack). Used as audience and in discovery URLs."
}

variable "github_repository" {
  type        = string
  default     = "identity-model"
  description = "GitHub repository name (without owner) for CI secrets. This is the repository name, which is NOT the PyPI package name (py-identity-model) — the repo was renamed and only GitHub's redirect kept the old default working."
}

# --- CI secret inputs --------------------------------------------------------
#
# These were previously read from the developer's local `.env` at the repo root
# via `file("${path.module}/../../.env")`, and the expired token was minted by a
# `local-exec` provisioner into a gitignored file. Both only ever worked from
# one directory on one machine: HCP Terraform rebuilds its run environment from
# the uploaded configuration on every run, so neither the .env nor anything a
# previous apply wrote survives. That is what kept this workspace on
# execution-mode local and out of VCS.
#
# None of these carry a default. An empty default would push an empty string
# into a live CI secret and break the suite it exists to feed, silently.

variable "descope_expired_token" {
  type        = string
  sensitive   = true
  description = <<-EOT
    An already-expired Descope session JWT, for the negative test cases.

    Mint with the access-key exchange, whose session tokens live 3 minutes:

      curl -s -X POST https://api.descope.com/v1/auth/accesskey/exchange \
        -H "Authorization: Bearer $PROJECT_ID:$ACCESS_KEY" \
        -H "Content-Type: application/json" \
        -d '{"loginId": "<client_id>"}'

    Use curl, not a Python stdlib client: Descope's WAF 403s the
    `Python-urllib` User-Agent on every route, and the body reads
    `error code: 1010`, which looks exactly like a rejected access key.

    Expiry does not decay — once expired the token stays valid input for the
    test, so this needs rotating only if the signing key changes.
  EOT

  validation {
    condition     = length(trimspace(var.descope_expired_token)) > 0
    error_message = "descope_expired_token must be non-empty; refusing to blank the live CI secret."
  }
}

variable "test_disco_address" {
  type        = string
  description = "Ory discovery endpoint for the TEST_* integration suite"
}

variable "test_jwks_address" {
  type        = string
  description = "Ory JWKS endpoint for the TEST_* integration suite"
}

variable "test_client_id" {
  type        = string
  description = "Ory client id for the TEST_* integration suite"
}

variable "test_client_secret" {
  type        = string
  sensitive   = true
  description = "Ory client secret for the TEST_* integration suite"

  validation {
    condition     = length(trimspace(var.test_client_secret)) > 0
    error_message = "test_client_secret must be non-empty; refusing to blank the live CI secret."
  }
}

variable "test_scope" {
  type        = string
  description = "Scope requested by the TEST_* integration suite"
}

variable "test_audience" {
  type        = string
  default     = ""
  description = "Audience for the TEST_* integration suite. Empty is a real value here, matching the previous lookup() default."
}

variable "test_expired_token" {
  type        = string
  sensitive   = true
  default     = ""
  description = "An already-expired Ory token for negative tests. Empty is tolerated, matching the previous lookup() default."
}
