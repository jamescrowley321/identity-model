variable "project_id" {
  type        = string
  description = "Shared Descope project ID (from identity-stack). Used as audience and in discovery URLs."

  # Feeds DESCOPE_AUDIENCE, DESCOPE_DISCO_ADDRESS and DESCOPE_JWKS_ADDRESS.
  # The first of those is written by `github_actions_secret.descope_audience`
  # in github.tf, which is not one of the for_each resources carrying the
  # precondition backstop -- so without this the guarantee would hold only for
  # the map-driven writers. An empty project_id also silently produces the
  # syntactically-valid discovery URL "https://api.descope.com//.well-known/...".
  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id must be non-empty; it feeds DESCOPE_AUDIENCE and both DESCOPE_*_ADDRESS secrets."
  }

  # It is interpolated straight into a URL path, so a value carrying a slash or
  # whitespace yields a well-formed but wrong discovery/JWKS address -- which no
  # non-empty check can catch, because the surrounding URL keeps it non-empty.
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]+$", var.project_id))
    error_message = "project_id must be a bare id (letters, digits, _ or -); it is interpolated into the discovery and JWKS URLs."
  }
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
# Every variable below that feeds a GitHub secret is defaultless AND carries a
# non-empty validation. Both halves are load-bearing, for different reasons:
#
#   * Defaultless is what makes the value REQUIRED. On a local interactive
#     apply Terraform prompts for it; on HCP Terraform, which is where this
#     root actually runs (see the `cloud` block in main.tf), there is nobody to
#     prompt, so a missing value fails the run. Either way it cannot be skipped
#     past. With `default = ""` neither happens: the operator is never asked,
#     the run goes green, and a live secret is silently overwritten with "".
#     GitHub secrets are write-only, so the previous value is unrecoverable.
#
#     The practical consequence: each of these needs a workspace variable set
#     in HCP. That is the intended trade -- a failed run beats a blanked
#     secret, because a failed run tells you.
#   * The validation is what rejects an *explicit* empty, which a `-var=x=`
#     flag or a stale tfvars entry can still supply past the prompt.
#
# `test_audience` is the one deliberate exception and keeps its default: an
# empty audience is a real configuration for the Ory client-credentials suite,
# not a missing value.
#
# The two expired-token inputs additionally carry a JWT shape check, because
# non-empty is not enough for them. Their consumer
# (py/src/tests/integration/test_utils.py::_is_valid_jwt_format) *skips* the
# negative test for anything that is not three non-empty dot-separated
# segments. So a well-formed-but-wrong value — a shell error string such as
# `error code: 1010`, which is exactly what Descope's WAF returns for a
# `Python-urllib` User-Agent — would be written to the secret and would disable
# the test proving this library rejects expired JWTs, with CI still green.
# The condition below is deliberately the same rule as `_is_valid_jwt_format`:
# reject here exactly what the consumer would skip on.

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

  validation {
    condition = alltrue([
      for part in split(".", var.descope_expired_token) : length(part) > 0
      ]) && length(split(".", var.descope_expired_token)) == 3 && (
      # Reject surrounding whitespace rather than tolerating it. A value pasted
      # into an HCP variable with a trailing newline splits into three non-empty
      # segments, so it passes the shape check, is written verbatim, and then
      # fails decoding at validate_token -- surfacing as a library base64 bug
      # rather than as "re-mint the token".
      var.descope_expired_token == trimspace(var.descope_expired_token)
    )
    error_message = "descope_expired_token must be a JWT (three non-empty dot-separated segments). A non-JWT value is written to the secret and then silently SKIPS the expiry-rejection test -- check for a WAF error body such as 'error code: 1010'."
  }
}

variable "test_disco_address" {
  type        = string
  description = "Ory discovery endpoint for the TEST_* integration suite"

  validation {
    condition     = length(trimspace(var.test_disco_address)) > 0
    error_message = "test_disco_address must be non-empty; refusing to blank the live CI secret."
  }
}

variable "test_jwks_address" {
  type        = string
  description = "Ory JWKS endpoint for the TEST_* integration suite"

  validation {
    condition     = length(trimspace(var.test_jwks_address)) > 0
    error_message = "test_jwks_address must be non-empty; refusing to blank the live CI secret."
  }
}

variable "test_client_id" {
  type        = string
  description = "Ory client id for the TEST_* integration suite"

  validation {
    condition     = length(trimspace(var.test_client_id)) > 0
    error_message = "test_client_id must be non-empty; refusing to blank the live CI secret."
  }
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

  validation {
    condition     = length(trimspace(var.test_scope)) > 0
    error_message = "test_scope must be non-empty; refusing to blank the live CI secret."
  }
}

variable "test_audience" {
  type        = string
  default     = ""
  description = <<-EOT
    Audience for the TEST_* integration suite.

    The deliberate exception to the defaultless rule above: an empty audience is
    a real configuration for this suite, not a missing value, and it matches the
    previous lookup() default. Consumers read it with `or None` and simply do not
    assert an audience -- no test is skipped by an empty value here.
  EOT
}

variable "test_expired_token" {
  type        = string
  sensitive   = true
  description = <<-EOT
    An already-expired Ory token for the negative test cases.

    Defaultless and shape-checked for the reason given above: this feeds the
    write-only TEST_EXPIRED_TOKEN secret, and its consumers skip rather than
    fail when it is blank or not a JWT.
  EOT

  validation {
    condition     = length(trimspace(var.test_expired_token)) > 0
    error_message = "test_expired_token must be non-empty; refusing to blank the live CI secret."
  }

  validation {
    condition = alltrue([
      for part in split(".", var.test_expired_token) : length(part) > 0
      ]) && length(split(".", var.test_expired_token)) == 3 && (
      # Reject surrounding whitespace rather than tolerating it. A value pasted
      # into an HCP variable with a trailing newline splits into three non-empty
      # segments, so it passes the shape check, is written verbatim, and then
      # fails decoding at validate_token -- surfacing as a library base64 bug
      # rather than as "re-mint the token".
      var.test_expired_token == trimspace(var.test_expired_token)
    )
    error_message = "test_expired_token must be a JWT (three non-empty dot-separated segments). A non-JWT value is written to the secret and then silently SKIPS the expiry-rejection test."
  }
}
