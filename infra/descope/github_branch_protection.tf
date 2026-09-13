# Branch protection for identity-model/main.
#
# Gated behind `var.enable_branch_protection` so it can be applied in a
# second pass — the intended sequence is:
#
#   1. terraform apply (secrets only, flag off) — no-op on protection
#   2. Next dependabot PR runs, all CI stages go green, capture exact
#      check names from the rollup
#   3. Set enable_branch_protection = true and populate
#      required_status_check_contexts in the tfvars / env
#   4. terraform apply again — protection goes live
#
# Without this staging, required_status_checks would block every PR on
# names that haven't been observed yet.

resource "github_branch_protection" "main" {
  count = var.enable_branch_protection ? 1 : 0

  repository_id = var.github_repository
  pattern       = "main"

  enforce_admins      = false
  allows_deletions    = false
  allows_force_pushes = false

  required_status_checks {
    strict   = false
    contexts = var.required_status_check_contexts
  }

  required_pull_request_reviews {
    required_approving_review_count = var.required_approving_review_count
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = false
  }
}
