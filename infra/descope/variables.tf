variable "project_id" {
  type        = string
  description = "Shared Descope project ID (from identity-stack). Used as audience and in discovery URLs."
}

variable "github_repository" {
  type        = string
  default     = "identity-model"
  description = "GitHub repository name (without owner) for CI secrets. This is the repository name, which is NOT the PyPI package name (py-identity-model) — the repo was renamed and only GitHub's redirect kept the old default working."
}

variable "sonar_token" {
  type        = string
  default     = ""
  sensitive   = true
  description = "SonarCloud project token. Provision via https://sonarcloud.io/account/security and supply as TF_VAR_sonar_token. Leave empty to skip mirroring SONAR_TOKEN."
}

variable "enable_branch_protection" {
  type        = bool
  default     = false
  description = <<-EOT
    Toggle branch protection on `main`. Leave false until a dependabot PR
    has been observed running fully green so required_status_check_contexts
    can be populated with the exact check names.
  EOT
}

variable "required_status_check_contexts" {
  type        = list(string)
  default     = []
  description = "List of status check contexts that must pass before a PR to main can be merged. Only used when enable_branch_protection is true."
}

variable "required_approving_review_count" {
  type        = number
  default     = 0
  description = "Number of approving reviews required before merge. Dependabot PRs are auto-merged; if set > 0, they stall until manually approved."
}
