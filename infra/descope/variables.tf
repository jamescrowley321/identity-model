variable "project_id" {
  type        = string
  description = "Shared Descope project ID (from identity-stack). Used as audience and in discovery URLs."
}

variable "github_repository" {
  type        = string
  default     = "identity-model"
  description = "GitHub repository name (without owner) for CI secrets. This is the repository name, which is NOT the PyPI package name (py-identity-model) — the repo was renamed and only GitHub's redirect kept the old default working."
}
