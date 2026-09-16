# Forget the branch-protection rule; do NOT destroy it.
#
# This root used to manage github_branch_protection.main, and the rule is still
# in this workspace's state. identity-model#674 removed the resource from the
# configuration because ownership moved to oss-admin
# (terraform/identity-model, workspace identity-model-github), which imported
# the live rule on 2026-09-16.
#
# Removing a resource from configuration while it remains in state makes the
# next plan DESTROY it. That plan was real: this workspace planned
# "github_branch_protection.main[0] will be destroyed", which would have deleted
# branch protection on identity-model's default branch while oss-admin's state
# still believed it owned a live rule.
#
# `destroy = false` drops it from state and leaves the real rule untouched,
# which is what a hand-off between roots requires. It is also the only safe
# mechanism here: `terraform state rm` fails against this workspace because its
# TFC state version carries a null lineage.
#
# Delete this block once an apply has run and the resource is out of state.
removed {
  from = github_branch_protection.main

  lifecycle {
    destroy = false
  }
}
