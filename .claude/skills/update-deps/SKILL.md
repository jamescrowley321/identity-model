---
name: update-deps
description: Consolidate open dependabot PRs into a single dependency update branch. Use when there are open dependabot PRs to merge.
allowed-tools: Bash, Read, Edit, Write, Glob, Grep, TaskCreate, TaskUpdate, TaskList
---

# Update Dependencies from Dependabot PRs

Consolidate all open dependabot PRs into a single dependency update branch with one commit and one PR.

## Step 1: Gather open dependabot PRs

```bash
gh pr list --state open --author "app/dependabot" --json number,title,headRefName,files
```

If no open PRs, inform the user and stop.

## Step 2: Create a feature branch

```bash
git checkout main
git pull origin main
git checkout -b chore/update-dependencies main
```

## Step 3: Analyze what needs to change

For each dependabot PR, determine if it modifies:
- **`uv.lock` only** — a lockfile-only bump (no version constraint change needed)
- **`pyproject.toml` + `uv.lock`** — a version constraint change

For PRs that modify `pyproject.toml`, read the diff to understand the constraint change:
```bash
gh pr diff <PR_NUMBER> -- pyproject.toml
```

Lint tools such as ruff are not pinned in `.pre-commit-config.yaml`: every hook is a make target running the version in `uv.lock`, so the lock update covers them.

## Step 4: Apply changes

1. For **pyproject.toml constraint changes**: Edit `pyproject.toml` to update the version bounds.
2. Run `uv sync` to regenerate `uv.lock` with all updates at once.
3. Run `uv lock --upgrade` if `uv sync` alone doesn't pick up all the new versions.

## Step 5: Verify

Run these commands and ensure they all pass:

```bash
make lint
make test
```

If tests or lint fail, investigate and fix. Common issues:
- New linter rules from ruff upgrades — run `uv run ruff check --fix src/`
- Type errors from pyrefly upgrades — fix type annotations
- Breaking changes in dependencies — check changelogs from the dependabot PR bodies

## Step 6: Commit and push

Stage only the changed files (typically `pyproject.toml`, `uv.lock`, `.pre-commit-config.yaml`):

```bash
git add pyproject.toml uv.lock .pre-commit-config.yaml
```

Commit with a conventional commit message:

```bash
git commit -m "$(cat <<'EOF'
build: consolidate dependabot dependency updates

<list each update as a bullet point with PR number, package, old version → new version>

Resolves #<PR1>, #<PR2>, ...
EOF
)"
```

Push and create a PR:

```bash
git push -u origin chore/update-dependencies
```

## Step 7: Create the PR

Create the PR with a summary table of all updates:

```bash
gh pr create --title "build: consolidate dependabot dependency updates" --body "$(cat <<'EOF'
## Summary
- Consolidates all N open dependabot PRs into a single dependency update

## Dependency Updates

| PR | Package | Type | Update |
|----|---------|------|--------|
| #N | package-name | runtime/dev/build | old → new |
...

## Test plan
- [ ] All tests pass (`make test`)
- [ ] All linting checks pass (`make lint`)
- [ ] CI passes on PR

Resolves #PR1, #PR2, ...
EOF
)"
```

## Step 8: Close dependabot PRs

After the consolidated PR is merged, the dependabot PRs should auto-close when their referenced issues resolve. If any remain open, close them with a comment:

```bash
gh pr close <PR_NUMBER> --comment "Consolidated into #<NEW_PR_NUMBER>"
```
