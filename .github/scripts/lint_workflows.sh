#!/usr/bin/env bash
#
# Lint the GitHub Actions workflows.
#
# The dependency check below is the point of this wrapper. actionlint shells
# out to shellcheck to lint `run:` blocks, and when shellcheck is ABSENT it
# does not warn, does not degrade loudly, and does not fail -- it exits 0 with
# those findings simply missing. Verified: with `-shellcheck=/nonexistent/...`
# a known SC2011 finding disappears and the exit status is 0.
#
# That is the same failure this repo has been chasing elsewhere: a control that
# cannot fire is indistinguishable from a control that passed. So the presence
# of both tools is asserted rather than assumed, and a missing one is a hard
# error.
#
# Severity floor: shellcheck runs at `warning` and above. `info`/`style` findings
# (mostly SC2086 on values GitHub itself substitutes) are advisory here and are
# not a merge gate; raising the floor is a deliberate, stated policy rather than
# a per-line suppression. Run `shellcheck -S info` by hand to see them.
set -euo pipefail

missing=0
for tool in actionlint shellcheck; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is not on PATH." >&2
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  cat >&2 <<'EOF'

Both tools are required; actionlint silently skips its shell linting without
shellcheck, which would leave this gate reporting success while checking less
than it claims.

  go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
  brew install shellcheck      # or: apt-get install -y shellcheck
EOF
  exit 1
fi

exec actionlint -shellcheck="shellcheck -S warning" "$@"
