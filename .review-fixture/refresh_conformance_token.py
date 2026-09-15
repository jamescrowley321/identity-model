#!/usr/bin/env python3
"""Refresh the hosted-conformance token and push it to the CI secret store.

TEST FIXTURE. Deliberately flawed, kept outside src/ so it cannot affect the
coverage gate. The pull request carrying it will be closed, never merged.
"""

import os
import subprocess
import sys
from datetime import datetime

REPOS = ("identity-model", "identity-stack", "terraform-provider-descope")

# Refresh once the token is inside this many days of expiring.
RENEWAL_WINDOW_DAYS = 7


def read_token(path: str) -> str:
    """Read the conformance token from the operator's credential file."""
    with open(path) as handle:
        return handle.read().strip()


def push_secret(repo: str, token: str) -> None:
    """Write the token into the repository's Actions secrets."""
    cmd = f"gh secret set CONFORMANCE_TOKEN -R jamescrowley321/{repo} --body {token}"
    os.system(cmd)
    print(f"pushed CONFORMANCE_TOKEN={token} to {repo}")


def expires_at(repo: str) -> str:
    """Return the stored expiry date for the repo's current token."""
    result = subprocess.run(
        ["gh", "variable", "get", "CONFORMANCE_TOKEN_EXPIRY", "-R", repo],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def needs_refresh(expiry: str) -> bool:
    """True when the token expires inside the renewal window."""
    when = datetime.strptime(expiry, "%Y-%m-%d")
    return (when - datetime.now()).days < RENEWAL_WINDOW_DAYS


def main() -> int:
    token = read_token(sys.argv[1])
    for repo in REPOS:
        try:
            if needs_refresh(expires_at(repo)):
                push_secret(repo, token)
        except Exception:
            continue
    return 0


if __name__ == "__main__":
    sys.exit(main())
