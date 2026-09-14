#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["playwright>=1.40"]
# ///
"""Rotate the OIDC conformance-suite API token and push it to the GitHub repo secret.

Target service: https://www.certification.openid.net/

Why this exists
---------------
The OIDF certification server exposes a REST API (`/api/plan`, `/api/runner`,
`/api/info`, `/api/plan/{id}/certificationpackage`) that is authenticated via a
Bearer token. Tokens are created via a single interactive step: log in to the
suite via Google or GitLab OIDC in a browser, navigate to the API token
management page, and click "Create". Everything after that (running the test
plans, publishing the certification package) is plain HTTP against the REST
API using the Bearer token.

This script automates the token creation + storage half of that workflow so
token rotation is reproducible and the resulting secret lands in the GitHub
Actions secret CI actually reads, instead of a `.env` file on someone's laptop.

Flow
----
1. Launch Chromium with a persistent user-data dir (so OIDC sessions stick).
2. Navigate to https://www.certification.openid.net/.
3. If not logged in, wait for the operator to complete the OIDC flow
   interactively (Google/GitLab). First run is always headful.
4. Navigate to the token management page and create a new API token.
5. Capture the token value from the UI.
6. Push the value to the repo's GitHub Actions secret via `gh secret set`.

Prerequisites
-------------
- Python 3.10+
- uv (https://docs.astral.sh/uv/) for the PEP 723 inline script runner
- Playwright Chromium browser binary:
      uv run --with playwright playwright install chromium
- GitHub CLI (https://cli.github.com/) authenticated as a repo admin
  (`gh auth login`) on the target repository.

Usage
-----
First run (interactive OIDC login — browser opens, you sign in manually):

      uv run conformance/scripts/rotate_conformance_token.py

Subsequent runs (persistent profile keeps you logged in, can be headless):

      uv run conformance/scripts/rotate_conformance_token.py --headless

Check the login/session without minting a token or writing the secret:

      uv run conformance/scripts/rotate_conformance_token.py --dry-run

The token is never printed and never written to disk. It goes from the browser
straight into the repository secret and is then discarded. GitHub secrets cannot
be read back, so if a local copy is ever genuinely needed that should be a
deliberate decision rather than a side effect of rotating.

Environment variables
---------------------
CONFORMANCE_TOKEN_REPO  GitHub repository (owner/name) to write the secret to
                        (default: jamescrowley321/identity-model)
CONFORMANCE_TOKEN_NAME  Secret name within the repository
                        (default: CONFORMANCE_TOKEN)
PLAYWRIGHT_PROFILE_DIR Override the persistent browser profile directory
                       (default: ~/.cache/py-identity-model/playwright-profile)

Design notes
------------
- **Persistent profile over headless auth**: Google and GitLab both actively
  block headless Chromium on login pages (UA detection + "this browser or app
  may not be secure" blocks). Letting the operator sign in once in a headful
  session and reusing the cookie jar is far more reliable than trying to
  defeat the bot detection. First run is interactive; subsequent runs can
  be headless as long as the session cookie is still valid.

- **REST API token creation**: After login, the script calls ``POST
  /api/token {"permanent": true}`` using the browser's authenticated
  session cookies. This is more robust than scraping the token management
  UI — the REST API is a stable contract defined in ``TokenApi.java`` and
  doesn't break when the UI is restyled. The response JSON is parsed
  defensively, trying common field names (``token``, ``value``,
  ``access_token``) and falling back to heuristic extraction if the field
  name changes.

- **Push via the gh CLI, not the REST API**: writing a GitHub secret over
  the REST API means fetching the repo public key and sealing the value with
  libsodium. The `gh` CLI does that, plus auth, in one command. Shelling out
  is fine for a script that runs occasionally under human supervision.

- **Why not a secret store**: this previously pushed to HCP Vault Secrets,
  which HashiCorp has since end-of-lifed — the `hcp vault-secrets` commands
  and the provider resources backing them are gone. Writing straight to the
  GitHub secret removes a hop and targets the thing CI actually reads. If a
  secret store is introduced later, it fronts this rather than replacing it.

- **No credentials in the script**: The script never reads Google/GitLab
  passwords from environment variables. All user auth happens in the
  browser the operator controls.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys

from playwright.sync_api import Page, sync_playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError


logger = logging.getLogger("conformance-token")

SUITE_URL = "https://www.certification.openid.net/"
HTTP_FORBIDDEN = 403
DEFAULT_PROFILE_DIR = (
    Path.home() / ".cache" / "py-identity-model" / "playwright-profile"
)
DEFAULT_REPO = "jamescrowley321/identity-model"
DEFAULT_SECRET_NAME = "CONFORMANCE_TOKEN"
DEFAULT_TOKEN_DESCRIPTION = "py-identity-model automation (Playwright-rotated)"

LOGIN_WAIT_TIMEOUT_MS = 5 * 60 * 1000  # 5 minutes
UI_INTERACTION_TIMEOUT_MS = 30 * 1000  # 30 seconds

# Minimum token length below which we treat the value as untrustworthy and
# refuse to render even a partial mask on stderr. The hosted suite issues
# ~40-char Bearer tokens; anything shorter than this likely indicates a bug
# in the extraction path rather than a real secret.
MIN_MASKABLE_TOKEN_LEN = 12


@dataclass
class RotateConfig:
    """Runtime config for a single rotation run."""

    profile_dir: Path
    headless: bool
    dry_run: bool
    repo: str
    secret_name: str
    token_description: str


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rotate the OIDC conformance suite API token and push it to the "
            "repository's GitHub Actions secret."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=(
            "Run Chromium headless. Only works if a prior interactive run has "
            "already captured the OIDC session cookies in the profile dir."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Check the authenticated session without creating a token or "
            "writing the GitHub secret."
        ),
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=None,
        help=f"Playwright profile dir override (default: {DEFAULT_PROFILE_DIR}).",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("CONFORMANCE_TOKEN_REPO", DEFAULT_REPO),
        help=f"Target GitHub repository, owner/name (default: {DEFAULT_REPO}).",
    )
    parser.add_argument(
        "--secret-name",
        default=os.environ.get("CONFORMANCE_TOKEN_NAME", DEFAULT_SECRET_NAME),
        help=f"Secret name within the repository (default: {DEFAULT_SECRET_NAME}).",
    )
    parser.add_argument(
        "--description",
        default=DEFAULT_TOKEN_DESCRIPTION,
        help="Description attached to the new token in the conformance UI.",
    )
    return parser.parse_args(argv)


def build_config(ns: argparse.Namespace) -> RotateConfig:
    profile_dir = ns.profile_dir or Path(
        os.environ.get("PLAYWRIGHT_PROFILE_DIR", str(DEFAULT_PROFILE_DIR))
    )
    return RotateConfig(
        profile_dir=profile_dir,
        headless=ns.headless,
        dry_run=ns.dry_run,
        repo=ns.repo,
        secret_name=ns.secret_name,
        token_description=ns.description,
    )


# ---------------------------------------------------------------------------
# Browser automation
# ---------------------------------------------------------------------------


def create_token_in_browser(cfg: RotateConfig) -> str | None:
    """Launch Playwright, let the user log in if needed, create a token via the UI.

    Returns ``None`` under ``--dry-run``: the session is established and checked,
    but no token is minted. Minting on a dry run left a *permanent* token on the
    OIDF certification account every time — and because the token is never
    printed (4728e4b), each one was unidentifiable and so unrevokable.
    """
    cfg.profile_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(cfg.profile_dir),
            headless=cfg.headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        try:
            page = context.new_page() if not context.pages else context.pages[0]
            page.set_default_timeout(UI_INTERACTION_TIMEOUT_MS)
            page.goto(SUITE_URL, wait_until="networkidle")

            if _needs_login(page):
                if cfg.headless:
                    raise RuntimeError(
                        "Not logged in and running headless. Re-run without --headless "
                        "to complete the OIDC login interactively — the persistent "
                        "profile will remember the session for subsequent runs."
                    )
                print(
                    "Please complete the OIDC login (Google or GitLab) in the "
                    "browser window. Waiting up to 5 minutes.",
                    file=sys.stderr,
                )
                _wait_until_logged_in(page, LOGIN_WAIT_TIMEOUT_MS)
                print("Login detected.", file=sys.stderr)

            if cfg.dry_run:
                print(
                    "--dry-run: authenticated session confirmed; no token minted.",
                    file=sys.stderr,
                )
                return None
            print("Creating API token...", file=sys.stderr)
            return _create_api_token(page, cfg.token_description)
        finally:
            context.close()


def _needs_login(page: Page) -> bool:
    """Return True if the suite is showing an unauthenticated landing page.

    The suite's front page renders a prominent "Login" link in the nav bar
    when the session is unauthenticated and hides it once signed in. We use
    that as the authentication heuristic.
    """
    login_locator = page.get_by_role("link", name="Login")
    return login_locator.count() > 0 and login_locator.first.is_visible()


def _wait_until_logged_in(page: Page, timeout_ms: int) -> None:
    """Block until the Login link disappears or the user's name appears."""
    page.wait_for_function(
        """
        () => {
            const links = Array.from(document.querySelectorAll('a, button'));
            const login = links.find(el => el.textContent.trim().toLowerCase() === 'login');
            return !login || login.offsetParent === null;
        }
        """,
        timeout=timeout_ms,
    )


def _create_api_token(page: Page, description: str) -> str:
    """Create an API token via the suite's REST API using the browser session.

    Uses ``POST /api/token`` with the browser's authenticated session cookies
    rather than scraping the token management UI. This is more robust than
    UI selectors because the REST API is a stable contract defined in the
    suite's ``TokenApi.java`` — it doesn't change when the UI is restyled.

    The browser context's ``request`` API automatically includes the session
    cookies established during the OIDC login, so the POST is authenticated
    without any extra header work.

    ``TokenApi.java`` accepts ``{"permanent": true}`` to create a long-lived
    token. The response is a JSON object containing the token details.
    """
    api_url = SUITE_URL + "api/token"
    logger.info("Creating API token via POST %s", api_url)

    response = page.request.post(
        api_url,
        data=json.dumps({"permanent": True}),
        headers={"Content-Type": "application/json"},
    )

    if response.status == HTTP_FORBIDDEN:
        raise RuntimeError(
            "POST /api/token returned 403 Forbidden. The authenticated user "
            "may be an admin or private-link user, which the suite restricts "
            "from creating API tokens. Try a different Google/GitLab account."
        )

    if not response.ok:
        raise RuntimeError(
            f"POST /api/token failed: HTTP {response.status}\n"
            f"  body: {response.text()[:500]}"
        )

    body = response.json()
    logger.info(
        "Token API response keys: %s",
        list(body.keys()) if isinstance(body, dict) else type(body).__name__,
    )

    # The response structure from TokenService is not publicly documented.
    # Try common field names in priority order. Log the full key set on
    # failure so the operator can identify the right field.
    token_value = None
    if isinstance(body, dict):
        for field in ("token", "value", "access_token", "accessToken", "owner"):
            if (
                field in body
                and isinstance(body[field], str)
                and len(body[field]) > MIN_MASKABLE_TOKEN_LEN
            ):
                token_value = body[field]
                break

        # If no known field matched, check if the response itself IS the
        # token string (some APIs return a bare string).
        if token_value is None:
            # Last resort: dump all string fields for debugging
            string_fields = {
                k: v
                for k, v in body.items()
                if isinstance(v, str) and len(v) > MIN_MASKABLE_TOKEN_LEN
            }
            if len(string_fields) == 1:
                token_value = next(iter(string_fields.values()))
                logger.info(
                    "Extracted token from field '%s' (not a known field name)",
                    next(iter(string_fields.keys())),
                )
            elif string_fields:
                raise RuntimeError(
                    f"POST /api/token succeeded but multiple candidate token "
                    f"fields found: {list(string_fields.keys())}. Update the "
                    f"field priority list in _create_api_token()."
                )
    elif isinstance(body, str) and len(body) > MIN_MASKABLE_TOKEN_LEN:
        token_value = body

    if not token_value:
        raise RuntimeError(
            f"POST /api/token succeeded (HTTP {response.status}) but no token "
            f"value could be extracted from the response.\n"
            f"  response keys: {list(body.keys()) if isinstance(body, dict) else 'N/A'}\n"
            f"  response type: {type(body).__name__}\n"
            f"Update _create_api_token() to handle this response format."
        )

    return token_value.strip()


# ---------------------------------------------------------------------------
# GitHub secret push
# ---------------------------------------------------------------------------


def push_to_github_secret(token: str, repo: str, secret_name: str) -> None:
    """Store the token as a GitHub Actions secret via the `gh` CLI.

    Passes the value on stdin so the token never appears on the process's
    command line (which would be visible to other users via ``ps`` on shared
    systems).
    """
    gh_path = _ensure_gh_cli_available()

    cmd = [
        gh_path,
        "secret",
        "set",
        secret_name,
        "--repo",
        repo,
        "--body-file",
        "-",
    ]
    result = subprocess.run(  # noqa: S603 — CLI invocation, argv is fully controlled above
        cmd,
        input=token,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"gh CLI failed (exit {result.returncode}).\n"
            f"  stderr: {result.stderr.strip()}\n"
            f"  stdout: {result.stdout.strip()}"
        )


def _ensure_gh_cli_available() -> str:
    """Verify the `gh` CLI is installed and authenticated, return its resolved path.

    Returns the absolute path to the ``gh`` binary as resolved by
    :func:`shutil.which` so subsequent ``subprocess.run`` calls pass an
    absolute argv[0] and don't rely on PATH lookups at the subprocess
    boundary. Raises RuntimeError with an actionable message if the CLI is
    missing or unauthenticated. We do not attempt to run ``gh auth login``
    automatically because that would itself require an interactive flow and
    is out of scope for this script.
    """
    gh_path = shutil.which("gh")
    if gh_path is None:
        raise RuntimeError(
            "gh CLI not found on PATH. Install it from https://cli.github.com/."
        )
    try:
        subprocess.run(  # noqa: S603 — argv is fully controlled above
            [gh_path, "auth", "status"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        # Use errors="replace" to survive binaries that emit non-UTF-8
        # bytes in their error output (corrupt builds, unusual locales,
        # binary garbage on unexpected failures). A bare .decode() would
        # raise UnicodeDecodeError, which would escape both this handler
        # and main()'s RuntimeError catch, crashing with a traceback
        # instead of a clean error message.
        stderr_text = exc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"gh CLI is not authenticated. Run `gh auth login`.\n  {stderr_text}"
        ) from exc
    return gh_path


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def rotate_token(cfg: RotateConfig) -> None:
    print(f"Rotating the conformance token via {SUITE_URL}", file=sys.stderr)
    print(f"  profile dir: {cfg.profile_dir}", file=sys.stderr)
    print(f"  target repo: {cfg.repo}", file=sys.stderr)

    token = create_token_in_browser(cfg)
    if token is None:
        print(
            "--dry-run set; no token was created and the repository secret was "
            "left unchanged.",
            file=sys.stderr,
        )
        return
    print("Token created successfully.", file=sys.stderr)

    push_to_github_secret(token, cfg.repo, cfg.secret_name)
    print("Repository secret updated.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    try:
        cfg = build_config(parse_args(argv))
        rotate_token(cfg)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PlaywrightTimeoutError as exc:
        print(f"browser timeout: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
