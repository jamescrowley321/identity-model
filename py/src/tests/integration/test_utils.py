import contextlib
import os
from pathlib import Path

from dotenv import dotenv_values, load_dotenv
import pytest

from py_identity_model.aio.http_client import _reset_async_http_client
from py_identity_model.ssl_config import get_ssl_verify
from py_identity_model.sync.http_client import _reset_http_client
import py_identity_model.sync.token_validation as _sync_token_validation


# JWT format: three dot-separated segments
JWT_SEGMENT_SEPARATOR_COUNT = 2


def set_env_file(env_file_path: str | None) -> None:
    """
    Set the environment file to use for configuration.

    Args:
        env_file_path: Path to the environment file, or None to use default
    """
    if env_file_path and Path(env_file_path).is_file():
        # Load the specified env file only if it exists
        load_dotenv(env_file_path, override=True)
    elif Path(".env").is_file():
        # Load default .env file only if it exists
        # Don't load .env.local - it's for local IdentityServer testing only
        load_dotenv(".env", override=True)

    # Clear SSL certificate environment variables for external service testing
    # These may be set in .env.local for local IdentityServer testing but should
    # not be used when testing against external services like Ory.
    #
    # We clear them BEFORE clearing caches to ensure get_ssl_verify() returns
    # the correct value (True for system certificates) on next call.
    os.environ.pop("SSL_CERT_FILE", None)
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    os.environ.pop("CURL_CA_BUNDLE", None)

    # Clear all SSL and HTTP client caches to pick up environment changes.
    # This is safe in parallel execution because each worker has its own process
    # and environment, and this only runs once per session during fixture initialization.
    get_ssl_verify.cache_clear()
    _reset_http_client()
    _reset_async_http_client()


#: spec/config.md CFG-107: booleans accept true/false/1/0 case-insensitively
#: and anything else is an error. Strictness matters more here than for most
#: flags: every unrecognised spelling of "on" would quietly mean *off*, and off
#: is the setting that restores the green-skip this gate exists to remove. A
#: typo must be loud, not permissive.
#:
#: Note the cross-language floor: the Go and Rust harnesses compare against the
#: literal "1" (e.g. rust/tests/discovery.rs). `true` therefore arms Python and
#: leaves those two skipping, so CI must set "1" -- which it does -- until all
#: three share one grammar.
_TRUE = frozenset({"true", "1"})
_FALSE = frozenset({"false", "0", ""})


def _strict_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise RuntimeError(
        f"CFG-003: {name}={raw!r} is not a boolean. Use one of "
        "true/false/1/0 (case-insensitive). Refusing to guess, because "
        "guessing wrong disables a test gate silently."
    )


def _is_valid_jwt_format(token: str) -> bool:
    """Check if a string looks like a JWT (3 dot-separated segments)."""
    return token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT and all(
        len(part) > 0 for part in token.split(".")
    )


def expired_token_or_skip(test_config: dict) -> str:
    """Return the configured expired JWT, failing instead of skipping in CI.

    ``TEST_EXPIRED_TOKEN`` reaches CI as a write-only GitHub secret written by
    ``infra/descope/github_ci_secrets.tf``. Write-only means a blank or
    malformed value cannot be read back and noticed -- and the tests it feeds
    are the ones proving this library *rejects* expired JWTs. Skipping on a
    missing value therefore turns a destroyed credential into a green run with
    the expiry check silently switched off, which is precisely the regression
    those tests exist to catch.

    So: skip locally, where the token is genuinely optional, but under
    ``TEST_REQUIRE_LIVE=1`` -- which the Ory and Descope integration jobs set --
    fail, so the loss surfaces on the job that depends on it.

    The token value is never echoed into the failure message; only its shape is
    described.
    """
    token = test_config.get("TEST_EXPIRED_TOKEN", "")
    if token and _is_valid_jwt_format(token):
        return token

    reason = (
        "TEST_EXPIRED_TOKEN is "
        + ("unset or empty" if not token else "not a valid JWT")
        + " (expected three non-empty dot-separated segments). The expiry-"
        "rejection tests cannot run. Re-mint the token and re-apply "
        "infra/descope -- see infra/descope/variables.tf."
    )
    if test_config.get("TEST_REQUIRE_LIVE"):
        pytest.fail(reason)
    pytest.skip(reason)


@contextlib.contextmanager
def count_upstream_fetches():
    """Count real upstream discovery + JWKS fetches on the sync cached path.

    Wraps — does not replace — the module-level ``get_discovery_document`` and
    ``get_jwks`` names in :mod:`py_identity_model.sync.token_validation`, so the
    genuine upstream fetch still runs (live signature validation keeps working)
    while every round-trip is tallied. A cache *hit* calls neither wrapped
    function, so the tally is a direct, non-timing proof of caching: N
    validations that share a provider must drive exactly ONE discovery and ONE
    JWKS fetch, not N. Clear the caches before entering the block so the first
    validation is a guaranteed miss and the resulting count is deterministic
    regardless of cache state left by earlier tests.

    (HTTP-layer retries live *below* ``get_discovery_document``/``get_jwks``, so
    a transiently-retried fetch is still a single counted call.)

    Yields:
        A live ``{"disco": int, "jwks": int}`` tally, updated as fetches occur.
    """
    real_get_discovery_document = _sync_token_validation.get_discovery_document
    real_get_jwks = _sync_token_validation.get_jwks
    counts = {"disco": 0, "jwks": 0}

    def counting_get_discovery_document(*args, **kwargs):
        counts["disco"] += 1
        return real_get_discovery_document(*args, **kwargs)

    def counting_get_jwks(*args, **kwargs):
        counts["jwks"] += 1
        return real_get_jwks(*args, **kwargs)

    _sync_token_validation.get_discovery_document = counting_get_discovery_document
    _sync_token_validation.get_jwks = counting_get_jwks
    try:
        yield counts
    finally:
        _sync_token_validation.get_discovery_document = real_get_discovery_document
        _sync_token_validation.get_jwks = real_get_jwks


def get_alternate_provider_expired_token() -> str | None:
    """
    Get an expired token from an alternate provider for cross-provider testing.

    Loads the expired token from .env.local which can be used to test that
    tokens from one provider fail validation against another provider's
    discovery endpoint.

    Returns:
        The expired token string, or None if .env.local doesn't exist
    """
    env_local_path = Path(".env.local")
    if not env_local_path.is_file():
        return None

    # Temporarily load .env.local to get the token without affecting current env
    local_config = dotenv_values(env_local_path)
    token = local_config.get("TEST_EXPIRED_TOKEN")
    if token and not _is_valid_jwt_format(token):
        return None
    return token


# Required env vars for integration tests.  Missing any of these will
# fail the ``test_config`` fixture immediately with a clear message
# pointing to ``.env.example``.
_REQUIRED_ENV_VARS = (
    "TEST_DISCO_ADDRESS",
    "TEST_JWKS_ADDRESS",
    "TEST_CLIENT_ID",
    "TEST_CLIENT_SECRET",
    "TEST_SCOPE",
)


def get_config(env_file: str | None = None) -> dict:
    """
    Get test configuration from environment variables.

    Args:
        env_file: Optional path to environment file. If provided, will load
                 this file before returning configuration.

    Returns:
        Dictionary containing test configuration

    Raises:
        RuntimeError: When required environment variables are missing or empty.
    """
    # If env_file parameter is provided, use it
    if env_file is not None:
        set_env_file(env_file)

    config = {
        "TEST_DISCO_ADDRESS": os.environ.get("TEST_DISCO_ADDRESS", ""),
        "TEST_JWKS_ADDRESS": os.environ.get("TEST_JWKS_ADDRESS", ""),
        "TEST_CLIENT_ID": os.environ.get("TEST_CLIENT_ID", ""),
        "TEST_CLIENT_SECRET": os.environ.get("TEST_CLIENT_SECRET", ""),
        "TEST_SCOPE": os.environ.get("TEST_SCOPE", ""),
        "TEST_EXPIRED_TOKEN": os.environ.get("TEST_EXPIRED_TOKEN", ""),
        "TEST_AUDIENCE": os.environ.get("TEST_AUDIENCE", ""),
        "TEST_REQUIRE_HTTPS": os.environ.get("TEST_REQUIRE_HTTPS", "true").lower()
        not in ("false", "0", "no"),
        # spec/config.md tier `test`. Off by default so a developer without the
        # optional credentials still gets a useful local run; CI sets it to 1 so
        # a missing credential is reported rather than skipped past.
        "TEST_REQUIRE_LIVE": _strict_bool(
            "TEST_REQUIRE_LIVE", os.environ.get("TEST_REQUIRE_LIVE", "")
        ),
        # Auth code flow config (optional — used when provider
        # supports devInteractions)
        "TEST_AUTH_CODE_CLIENT_ID": os.environ.get("TEST_AUTH_CODE_CLIENT_ID", ""),
        "TEST_AUTH_CODE_CLIENT_SECRET": os.environ.get(
            "TEST_AUTH_CODE_CLIENT_SECRET", ""
        ),
        "TEST_AUTH_CODE_REDIRECT_URI": os.environ.get(
            "TEST_AUTH_CODE_REDIRECT_URI", ""
        ),
        "TEST_PKCE_PUBLIC_CLIENT_ID": os.environ.get("TEST_PKCE_PUBLIC_CLIENT_ID", ""),
        "TEST_PKCE_PUBLIC_REDIRECT_URI": os.environ.get(
            "TEST_PKCE_PUBLIC_REDIRECT_URI", ""
        ),
        # Opaque token client for introspection/revocation tests
        "TEST_OPAQUE_CLIENT_ID": os.environ.get("TEST_OPAQUE_CLIENT_ID", ""),
        "TEST_OPAQUE_CLIENT_SECRET": os.environ.get("TEST_OPAQUE_CLIENT_SECRET", ""),
        # Dynamic client registration CRUD test (RFC 7591/7592). Admin creds
        # mint a one-shot client-registration initial access token via the
        # provider's admin REST API; the provider realm locates that API.
        "TEST_ADMIN_USERNAME": os.environ.get("TEST_ADMIN_USERNAME", ""),
        "TEST_ADMIN_PASSWORD": os.environ.get("TEST_ADMIN_PASSWORD", ""),
        "TEST_ADMIN_REALM": os.environ.get("TEST_ADMIN_REALM", "master"),
        "TEST_PROVIDER_REALM": os.environ.get("TEST_PROVIDER_REALM", ""),
        # A pre-issued initial access token takes precedence over minting one.
        "TEST_REGISTRATION_INITIAL_ACCESS_TOKEN": os.environ.get(
            "TEST_REGISTRATION_INITIAL_ACCESS_TOKEN", ""
        ),
        # Provider-reachable URL that captures a pushed back-channel logout
        # token (live back-channel logout test); unset skips that test.
        "TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL": os.environ.get(
            "TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL", ""
        ),
    }

    # Fail fast on missing required config
    missing = [var for var in _REQUIRED_ENV_VARS if not config.get(var)]
    if missing:
        raise RuntimeError(
            f"Missing required integration test config: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in values for your OIDC provider."
        )

    return config
