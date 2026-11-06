"""Optional helper that builds :class:`~fastapi_identity_model.OIDCSettings` from the environment.

The package never imports this module. Nothing reads the environment unless
you call :func:`oidc_settings_from_env`. Use it, or construct ``OIDCSettings``
yourself, and pass the settings in.
"""

from __future__ import annotations

import os

from .config import OIDCSettings


__all__ = ["oidc_settings_from_env"]


def oidc_settings_from_env(prefix: str = "OIDC_") -> OIDCSettings:
    """Build settings from environment variables (e.g. ``OIDC_DISCOVERY_URL``).

    Required: ``{prefix}DISCOVERY_URL``, ``{prefix}CLIENT_ID``. ``REDIRECT_URI``
    is required only for the login router; a resource-server-only deployment
    may omit it. ``EXCLUDED_PATHS`` is a comma-separated list. Others fall back
    to the ``OIDCSettings`` defaults.

    Raises:
        ValueError: A required variable is unset or empty.
    """

    def _req(name: str) -> str:
        value = os.environ.get(f"{prefix}{name}")
        if not value:
            raise ValueError(f"Missing required env var {prefix}{name}")
        return value

    excluded = os.environ.get(f"{prefix}EXCLUDED_PATHS")
    # Unset keeps the OIDCSettings default list.
    extra = (
        {"excluded_paths": [p.strip() for p in excluded.split(",") if p.strip()]}
        if excluded
        else {}
    )
    return OIDCSettings(
        discovery_url=_req("DISCOVERY_URL"),
        client_id=_req("CLIENT_ID"),
        redirect_uri=os.environ.get(f"{prefix}REDIRECT_URI", ""),
        client_secret=os.environ.get(f"{prefix}CLIENT_SECRET"),
        scope=os.environ.get(f"{prefix}SCOPE", "openid profile email"),
        audience=os.environ.get(f"{prefix}AUDIENCE"),
        post_login_redirect=os.environ.get(f"{prefix}POST_LOGIN_REDIRECT", "/"),
        post_logout_redirect=os.environ.get(f"{prefix}POST_LOGOUT_REDIRECT", "/"),
        **extra,
    )
