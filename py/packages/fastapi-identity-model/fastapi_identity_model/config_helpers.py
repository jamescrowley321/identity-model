"""Optional helper that builds :class:`~fastapi_identity_model.OIDCSettings` from the environment.

The package never imports this module. Nothing reads the environment unless
you call :func:`oidc_settings_from_env`. Use it, or construct ``OIDCSettings``
yourself, and pass the settings in.
"""

from __future__ import annotations

import os

from py_identity_model import TokenBinding

from .config import OIDCSettings


__all__ = ["oidc_settings_from_env"]


def _audiences(value: str | None) -> list[str]:
    # Entries are kept as given (stripped); an empty entry ("a,,b" or a
    # trailing comma) reaches OIDCSettings and is rejected there.
    if not value:
        return []
    return [entry.strip() for entry in value.split(",")]


def _flag(name: str) -> bool:
    value = os.environ.get(name, "")
    if value.lower() in ("", "false"):
        return False
    if value.lower() == "true":
        return True
    raise ValueError(f"{name} must be 'true' or 'false'; got {value!r}")


def oidc_settings_from_env(prefix: str = "OIDC_") -> OIDCSettings:
    """Build settings from environment variables (e.g. ``OIDC_DISCOVERY_URL``).

    Required: ``{prefix}DISCOVERY_URL``, ``{prefix}CLIENT_ID``. ``REDIRECT_URI``
    is required only for the login router; a resource-server-only deployment
    may omit it. ``EXCLUDED_PATHS`` is a comma-separated list.
    ``REQUIRED_BINDING`` is ``none``, ``dpop`` or ``mtls``.
    ``CLIENT_CERTIFICATE_HEADER`` names the header carrying the mTLS client
    certificate; ``EXPECTED_ORIGIN`` is the ``scheme://host[:port]`` for the
    DPoP ``htu`` check. ``TRUSTED_AUDIENCES`` is a comma-separated list of
    extra ID Token audiences the login callback accepts; ``VALIDATE_AZP`` is
    ``true`` or ``false``. Others fall back to the ``OIDCSettings`` defaults.

    Raises:
        ValueError: A required variable is unset or empty,
            ``REQUIRED_BINDING`` is not a ``TokenBinding`` value,
            ``EXPECTED_ORIGIN`` is not an http(s) origin,
            ``TRUSTED_AUDIENCES`` has an empty entry, or ``VALIDATE_AZP`` is
            not ``true`` or ``false``.
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
        audience_override=os.environ.get(f"{prefix}AUDIENCE"),
        post_login_redirect=os.environ.get(f"{prefix}POST_LOGIN_REDIRECT", "/"),
        post_logout_redirect=os.environ.get(f"{prefix}POST_LOGOUT_REDIRECT", "/"),
        required_binding=TokenBinding(
            os.environ.get(f"{prefix}REQUIRED_BINDING") or TokenBinding.NONE.value
        ),
        client_certificate_header=(
            os.environ.get(f"{prefix}CLIENT_CERTIFICATE_HEADER") or None
        ),
        expected_origin=os.environ.get(f"{prefix}EXPECTED_ORIGIN") or None,
        trusted_audiences=_audiences(os.environ.get(f"{prefix}TRUSTED_AUDIENCES")),
        validate_azp=_flag(f"{prefix}VALIDATE_AZP"),
        **extra,
    )
