"""Optional helpers that build a :class:`~py_identity_model.Config` from strings.

The library never imports this module. Nothing reads the environment unless
you call :func:`config_from_env`. Use these helpers, or write your own, and
pass the resulting ``Config`` in yourself.

Both helpers read the library's environment variable names. Where a setting
has several, the first one that is set wins:

- ``http_timeout``: ``HTTP_TIMEOUT``
- ``http_retry_max_attempts``: ``HTTP_RETRY_MAX_ATTEMPTS``, then ``HTTP_RETRY_COUNT``
- ``http_retry_base_delay``: ``HTTP_RETRY_BASE_DELAY``
- ``ca_bundle``: ``SSL_CERT_FILE``, then ``CURL_CA_BUNDLE``, then ``REQUESTS_CA_BUNDLE``
- ``jwks_max_size``: ``MAX_JWKS_SIZE``
- ``jwks_max_keys``: ``MAX_JWKS_KEYS``
- ``jwks_cache_ttl``: ``JWKS_CACHE_TTL``
- ``jwks_kid_miss_cooldown``: ``KID_MISS_REFRESH_COOLDOWN``
- ``discovery_cache_ttl``: ``DISCO_CACHE_TTL``
- ``cache_max_entries``: ``JWKS_CACHE_MAX_ENTRIES``
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import TYPE_CHECKING, Any

from .core.config import Config, ConfigError, ConfigIssue


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


__all__ = ["config_from_env", "config_from_mapping"]


@dataclass(frozen=True)
class _Setting:
    """One ``Config`` field and the keys that set it."""

    field: str
    keys: tuple[str, ...]  # highest priority first
    convert: Callable[[str], Any]
    invalid: str  # the issue message when ``convert`` fails


def _setting(field: str, *keys: str, kind: type) -> _Setting:
    if kind is int:
        return _Setting(field, keys, int, "must be an integer")
    if kind is float:
        return _Setting(field, keys, float, "must be a number")
    return _Setting(field, keys, str, "")


# In Config's field order, so issues report in the same order as Config's.
_SETTINGS: tuple[_Setting, ...] = (
    _setting("http_timeout", "HTTP_TIMEOUT", kind=float),
    _setting(
        "http_retry_max_attempts",
        "HTTP_RETRY_MAX_ATTEMPTS",
        "HTTP_RETRY_COUNT",
        kind=int,
    ),
    _setting("http_retry_base_delay", "HTTP_RETRY_BASE_DELAY", kind=float),
    _setting(
        "ca_bundle",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        kind=str,
    ),
    _setting("jwks_max_size", "MAX_JWKS_SIZE", kind=int),
    _setting("jwks_max_keys", "MAX_JWKS_KEYS", kind=int),
    _setting("jwks_cache_ttl", "JWKS_CACHE_TTL", kind=float),
    _setting("jwks_kid_miss_cooldown", "KID_MISS_REFRESH_COOLDOWN", kind=float),
    _setting("discovery_cache_ttl", "DISCO_CACHE_TTL", kind=float),
    _setting("cache_max_entries", "JWKS_CACHE_MAX_ENTRIES", kind=int),
)


def config_from_mapping(
    values: Mapping[str, str | None], *, prefix: str = ""
) -> Config:
    """Build a :class:`Config` from string values keyed by variable name.

    Each key is looked up as ``prefix + name``. A key that is missing, empty
    or ``None`` is unset, and its setting keeps the default. When a setting has
    several keys, the first one that is set wins. Other keys are ignored.

    ``None`` values are accepted so the result of python-dotenv's
    ``dotenv_values()`` can be passed straight in.

    Args:
        values: String values, for example ``os.environ`` or a parsed
            ``.env`` file.
        prefix: Prepended to every key name, for example ``"APP_"``.

    Returns:
        The validated ``Config``.

    Raises:
        ConfigError: one error naming every key whose value can't be
            converted or is out of range. Each issue names the key as it
            appears in ``values``, never the value.
    """
    kwargs: dict[str, Any] = {}
    key_for: dict[str, str] = {}
    problems: dict[str, str] = {}
    for setting in _SETTINGS:
        found = _first_set(values, prefix, setting.keys)
        if found is None:
            continue
        key, raw = found
        key_for[setting.field] = key
        try:
            kwargs[setting.field] = setting.convert(raw)
        except ValueError:
            problems[setting.field] = setting.invalid

    try:
        config = Config(**kwargs)
    except ConfigError as exc:
        problems.update({issue.setting: issue.message for issue in exc.issues})
    else:
        if not problems:
            return config
    # Report under the key the caller wrote, in Config's field order.
    raise ConfigError(
        [
            ConfigIssue(key_for[s.field], problems[s.field])
            for s in _SETTINGS
            if s.field in problems
        ]
    ) from None


def config_from_env(prefix: str = "") -> Config:
    """Build a :class:`Config` from the environment.

    The same as ``config_from_mapping(os.environ, prefix=prefix)``.

    Args:
        prefix: Prepended to every variable name, for example ``"APP_"``.

    Returns:
        The validated ``Config``.

    Raises:
        ConfigError: one error naming every invalid variable.
    """
    return config_from_mapping(os.environ, prefix=prefix)


def _first_set(
    values: Mapping[str, str | None], prefix: str, keys: tuple[str, ...]
) -> tuple[str, str] | None:
    """Return the first of ``keys`` (with ``prefix``) that has a value."""
    for name in keys:
        key = prefix + name
        raw = values.get(key)
        if raw:  # missing, None and "" are all unset
            return key, raw
    return None
