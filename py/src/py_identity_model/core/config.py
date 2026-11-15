"""Plain, typed configuration for py-identity-model.

Two frozen values hold the library's settings, each with the library's
default: :class:`HTTPConfig` for an HTTP client (timeout, retries, TLS, JWKS
size limits) and :class:`CacheConfig` for a validation cache (TTLs, size,
kid-miss cooldown). Each consumer takes only the config it reads, so a setting
can't be passed somewhere that silently ignores it.

Each is validated when it is created: every invalid setting is collected into
one :class:`ConfigError`, and no value is returned. An invalid value is never
replaced by its default.

Neither has loaders or parses strings. Where the values come from
(environment, files, a secrets manager) is the caller's decision; build them
in your own code and pass them in.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import math
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .client_auth_method import ClientAuthMethod
from .http_utils import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_JWKS_KEYS,
    DEFAULT_MAX_JWKS_SIZE,
    DEFAULT_RETRY_BASE_DELAY,
    DEFAULT_RETRY_MAX_ATTEMPTS,
)
from .jwks_cache import (
    DEFAULT_DISCO_CACHE_TTL_SECONDS,
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    DEFAULT_MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_KID_MISS_COOLDOWN_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    MIN_KID_MISS_COOLDOWN_SECONDS,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


__all__ = [
    "CacheConfig",
    "ClientAuthMethod",
    "ConfigError",
    "ConfigIssue",
    "HTTPConfig",
]


# --------------------------------------------------------------------------- #
# Errors                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, kw_only=True)
class ConfigIssue:
    """One invalid setting. Names the setting and the rule, never the value."""

    setting: str
    message: str

    def __str__(self) -> str:
        return f"{self.setting}: {self.message}"


class ConfigError(ValueError):
    """Raised when an :class:`HTTPConfig` or :class:`CacheConfig` is invalid. Carries every issue at once."""

    def __init__(self, issues: Sequence[ConfigIssue]) -> None:
        self.issues: tuple[ConfigIssue, ...] = tuple(issues)
        super().__init__(
            "configuration is invalid:\n"
            + "\n".join(f"  - {issue}" for issue in self.issues)
        )


def require_config[C: (HTTPConfig, CacheConfig)](
    config: object, expected: type[C], consumer: str
) -> C:
    """Return *config*, or ``expected()`` when it is ``None``.

    Raises:
        TypeError: If *config* is another type, for example a
            :class:`CacheConfig` passed to an HTTP client, which would
            otherwise be ignored.
    """
    if config is None:
        return expected()
    if not isinstance(config, expected):
        raise TypeError(
            f"{consumer} takes config={expected.__name__}, not {type(config).__name__}"
        )
    return config


# --------------------------------------------------------------------------- #
# HTTPConfig and CacheConfig                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Range:
    """The valid range of one numeric setting."""

    integer: bool
    lo: float
    lo_exclusive: bool = False
    hi: float | None = None


# Error messages name the rule, never the value (a path or number the caller
# supplied stays out of logs). Bounds are library constants, safe to state.
_RANGES: dict[str, _Range] = {
    "http_timeout": _Range(integer=False, lo=0, lo_exclusive=True),
    "http_retry_max_attempts": _Range(integer=True, lo=0),
    "http_retry_base_delay": _Range(integer=False, lo=0),
    "jwks_max_size": _Range(integer=True, lo=1),
    "jwks_max_keys": _Range(integer=True, lo=1),
    "jwks_cache_ttl": _Range(
        integer=False, lo=MIN_CACHE_TTL_SECONDS, hi=MAX_CACHE_TTL_SECONDS
    ),
    "jwks_kid_miss_cooldown": _Range(
        integer=False,
        lo=MIN_KID_MISS_COOLDOWN_SECONDS,
        hi=MAX_KID_MISS_COOLDOWN_SECONDS,
    ),
    "discovery_cache_ttl": _Range(
        integer=False, lo=MIN_CACHE_TTL_SECONDS, hi=MAX_CACHE_TTL_SECONDS
    ),
    "cache_max_entries": _Range(integer=True, lo=1),
}


def _bound(value: float) -> str:
    return f"{value:g}"


def _check_type(value: object, rule: _Range) -> str | None:
    """Return why ``value`` is not a number of ``rule``'s kind, or None."""
    # bool is an int subclass, but True is not a timeout or a count.
    if rule.integer:
        ok = isinstance(value, int) and not isinstance(value, bool)
        return None if ok else "must be an integer"
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "must be a number"
    try:
        finite = math.isfinite(value)
    except OverflowError:  # an int too large to convert to a float
        finite = False
    return None if finite else "must be a finite number"


def _check_number(value: object, rule: _Range) -> str | None:
    """Return why ``value`` breaks ``rule``, or None when it is valid."""
    problem = _check_type(value, rule)
    if problem is not None:
        return problem
    num = cast("float", value)
    if rule.lo_exclusive and num <= rule.lo:
        problem = f"must be greater than {_bound(rule.lo)}"
    elif not rule.lo_exclusive and num < rule.lo:
        problem = f"must be at least {_bound(rule.lo)}"
    elif rule.hi is not None and num > rule.hi:
        problem = f"must be at most {_bound(rule.hi)}"
    return problem


def _check_ca_bundle(value: object) -> str | None:
    if value is None:
        return None
    problem = "must be a path to a readable file"
    if not isinstance(value, str):
        return problem
    try:
        readable = Path(value).is_file() and os.access(value, os.R_OK)
    except (OSError, ValueError):  # e.g. a name too long, an embedded NUL
        readable = False
    return None if readable else problem


class _ValidatedConfig:
    """Validates every field of a frozen settings dataclass on creation."""

    def __post_init__(self) -> None:
        issues: list[ConfigIssue] = []
        for f in fields(cast("Any", self)):  # field order: issues report in that order
            value = getattr(self, f.name)
            rule = _RANGES.get(f.name)
            problem = (
                _check_number(value, rule)
                if rule is not None
                else _check_ca_bundle(value)
            )
            if problem is not None:
                issues.append(ConfigIssue(setting=f.name, message=problem))
        if issues:
            raise ConfigError(issues)


@dataclass(frozen=True, kw_only=True)
class HTTPConfig(_ValidatedConfig):
    """Settings for an HTTP client, validated on creation.

    Read only by :class:`~py_identity_model.sync.managed_client.HTTPClient`
    and :class:`~py_identity_model.aio.managed_client.AsyncHTTPClient`. Cache
    settings live on :class:`CacheConfig`, which the validation caches read.

    Every field has the library's default, so ``HTTPConfig()`` is a complete,
    valid configuration. Pass typed values (``HTTPConfig(http_timeout=5.0)``);
    strings are not parsed. Fields are keyword-only.

    Attributes:
        http_timeout: Request timeout in seconds. Must be greater than 0.
        http_retry_max_attempts: Retries for a rate-limited or failed request.
            0 disables retries.
        http_retry_base_delay: Base delay in seconds for exponential backoff.
            Each retry's delay is capped at 120 seconds.
        ca_bundle: Path to a CA bundle file used to verify TLS. ``None``
            verifies with the HTTP stack's default bundle. Must be a readable
            file.
        jwks_max_size: Largest JWKS response accepted, in bytes.
        jwks_max_keys: Most keys accepted in one JWKS.

    Raises:
        ConfigError: one error naming every invalid setting.
    """

    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    http_retry_max_attempts: int = DEFAULT_RETRY_MAX_ATTEMPTS
    http_retry_base_delay: float = DEFAULT_RETRY_BASE_DELAY
    ca_bundle: str | None = None
    jwks_max_size: int = DEFAULT_MAX_JWKS_SIZE
    jwks_max_keys: int = DEFAULT_MAX_JWKS_KEYS


@dataclass(frozen=True, kw_only=True)
class CacheConfig(_ValidatedConfig):
    """Settings for a validation cache, validated on creation.

    Read only by :class:`~py_identity_model.sync.validation_cache.ValidationCache`
    and :class:`~py_identity_model.aio.validation_cache.AsyncValidationCache`.
    Transport settings live on :class:`HTTPConfig`.

    Every field has the library's default, so ``CacheConfig()`` is a complete,
    valid configuration. Fields are keyword-only.

    Attributes:
        jwks_cache_ttl: JWKS cache lifetime in seconds, used only when the
            response has no ``Cache-Control: max-age``. 60 to 86400; default
            3600 (1 hour).
        jwks_kid_miss_cooldown: Minimum seconds between JWKS refreshes
            triggered by an unknown ``kid``. 0 to 3600; 0 disables the
            cooldown.
        discovery_cache_ttl: Discovery cache lifetime in seconds, used only
            when the response has no ``Cache-Control: max-age``. 60 to 86400.
        cache_max_entries: Most providers held by each of the JWKS cache and
            the discovery cache. At least 1.

    Raises:
        ConfigError: one error naming every invalid setting.
    """

    jwks_cache_ttl: float = DEFAULT_JWKS_CACHE_TTL_SECONDS
    jwks_kid_miss_cooldown: float = DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
    discovery_cache_ttl: float = DEFAULT_DISCO_CACHE_TTL_SECONDS
    cache_max_entries: int = DEFAULT_MAX_CACHE_ENTRIES
