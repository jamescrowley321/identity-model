"""Typed, fail-closed configuration for py-identity-model.

Implements the cross-language configuration contract (``spec/config.md``): a
typed ``Config`` value resolved from pluggable :class:`ConfigSource` s, validated
once at construction, that fails closed on missing/partial/invalid input and
redacts secrets in every representation.

This is the opt-in, strict surface. It reads the environment only inside
:class:`EnvSource` (never at import time) and adds no new dependencies.

Design (see ``spec/config.md``):

* Sources supply raw strings only; typing, defaulting, and validation happen
  here, after resolution — no source can bypass them.
* Precedence per key, first hit wins: explicit ``overrides`` > consumer sources
  in the order given > :class:`EnvSource` > registry default.
* Construction is atomic: any problem yields a :class:`ConfigError` carrying
  *all* issues (registry-ordered) and no ``Config`` value.
* Secret-classified values are wrapped in :class:`Secret` and never appear in
  ``repr``/``str``/errors/serialized output.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
import math
import os
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable
from urllib.parse import urlparse


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


__all__ = [
    "ClientAuthMethod",
    "Config",
    "ConfigError",
    "ConfigIssue",
    "ConfigSource",
    "EnvSource",
    "MappingSource",
    "Secret",
]

REDACTED = "<redacted>"


class Secret:
    """Wraps a secret string so it can never be printed by accident.

    The raw value is reachable only through :meth:`expose`; every rendering
    (``repr``/``str``) shows the redaction placeholder.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def expose(self) -> str:
        """Return the raw secret. The only way to read the value."""
        return self._value

    def __repr__(self) -> str:
        return f"Secret('{REDACTED}')"

    def __str__(self) -> str:
        return REDACTED

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))


# --------------------------------------------------------------------------- #
# Errors                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ConfigIssue:
    """One problem found during construction. Names keys, never values."""

    code: str  # CFG-001 (missing) | CFG-002 (group) | CFG-003 (invalid) | CFG-004 (source)
    keys: tuple[str, ...]
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message} ({', '.join(self.keys)})"


class ConfigError(Exception):
    """Raised when strict construction fails. Carries every issue at once."""

    def __init__(self, issues: Sequence[ConfigIssue]) -> None:
        self.issues: tuple[ConfigIssue, ...] = tuple(issues)
        super().__init__(
            "configuration is invalid:\n"
            + "\n".join(f"  - {issue}" for issue in self.issues)
        )


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #


class _Kind(Enum):
    STR = "str"
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    URL = "url"
    STRLIST = "strlist"


class ClientAuthMethod(Enum):
    """Client authentication method — decides whether ``client.secret`` is required."""

    NONE = "none"
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"

    @property
    def requires_secret(self) -> bool:
        return self is not ClientAuthMethod.NONE


_SENTINEL = object()


@dataclass(frozen=True)
class _KeySpec:
    logical: str
    attr: str
    env: tuple[str, ...]  # primary first, then aliases
    kind: _Kind
    # default sentinel => required within its group (no standalone default)
    default: object = _SENTINEL
    secret: bool = False
    group: str | None = None
    prefixed: bool = False  # env names take the client prefix
    lo: float | None = None  # inclusive lower bound (numeric)
    hi: float | None = None  # inclusive upper bound (numeric)


# Registry is ordered: error collection reports in this order (spec/config.md).
# Values transcribed from the implementation as of 2026-09-03.
_REGISTRY: tuple[_KeySpec, ...] = (
    # HTTP transport
    _KeySpec(
        "http.timeout", "http_timeout", ("HTTP_TIMEOUT",), _Kind.FLOAT, 30.0, lo=0.0
    ),
    _KeySpec(
        "http.retry.max_attempts",
        "http_retry_max_attempts",
        ("HTTP_RETRY_MAX_ATTEMPTS", "HTTP_RETRY_COUNT"),
        _Kind.INT,
        3,
        lo=0,
    ),
    _KeySpec(
        "http.retry.base_delay",
        "http_retry_base_delay",
        ("HTTP_RETRY_BASE_DELAY",),
        _Kind.FLOAT,
        1.0,
        lo=0.0,
    ),
    # JWKS & discovery
    _KeySpec(
        "jwks.max_size", "jwks_max_size", ("MAX_JWKS_SIZE",), _Kind.INT, 524288, lo=1
    ),
    _KeySpec(
        "jwks.max_keys", "jwks_max_keys", ("MAX_JWKS_KEYS",), _Kind.INT, 100, lo=1
    ),
    _KeySpec(
        "jwks.cache.ttl",
        "jwks_cache_ttl",
        ("JWKS_CACHE_TTL",),
        _Kind.FLOAT,
        86400.0,
        lo=60.0,
        hi=86400.0,
    ),
    _KeySpec(
        "discovery.cache.ttl",
        "discovery_cache_ttl",
        ("DISCO_CACHE_TTL",),
        _Kind.FLOAT,
        3600.0,
        lo=60.0,
        hi=86400.0,
    ),
    _KeySpec(
        "jwks.kid_miss_cooldown",
        "jwks_kid_miss_cooldown",
        ("KID_MISS_REFRESH_COOLDOWN",),
        _Kind.FLOAT,
        5.0,
        lo=0.0,
        hi=3600.0,
    ),
    _KeySpec(
        "jwks.cache.max_entries",
        "jwks_cache_max_entries",
        ("JWKS_CACHE_MAX_ENTRIES",),
        _Kind.INT,
        64,
        lo=0,
    ),
    _KeySpec(
        "discovery.cache.max_entries",
        "discovery_cache_max_entries",
        ("DISCO_CACHE_MAX_ENTRIES",),
        _Kind.INT,
        64,
        lo=0,
    ),
    # Client settings group (env names take the client prefix)
    _KeySpec(
        "client.discovery_url",
        "client_discovery_url",
        ("DISCOVERY_URL",),
        _Kind.URL,
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.id",
        "client_id",
        ("CLIENT_ID",),
        _Kind.STR,
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.secret",
        "client_secret",
        ("CLIENT_SECRET",),
        _Kind.STR,
        default=None,
        secret=True,
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.scope",
        "client_scope",
        ("SCOPE",),
        _Kind.STR,
        "openid profile email",
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.audience",
        "client_audience",
        ("AUDIENCE",),
        _Kind.STR,
        default=None,
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.redirect_uri",
        "client_redirect_uri",
        ("REDIRECT_URI",),
        _Kind.URL,
        "",
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.post_login_redirect",
        "client_post_login_redirect",
        ("POST_LOGIN_REDIRECT",),
        _Kind.STR,
        "/",
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.post_logout_redirect",
        "client_post_logout_redirect",
        ("POST_LOGOUT_REDIRECT",),
        _Kind.STR,
        "/",
        group="client",
        prefixed=True,
    ),
    _KeySpec(
        "client.excluded_paths",
        "client_excluded_paths",
        ("EXCLUDED_PATHS",),
        _Kind.STRLIST,
        ("/docs", "/openapi.json", "/health"),
        group="client",
        prefixed=True,
    ),
)

_BY_LOGICAL: dict[str, _KeySpec] = {spec.logical: spec for spec in _REGISTRY}
# Required client keys (no standalone default) validated when the group is requested.
_CLIENT_REQUIRED = ("client.discovery_url", "client.id")


# --------------------------------------------------------------------------- #
# Sources                                                                      #
# --------------------------------------------------------------------------- #


@runtime_checkable
class ConfigSource(Protocol):
    """Supplies raw string values for the requested logical keys.

    Implementations return only the subset they can supply, keyed by logical
    key id. They MUST NOT type, default, clamp, or validate — the library does
    that. A source that raises fails construction closed (``CFG-004``).
    """

    def resolve(self, keys: Sequence[str]) -> Mapping[str, str]: ...


class MappingSource:
    """A source backed by an in-process mapping keyed by logical key id."""

    def __init__(self, values: Mapping[str, str], *, name: str = "mapping") -> None:
        self._values = dict(values)
        self.name = name

    def resolve(self, keys: Sequence[str]) -> Mapping[str, str]:
        requested = set(keys)
        return {k: v for k, v in self._values.items() if k in requested}


class EnvSource:
    """The default source: resolves logical keys from environment variables.

    Client-group keys take ``prefix`` (default ``OIDC_``). Reads happen here,
    at :meth:`resolve` time — never at import.
    """

    def __init__(self, *, prefix: str = "OIDC_", name: str = "env") -> None:
        self.prefix = prefix
        self.name = name

    def _env_names(self, spec: _KeySpec) -> tuple[str, ...]:
        if spec.prefixed:
            return tuple(f"{self.prefix}{name}" for name in spec.env)
        return spec.env

    def resolve(self, keys: Sequence[str]) -> Mapping[str, str]:
        environ = os.environ
        out: dict[str, str] = {}
        for logical in keys:
            spec = _BY_LOGICAL.get(logical)
            if spec is None:
                continue
            for env_name in self._env_names(spec):  # primary first, then aliases
                if env_name in environ:
                    out[logical] = environ[env_name]
                    break
        return out


# --------------------------------------------------------------------------- #
# Config                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Config:
    """A validated, immutable configuration value.

    Construct via :meth:`from_env` (zero-config) or :meth:`build` (custom
    sources / overrides). Never construct the dataclass directly — the fields
    below are the *result* of validated resolution.
    """

    _secret_fields: ClassVar[frozenset[str]] = frozenset({"client_secret"})

    # HTTP transport
    http_timeout: float
    http_retry_max_attempts: int
    http_retry_base_delay: float
    # JWKS & discovery
    jwks_max_size: int
    jwks_max_keys: int
    jwks_cache_ttl: float
    discovery_cache_ttl: float
    jwks_kid_miss_cooldown: float
    jwks_cache_max_entries: int
    discovery_cache_max_entries: int
    # Client settings group
    client_discovery_url: str | None
    client_id: str | None
    client_secret: Secret | None
    client_scope: str
    client_audience: str | None
    client_redirect_uri: str
    client_post_login_redirect: str
    client_post_logout_redirect: str
    client_excluded_paths: tuple[str, ...]

    @classmethod
    def from_env(
        cls,
        *,
        prefix: str = "OIDC_",
        group: str | None = None,
        client_auth_method: ClientAuthMethod = ClientAuthMethod.NONE,
    ) -> Config:
        """Build from environment variables (the default path)."""
        return cls.build(
            sources=[EnvSource(prefix=prefix)],
            env=False,
            group=group,
            client_auth_method=client_auth_method,
        )

    @classmethod
    def build(
        cls,
        *,
        sources: Sequence[ConfigSource] | None = None,
        overrides: Mapping[str, str] | None = None,
        env: bool = True,
        group: str | None = None,
        client_auth_method: ClientAuthMethod = ClientAuthMethod.NONE,
    ) -> Config:
        """Resolve and validate a Config, failing closed with all issues.

        Args:
            sources: consumer sources, highest precedence first.
            overrides: explicit in-code values (logical key id -> raw string);
                highest precedence of all.
            env: append a default-prefix :class:`EnvSource` as the lowest-
                precedence source (the default path). Set False to exclude the
                environment; pass an explicit ``EnvSource(prefix=...)`` in
                ``sources`` for a non-default prefix.
            group: which key group the construction requires ("client" or None).
            client_auth_method: when the client group is requested, decides
                whether ``client.secret`` is required.
        """
        chain: list[ConfigSource] = list(sources or [])
        if env:
            chain.append(EnvSource())

        issues: list[ConfigIssue] = []
        raw = _resolve_raw(chain, overrides or {}, issues)

        # Type + validate each present value; default the absent (registry order).
        values: dict[str, object] = {}
        for spec in _REGISTRY:
            if spec.logical in raw:
                parsed = _parse(spec, raw[spec.logical], issues)
                if parsed is not _SENTINEL:
                    values[spec.attr] = parsed
            elif spec.default is not _SENTINEL:
                values[spec.attr] = spec.default
            # else: absent + no standalone default -> handled by group rules below

        _apply_group_rules(group, client_auth_method, raw, values, issues)

        if issues:
            raise ConfigError(issues)

        # Fill any client fields still unset (only happens on the success path
        # when the group was not requested and no value was supplied).
        for spec in _REGISTRY:
            if spec.attr not in values:
                values[spec.attr] = None if spec.default is _SENTINEL else spec.default

        # audience defaults to client id when unset
        if values.get("client_audience") is None:
            values["client_audience"] = values.get("client_id")

        return cls(**values)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        parts: list[str] = []
        for f in fields(self):
            val = getattr(self, f.name)
            if f.name in self._secret_fields and val is not None:
                parts.append(f"{f.name}={REDACTED!r}")
            else:
                parts.append(f"{f.name}={val!r}")
        return f"Config({', '.join(parts)})"


# --------------------------------------------------------------------------- #
# Parsing & validation (strict mode)                                          #
# --------------------------------------------------------------------------- #


def _resolve_raw(
    chain: Sequence[ConfigSource],
    overrides: Mapping[str, str],
    issues: list[ConfigIssue],
) -> dict[str, str]:
    """Resolve raw values by precedence: overrides > sources in order.

    A source that raises fails closed with CFG-004; it is never skipped.
    """
    logical_keys = tuple(spec.logical for spec in _REGISTRY)
    raw: dict[str, str] = {k: overrides[k] for k in logical_keys if k in overrides}
    remaining = [k for k in logical_keys if k not in raw]
    for source in chain:
        if not remaining:
            break
        try:
            supplied = source.resolve(remaining)
        except Exception:
            name = getattr(source, "name", type(source).__name__)
            issues.append(
                ConfigIssue(
                    "CFG-004", (f"source:{name}",), f"source {name!r} failed to resolve"
                )
            )
            continue
        for logical in list(remaining):
            if logical in supplied:
                raw[logical] = supplied[logical]
                remaining.remove(logical)
    return raw


# Error messages MUST NOT contain the configured value (spec/config.md
# §Secret Redaction / §Error Taxonomy) — they describe the failure and name the
# key only. Bounds/limits are contract constants, safe to state.


def _parse_number(spec: _KeySpec, text: str, issues: list[ConfigIssue]) -> object:
    """Parse an int/float value with finiteness + range checks."""
    try:
        num: float | int = int(text) if spec.kind is _Kind.INT else float(text)
    except ValueError:
        issues.append(
            ConfigIssue("CFG-003", (spec.logical,), "value is not a valid number")
        )
        return _SENTINEL
    if spec.kind is _Kind.FLOAT and not math.isfinite(num):
        issues.append(
            ConfigIssue("CFG-003", (spec.logical,), "value is not a finite number")
        )
        return _SENTINEL
    if spec.lo is not None and num < spec.lo:
        issues.append(
            ConfigIssue(
                "CFG-003", (spec.logical,), f"value is below the minimum {spec.lo}"
            )
        )
        return _SENTINEL
    if spec.hi is not None and num > spec.hi:
        issues.append(
            ConfigIssue(
                "CFG-003", (spec.logical,), f"value is above the maximum {spec.hi}"
            )
        )
        return _SENTINEL
    return num


def _parse_bool(spec: _KeySpec, text: str, issues: list[ConfigIssue]) -> object:
    low = text.lower()
    if low in ("true", "1"):
        return True
    if low in ("false", "0"):
        return False
    issues.append(ConfigIssue("CFG-003", (spec.logical,), "value is not a boolean"))
    return _SENTINEL


def _parse_url(spec: _KeySpec, text: str, issues: list[ConfigIssue]) -> object:
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.netloc:
        issues.append(
            ConfigIssue("CFG-003", (spec.logical,), "value is not an absolute URL")
        )
        return _SENTINEL
    return text


def _parse(spec: _KeySpec, raw: str, issues: list[ConfigIssue]) -> object:
    """Parse+validate one raw value. Records CFG-003 and returns sentinel on failure."""
    if spec.kind is _Kind.STRLIST:
        return tuple(p.strip() for p in raw.split(",") if p.strip())

    text = raw.strip()
    if text == "":
        issues.append(
            ConfigIssue("CFG-003", (spec.logical,), "value is empty or whitespace-only")
        )
        return _SENTINEL

    if spec.kind is _Kind.STR:
        return raw
    if spec.kind is _Kind.BOOL:
        return _parse_bool(spec, text, issues)
    if spec.kind is _Kind.URL:
        return _parse_url(spec, text, issues)
    # INT / FLOAT
    return _parse_number(spec, text, issues)


def _apply_group_rules(
    group: str | None,
    client_auth_method: ClientAuthMethod,
    raw: Mapping[str, str],
    values: dict[str, object],
    issues: list[ConfigIssue],
) -> None:
    """Client-group validation (spec/config.md §Group Rules)."""
    client_present = any(k.startswith("client.") and k in raw for k in _BY_LOGICAL)

    if group == "client":
        # truly absent (not merely present-but-invalid, which is already CFG-003'd)
        issues.extend(
            ConfigIssue("CFG-001", (req,), f"required key {req!r} is missing")
            for req in _CLIENT_REQUIRED
            if req not in values and req not in raw
        )
        if client_auth_method.requires_secret and values.get("client_secret") is None:
            issues.append(
                ConfigIssue(
                    "CFG-002",
                    ("client", "client.secret"),
                    f"client auth method {client_auth_method.value!r} requires client.secret",
                )
            )
        # wrap the secret
        _wrap_client_secret(values)
    else:
        # Group not requested: a stray client fragment without discovery_url is an error.
        if client_present and "client.discovery_url" not in raw:
            issues.append(
                ConfigIssue(
                    "CFG-002",
                    ("client", "client.discovery_url"),
                    "client-group key present without client.discovery_url",
                )
            )
        _wrap_client_secret(values)


def _wrap_client_secret(values: dict[str, object]) -> None:
    secret = values.get("client_secret")
    if isinstance(secret, str):
        values["client_secret"] = Secret(secret)
