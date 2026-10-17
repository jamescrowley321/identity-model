"""
Discovery cache, JWKS cache and kid-miss cooldown for sync token validation.

HTTP clients only send requests. The state that token validation keeps
between calls lives on a :class:`ValidationCache`: the discovery documents,
the JWKS, and the time of the last forced JWKS refresh per ``jwks_uri``.
Pass one to ``validate_token`` (and the ID Token and Logout Token
validators) as ``cache=``; without one, the process-wide default cache
(:func:`get_default_validation_cache`) is used, whatever ``http_client`` is
passed. A client built per request therefore still shares the cooldown
(#945).

The default cache is rebuilt in a forked child, so a pre-fork server's
workers never share one. A cache you build yourself is not: build it after
the fork.
"""

from __future__ import annotations

from collections import OrderedDict
import threading
from typing import TYPE_CHECKING

from ..core.config import Config
from ..core.process_local import ProcessLocal


if TYPE_CHECKING:
    from ..core.jwks_cache import DiscoCacheEntry, JwksCacheEntry


# Per-URI fetch locks are striped: two requests for the same address coalesce
# into one upstream fetch, while requests for different addresses rarely share
# a stripe and so do not block each other.
_LOCK_STRIPES = 32


class ValidationCache:
    """Discovery cache, JWKS cache and kid-miss cooldown state.

    The discovery cache is keyed by ``(address, policy.cache_key())``, so a
    response admitted under a lax policy is never served to a caller running
    a stricter one. The JWKS cache and ``kid_miss_last_attempt`` (the last
    forced JWKS refresh) are keyed by ``jwks_uri``. Both caches are
    ``OrderedDict``s so read hits can refresh LRU recency; eviction targets the
    least recently *used* entry (#397).

    ``disco_write_lock`` / ``jwks_write_lock`` guard only the brief cache write
    and eviction and never span an upstream fetch; the striped fetch locks
    give per-URI single-flight. ``kid_miss_last_attempt`` is guarded by
    ``jwks_write_lock``.

    Args:
        config: Sets the fallback TTLs (``jwks_cache_ttl``,
            ``discovery_cache_ttl``), the size bound (``cache_max_entries``)
            and the cooldown (``jwks_kid_miss_cooldown``). ``None`` means
            ``Config()`` defaults. The other settings belong to the HTTP
            client and are not read here.
    """

    def __init__(self, *, config: Config | None = None) -> None:
        self._config = config if config is not None else Config()
        self.disco: OrderedDict[tuple[str, tuple], DiscoCacheEntry] = OrderedDict()
        self.disco_write_lock = threading.Lock()
        self._disco_fetch_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]
        self.jwks: OrderedDict[str, JwksCacheEntry] = OrderedDict()
        self.jwks_write_lock = threading.Lock()
        self._jwks_fetch_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]
        self.kid_miss_last_attempt: dict[str, float] = {}

    @property
    def config(self) -> Config:
        """The settings for this cache's TTLs, size and cooldown."""
        return self._config

    def disco_fetch_lock(self, cache_key: tuple[str, tuple]) -> threading.Lock:
        return self._disco_fetch_locks[hash(cache_key) % _LOCK_STRIPES]

    def jwks_fetch_lock(self, jwks_uri: str) -> threading.Lock:
        return self._jwks_fetch_locks[hash(jwks_uri) % _LOCK_STRIPES]


_default_cache: ProcessLocal[ValidationCache] = ProcessLocal(
    lambda inherited: ValidationCache(
        config=inherited.config if inherited is not None else None
    )
)


def get_default_validation_cache() -> ValidationCache:
    """Return the process-wide default cache, built from ``Config()``.

    Used by every sync validator called without ``cache=``. A forked child
    gets its own.
    """
    return _default_cache.get()


def _reset_default_validation_cache(config: Config | None = None) -> None:
    """Replace the default cache with an empty one (testing only).

    The new default is built from *config* (``Config()`` when ``None``).
    """
    _default_cache.replace(ValidationCache(config=config))


__all__ = ["ValidationCache", "get_default_validation_cache"]
