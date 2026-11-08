"""
Discovery cache, JWKS cache and kid-miss cooldown for async token validation.

Async mirror of :mod:`py_identity_model.sync.validation_cache`. Pass an
:class:`AsyncValidationCache` to the async validators as ``cache=``; without
one, the process-wide default (:func:`get_default_async_validation_cache`) is
used. Its locks are per event loop, so one cache serves any number of loops
in turn or at once. The default cache is rebuilt in a forked child.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import threading
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from ..core.config import Config
from ..core.process_local import ProcessLocal


if TYPE_CHECKING:
    from ..core.jwks_cache import (
        DiscoCacheEntry,
        DiscoCacheKey,
        JwksCacheEntry,
        JwksCacheKey,
    )


# See sync.validation_cache: striped per-URI fetch locks.
_LOCK_STRIPES = 32


class _LoopLocks:
    """Per-event-loop asyncio locks: one write lock plus striped fetch locks.

    An ``asyncio.Lock`` binds to the loop that first waits on it, so any embed
    or test runner that creates a new loop per scope would hit
    ``RuntimeError: <Lock> is bound to a different event loop`` with a single
    shared lock. Keying on the running loop via ``WeakKeyDictionary`` gives
    each loop its own lock set, reclaimed when the loop is closed (#399).
    """

    def __init__(self, creation_lock: threading.Lock) -> None:
        self._creation_lock = creation_lock
        self._write: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
            WeakKeyDictionary()
        )
        self._fetch: WeakKeyDictionary[
            asyncio.AbstractEventLoop, list[asyncio.Lock]
        ] = WeakKeyDictionary()

    def write_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._write.get(loop)
        if lock is None:
            with self._creation_lock:
                lock = self._write.get(loop)
                if lock is None:
                    lock = asyncio.Lock()
                    self._write[loop] = lock
        return lock

    def fetch_lock(self, key: object) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        stripes = self._fetch.get(loop)
        if stripes is None:
            with self._creation_lock:
                stripes = self._fetch.get(loop)
                if stripes is None:
                    stripes = [asyncio.Lock() for _ in range(_LOCK_STRIPES)]
                    self._fetch[loop] = stripes
        return stripes[hash(key) % _LOCK_STRIPES]


class AsyncValidationCache:
    """Discovery cache, JWKS cache and kid-miss cooldown state (async).

    Async mirror of :class:`py_identity_model.sync.validation_cache.ValidationCache`;
    the write and fetch locks are per event loop (see :class:`_LoopLocks`).
    ``kid_miss_last_attempt`` is guarded by the JWKS write lock.

    Args:
        config: Sets the fallback TTLs (``jwks_cache_ttl``,
            ``discovery_cache_ttl``), the size bound (``cache_max_entries``)
            and the cooldown (``jwks_kid_miss_cooldown``). ``None`` means
            ``Config()`` defaults. The other settings belong to the HTTP
            client and are not read here.
    """

    def __init__(self, *, config: Config | None = None) -> None:
        self._config = config if config is not None else Config()
        creation_lock = threading.Lock()
        self.disco: OrderedDict[DiscoCacheKey, DiscoCacheEntry] = OrderedDict()
        self._disco_locks = _LoopLocks(creation_lock)
        self.jwks: OrderedDict[JwksCacheKey, JwksCacheEntry] = OrderedDict()
        self._jwks_locks = _LoopLocks(creation_lock)
        self.kid_miss_last_attempt: dict[str, float] = {}

    @property
    def config(self) -> Config:
        """The settings for this cache's TTLs, size and cooldown."""
        return self._config

    def disco_write_lock(self) -> asyncio.Lock:
        return self._disco_locks.write_lock()

    def disco_fetch_lock(self, cache_key: DiscoCacheKey) -> asyncio.Lock:
        return self._disco_locks.fetch_lock(cache_key)

    def jwks_write_lock(self) -> asyncio.Lock:
        return self._jwks_locks.write_lock()

    def jwks_fetch_lock(self, cache_key: JwksCacheKey) -> asyncio.Lock:
        return self._jwks_locks.fetch_lock(cache_key)


_default_cache: ProcessLocal[AsyncValidationCache] = ProcessLocal(
    lambda inherited: AsyncValidationCache(
        config=inherited.config if inherited is not None else None
    )
)


def get_default_async_validation_cache() -> AsyncValidationCache:
    """Return the process-wide default async cache, built from ``Config()``.

    Used by every async validator called without ``cache=``. A forked child
    gets its own.
    """
    return _default_cache.get()


def _reset_default_async_validation_cache(config: Config | None = None) -> None:
    """Replace the default async cache with an empty one (testing only).

    The new default is built from *config* (``Config()`` when ``None``).
    """
    _default_cache.replace(AsyncValidationCache(config=config))


__all__ = ["AsyncValidationCache", "get_default_async_validation_cache"]
