"""
Managed async HTTP client for dependency injection.

Wraps ``httpx.AsyncClient`` with lifecycle management and context manager
support, and holds the :class:`~py_identity_model.core.config.Config` the
library uses for every request made through it.  Pass an
``AsyncHTTPClient`` instance to any public async function via the
``http_client`` parameter to use it instead of the library default client.

Each ``AsyncHTTPClient`` owns its discovery cache, JWKS cache and kid-miss
cooldown state, so every cache has exactly one ``Config``.  Two clients do
not share cached documents.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import threading
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

import httpx

from ..core.config import Config
from ..ssl_config import get_ssl_verify


if TYPE_CHECKING:
    from types import TracebackType

    from ..core.jwks_cache import DiscoCacheEntry, JwksCacheEntry


# See sync.managed_client: striped per-URI fetch locks.
_LOCK_STRIPES = 32


class _LoopLocks:
    """Per-event-loop asyncio locks: one write lock plus striped fetch locks.

    An ``asyncio.Lock`` binds to the loop that first acquires it, so any embed
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


class AsyncClientCaches:
    """Discovery cache, JWKS cache and kid-miss cooldown state of one client.

    Async mirror of :class:`py_identity_model.sync.managed_client.ClientCaches`;
    the write and fetch locks are per event loop (see :class:`_LoopLocks`).
    ``kid_miss_last_attempt`` is guarded by the JWKS write lock.
    """

    def __init__(self) -> None:
        creation_lock = threading.Lock()
        self.disco: OrderedDict[tuple[str, tuple], DiscoCacheEntry] = OrderedDict()
        self._disco_locks = _LoopLocks(creation_lock)
        self.jwks: OrderedDict[str, JwksCacheEntry] = OrderedDict()
        self._jwks_locks = _LoopLocks(creation_lock)
        self.kid_miss_last_attempt: dict[str, float] = {}

    def disco_write_lock(self) -> asyncio.Lock:
        return self._disco_locks.write_lock()

    def disco_fetch_lock(self, cache_key: tuple[str, tuple]) -> asyncio.Lock:
        return self._disco_locks.fetch_lock(cache_key)

    def jwks_write_lock(self) -> asyncio.Lock:
        return self._jwks_locks.write_lock()

    def jwks_fetch_lock(self, jwks_uri: str) -> asyncio.Lock:
        return self._jwks_locks.fetch_lock(jwks_uri)


def build_async_httpx_client(config: Config) -> httpx.AsyncClient:
    """Build an ``httpx.AsyncClient`` from *config* (timeout and TLS)."""
    return httpx.AsyncClient(
        verify=get_ssl_verify(config),
        timeout=config.http_timeout,
        follow_redirects=False,
    )


class AsyncHTTPClient:
    """Managed async HTTP client with optional lifecycle ownership.

    When constructed without an explicit *client*, a new
    ``httpx.AsyncClient`` is created from *config* (``http_timeout``,
    ``ca_bundle``) and **owned** by this instance — calling :meth:`close`
    (or exiting the context manager) will close it.

    When an existing *client* is provided, this instance acts as a
    non-owning wrapper and :meth:`close` is a no-op.  The wrapped client
    keeps its own timeout and TLS settings; *config* still governs retries,
    JWKS limits and the caches.

    Args:
        client: Existing ``httpx.AsyncClient`` to wrap.  If ``None``, a new
            client is created from *config*.
        config: The library settings for requests through this client.
            ``None`` means ``Config()`` defaults; the environment is never
            read.

    Raises:
        RuntimeError: If the client is accessed after :meth:`close`.
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        config: Config | None = None,
    ) -> None:
        self._config = config if config is not None else Config()
        self._caches = AsyncClientCaches()
        if client is not None:
            self._client = client
            self._owned = False
        else:
            self._client = build_async_httpx_client(self._config)
            self._owned = True
        self._closed = False

    @property
    def config(self) -> Config:
        """The settings used for requests through this client."""
        return self._config

    @property
    def owns_client(self) -> bool:
        """Whether this instance built (and closes) its ``httpx.AsyncClient``."""
        return self._owned

    @property
    def caches(self) -> AsyncClientCaches:
        """The discovery/JWKS caches and kid-miss state owned by this client."""
        return self._caches

    @property
    def client(self) -> httpx.AsyncClient:
        """The underlying ``httpx.AsyncClient``."""
        self.ensure_open()
        return self._client

    def ensure_open(self) -> None:
        """Raise ``RuntimeError`` if this client has been closed.

        Entry points call this before serving from the caches, so a closed
        client fails the same way on a cache hit as on a cache miss.
        """
        if self._closed:
            raise RuntimeError("AsyncHTTPClient has been closed")

    async def close(self) -> None:
        """Close the client if this instance owns it.  Idempotent."""
        if self._closed:
            return
        try:
            if self._owned:
                await self._client.aclose()
        finally:
            self._closed = True

    async def __aenter__(self) -> AsyncHTTPClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()


__all__ = ["AsyncClientCaches", "AsyncHTTPClient", "build_async_httpx_client"]
