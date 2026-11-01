"""
Managed sync HTTP client for dependency injection.

Wraps ``httpx.Client`` with lifecycle management and context manager
support, and holds the :class:`~py_identity_model.core.config.Config` the
library uses for every request made through it.  Pass an ``HTTPClient``
instance to any public sync function via the ``http_client`` parameter to
use it instead of the library default client.

Each ``HTTPClient`` owns its discovery cache, JWKS cache and kid-miss
cooldown state, so every cache has exactly one ``Config``.  Two clients do
not share cached documents.
"""

from __future__ import annotations

from collections import OrderedDict
import threading
from typing import TYPE_CHECKING

import httpx

from ..core.config import Config
from ..ssl_config import get_ssl_verify


if TYPE_CHECKING:
    from types import TracebackType

    from ..core.jwks_cache import DiscoCacheEntry, JwksCacheEntry


# Per-URI fetch locks are striped: two requests for the same address coalesce
# into one upstream fetch, while requests for different addresses rarely share
# a stripe and so do not block each other.
_LOCK_STRIPES = 32


class ClientCaches:
    """Discovery cache, JWKS cache and kid-miss cooldown state of one client.

    The caches are ``OrderedDict``s so read hits can refresh LRU recency;
    eviction targets the least recently *used* entry (#397). The discovery
    cache is keyed by ``(address, policy.cache_key())`` so a response admitted
    under a lax policy is never served to a caller running a stricter one.

    ``write_lock`` guards only the brief cache write + eviction critical
    section and never spans an upstream fetch; the striped fetch locks give
    per-URI single-flight. ``kid_miss_last_attempt`` records the last forced
    JWKS refresh per ``jwks_uri`` and is guarded by ``jwks_write_lock``.
    """

    def __init__(self) -> None:
        self.disco: OrderedDict[tuple[str, tuple], DiscoCacheEntry] = OrderedDict()
        self.disco_write_lock = threading.Lock()
        self._disco_fetch_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]
        self.jwks: OrderedDict[str, JwksCacheEntry] = OrderedDict()
        self.jwks_write_lock = threading.Lock()
        self._jwks_fetch_locks = [threading.Lock() for _ in range(_LOCK_STRIPES)]
        self.kid_miss_last_attempt: dict[str, float] = {}

    def disco_fetch_lock(self, cache_key: tuple[str, tuple]) -> threading.Lock:
        return self._disco_fetch_locks[hash(cache_key) % _LOCK_STRIPES]

    def jwks_fetch_lock(self, jwks_uri: str) -> threading.Lock:
        return self._jwks_fetch_locks[hash(jwks_uri) % _LOCK_STRIPES]


def build_httpx_client(config: Config) -> httpx.Client:
    """Build an ``httpx.Client`` from *config* (timeout and TLS verification)."""
    return httpx.Client(
        verify=get_ssl_verify(config),
        timeout=config.http_timeout,
        follow_redirects=False,
    )


class HTTPClient:
    """Managed sync HTTP client with optional lifecycle ownership.

    When constructed without an explicit *client*, a new ``httpx.Client``
    is created from *config* (``http_timeout``, ``ca_bundle``) and **owned**
    by this instance — calling :meth:`close` (or exiting the context
    manager) will close it.

    When an existing *client* is provided, this instance acts as a
    non-owning wrapper and :meth:`close` is a no-op.  The wrapped client
    keeps its own timeout and TLS settings; *config* still governs retries,
    JWKS limits and the caches.

    Args:
        client: Existing ``httpx.Client`` to wrap.  If ``None``, a new
            client is created from *config*.
        config: The library settings for requests through this client.
            ``None`` means ``Config()`` defaults; the environment is never
            read.

    Raises:
        RuntimeError: If the client is accessed after :meth:`close`.
    """

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        config: Config | None = None,
    ) -> None:
        self._config = config if config is not None else Config()
        self._caches = ClientCaches()
        if client is not None:
            self._client = client
            self._owned = False
        else:
            self._client = build_httpx_client(self._config)
            self._owned = True
        self._closed = False

    @property
    def config(self) -> Config:
        """The settings used for requests through this client."""
        return self._config

    @property
    def owns_client(self) -> bool:
        """Whether this instance built (and closes) its ``httpx.Client``."""
        return self._owned

    @property
    def caches(self) -> ClientCaches:
        """The discovery/JWKS caches and kid-miss state owned by this client."""
        return self._caches

    @property
    def client(self) -> httpx.Client:
        """The underlying ``httpx.Client``."""
        self.ensure_open()
        return self._client

    def ensure_open(self) -> None:
        """Raise ``RuntimeError`` if this client has been closed.

        Entry points call this before serving from the caches, so a closed
        client fails the same way on a cache hit as on a cache miss.
        """
        if self._closed:
            raise RuntimeError("HTTPClient has been closed")

    def close(self) -> None:
        """Close the client if this instance owns it.  Idempotent."""
        if self._closed:
            return
        try:
            if self._owned:
                self._client.close()
        finally:
            self._closed = True

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = ["ClientCaches", "HTTPClient", "build_httpx_client"]
