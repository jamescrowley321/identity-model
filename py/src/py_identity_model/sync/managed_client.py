"""
Managed sync HTTP client for dependency injection.

Wraps ``httpx.Client`` with lifecycle management and context manager
support, and holds the :class:`~py_identity_model.core.config.Config` the
library uses for every request made through it.  Pass an ``HTTPClient``
instance to any public sync function via the ``http_client`` parameter to
use it instead of the library default client.

The client only sends requests.  The discovery and JWKS caches and the
kid-miss cooldown live on a validation cache (``cache=`` on the validators),
not on the client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from ..core.config import Config
from ..ssl_config import get_ssl_verify


if TYPE_CHECKING:
    from types import TracebackType


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
    keeps its own timeout and TLS settings; *config* still governs retries
    and JWKS limits.

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
    def client(self) -> httpx.Client:
        """The underlying ``httpx.Client``."""
        self.ensure_open()
        return self._client

    def ensure_open(self) -> None:
        """Raise ``RuntimeError`` if this client has been closed.

        The validators call this before serving from their cache, so a closed
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


__all__ = ["HTTPClient", "build_httpx_client"]
