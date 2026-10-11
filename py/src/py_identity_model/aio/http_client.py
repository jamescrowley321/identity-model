"""
Asynchronous HTTP client with connection pooling and retry logic.

This module provides the library default async client and automatic retry
logic for transient failures like rate limiting. Timeouts, TLS and retry
settings come from the client's :class:`~py_identity_model.core.config.Config`;
the library reads no environment variables.

The library default client (:func:`get_default_async_http_client`) is one
process-wide :class:`AsyncHTTPClient` built from ``Config()`` and used by
every entry point called without ``http_client=``.
"""

from __future__ import annotations

import asyncio
from functools import wraps
import threading
from typing import TYPE_CHECKING, Concatenate, ParamSpec

import httpx

from ..core.config import Config
from ..core.http_utils import (
    calculate_delay,
    check_no_redirect,
    resolve_retry_delay,
    should_retry_response,
)
from ..core.mtls import build_mtls_ssl_context
from ..logging_config import logger
from .managed_client import (
    AsyncClientCaches,
    AsyncHTTPClient,
    build_async_httpx_client,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ..core.models import MtlsClientAuth


_P = ParamSpec("_P")


class _DefaultAsyncHTTPClient(AsyncHTTPClient):
    """The library default async client.

    The underlying ``httpx.AsyncClient`` is created on first use (under a
    thread lock, so concurrent first use from several threads builds one).
    :meth:`close` closes it and the next use builds a new one; the caches
    survive a close.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._caches = AsyncClientCaches()
        self._owned = True
        self._closed = False
        self._http: httpx.AsyncClient | None = None
        self._creation_lock = threading.Lock()
        # Created eagerly to avoid initialization races. asyncio.Lock() is safe
        # to create outside an event loop; it binds to the running loop on
        # first acquire.
        self._cleanup_lock = asyncio.Lock()

    @property
    def client(self) -> httpx.AsyncClient:
        http = self._http
        if http is not None:
            return http
        with self._creation_lock:
            if self._http is None:
                self._http = build_async_httpx_client(self._config)
            return self._http

    async def close(self) -> None:
        if self._http is None:
            return
        async with self._cleanup_lock:
            http = self._http
            if http is not None:
                await http.aclose()
                self._http = None

    def forget_connections(self) -> None:
        """Drop the underlying client without closing it (testing only)."""
        with self._creation_lock:
            self._http = None


_default_client_lock = threading.Lock()
_default_state: dict[str, _DefaultAsyncHTTPClient | None] = {"client": None}


def _get_default() -> _DefaultAsyncHTTPClient:
    client = _default_state["client"]
    if client is not None:
        return client
    with _default_client_lock:
        client = _default_state["client"]
        if client is None:
            client = _DefaultAsyncHTTPClient(Config())
            _default_state["client"] = client
        return client


def get_default_async_http_client() -> AsyncHTTPClient:
    """Return the library default async client, built from ``Config()``.

    Used by every async entry point called without ``http_client=``. The
    instance is shared by the process: one discovery cache, one JWKS cache,
    one connection pool.
    """
    return _get_default()


def _reset_default_async_http_client(config: Config | None = None) -> None:
    """Replace the default client with a fresh one (testing only).

    The new default is built from *config* (``Config()`` when ``None``) and
    starts with empty caches. Does NOT close the previous default's
    connections; ``await close_async_http_client()`` first for that.
    """
    with _default_client_lock:
        _default_state["client"] = _DefaultAsyncHTTPClient(
            config if config is not None else Config()
        )


def _log_retry(message: str, delay: float, attempt: int, retries: int) -> None:
    """Log a retry attempt warning."""
    logger.warning(f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})")


def retry_with_backoff_async(
    max_retries: int | None = None, base_delay: float | None = None
) -> Callable[
    [Callable[Concatenate[httpx.AsyncClient, _P], Awaitable[httpx.Response]]],
    Callable[Concatenate[AsyncHTTPClient, _P], Awaitable[httpx.Response]],
]:
    """
    Decorator to retry async HTTP requests on rate limiting with exponential backoff.

    The decorated function takes an ``httpx.AsyncClient`` first; the wrapper
    takes the managed :class:`AsyncHTTPClient` instead, passes its
    ``httpx.AsyncClient`` through, and reads the retry settings from its config.

    Args:
        max_retries: Maximum number of retry attempts (default: the client's
            ``Config.http_retry_max_attempts``). Must not be negative.
        base_delay: Base delay in seconds for exponential backoff (default: the
            client's ``Config.http_retry_base_delay``). Must not be negative.

    Returns:
        Decorated async function that retries on 429 and 5xx errors

    Raises:
        ValueError: If *max_retries* or *base_delay* is negative.
    """
    if max_retries is not None and max_retries < 0:
        raise ValueError("max_retries must be at least 0")
    if base_delay is not None and base_delay < 0:
        raise ValueError("base_delay must be at least 0")

    def decorator(
        func: Callable[Concatenate[httpx.AsyncClient, _P], Awaitable[httpx.Response]],
    ) -> Callable[Concatenate[AsyncHTTPClient, _P], Awaitable[httpx.Response]]:
        @wraps(func)
        async def wrapper(
            client: AsyncHTTPClient, *args: _P.args, **kwargs: _P.kwargs
        ) -> httpx.Response:
            config = client.config
            retries = (
                max_retries
                if max_retries is not None
                else config.http_retry_max_attempts
            )
            delay_base = (
                base_delay if base_delay is not None else config.http_retry_base_delay
            )
            last_exception: httpx.RequestError | None = None

            for attempt in range(retries + 1):
                try:
                    response = await func(client.client, *args, **kwargs)

                    # Check if response needs retry (429 or 5xx with retries remaining)
                    if should_retry_response(response, attempt, retries):
                        delay = resolve_retry_delay(response, delay_base, attempt)
                        _log_retry(
                            f"HTTP {response.status_code}",
                            delay,
                            attempt,
                            retries,
                        )
                        await asyncio.sleep(delay)
                        continue

                    check_no_redirect(response)
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = calculate_delay(delay_base, attempt)
                        _log_retry(f"Request error: {e}", delay, attempt, retries)
                        await asyncio.sleep(delay)
                        continue
                    raise

            # Exhausted all retries - return last response or raise last exception
            if last_exception:
                raise last_exception
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


def get_async_http_client() -> httpx.AsyncClient:
    """
    Get the ``httpx.AsyncClient`` of the library default client.

    Returns:
        httpx.AsyncClient: Connection-pooled client built from ``Config()``

    Note:
        The client uses default limits:
        - max_connections: 100
        - max_keepalive_connections: 20
        - keepalive_expiry: 5.0 seconds

        Thread-safe: Uses a lock to prevent race conditions when creating
        the async client from multiple threads simultaneously.
    """
    return _get_default().client


def build_mtls_client(mtls: MtlsClientAuth, config: Config) -> httpx.AsyncClient:
    """Build a short-lived async HTTP client presenting a client certificate.

    Used for RFC 8705 mutual-TLS client authentication: the certificate is
    presented at the TLS layer, so a dedicated client is required (httpx has
    no per-request ``cert=``). The caller **owns** the returned client and
    must ``aclose()`` it once the request completes.

    Args:
        mtls: The mTLS client-authentication configuration.
        config: Supplies the timeout and the server CA bundle.

    Returns:
        A new ``httpx.AsyncClient`` configured with the client certificate.
    """
    return httpx.AsyncClient(
        verify=build_mtls_ssl_context(mtls, config),
        timeout=config.http_timeout,
        follow_redirects=False,
    )


def resolve_async_http_client(
    mtls: MtlsClientAuth | None,
    http_client: AsyncHTTPClient | None,
) -> tuple[AsyncHTTPClient, httpx.AsyncClient | None]:
    """Resolve the async HTTP client to use for a client-authenticating request.

    When *mtls* is configured, a short-lived cert-configured client is built
    (RFC 8705) and wrapped with the ``Config`` of *http_client* when one is
    given, else of the library default client. The request then goes through
    that cert client, never through *http_client*'s own connection pool,
    which cannot be guaranteed to present the certificate; *http_client*
    supplies only its settings (``ca_bundle``, ``http_timeout``, retries).
    Without *mtls*, *http_client* is used as-is, else the default client.

    Args:
        mtls: The request's mTLS configuration, or ``None``.
        http_client: An optional managed ``AsyncHTTPClient`` wrapper.

    Returns:
        ``(client, owned)`` — *client* is the managed client to use; *owned*
        is the ``httpx.AsyncClient`` the caller must ``aclose()`` afterwards
        (mTLS), else ``None`` for shared/managed clients that must not be
        closed here.

    Raises:
        RuntimeError: If *http_client* has been closed.
    """
    if mtls is None:
        if http_client is not None:
            return http_client, None
        return _get_default(), None
    if http_client is not None:
        http_client.ensure_open()
        config = http_client.config
    else:
        config = _get_default().config
    owned = build_mtls_client(mtls, config)
    return AsyncHTTPClient(owned, config=config), owned


async def close_async_http_client() -> None:
    """
    Close the default client's ``httpx.AsyncClient``.

    This should be called when shutting down the application to properly
    clean up resources. Not calling this will leave connections open, but
    they will be cleaned up when the process exits. The next use builds a
    new connection pool; the default client's caches are kept.
    """
    client = _default_state["client"]
    if client is not None:
        await client.close()


def _reset_async_http_client() -> None:
    """
    Drop the default client's ``httpx.AsyncClient`` (for testing purposes only).

    IMPORTANT: This does NOT close the underlying connections. Callers
    must await close_async_http_client() first to properly release
    sockets and prevent ResourceWarning during garbage collection.
    """
    client = _default_state["client"]
    if client is not None:
        client.forget_connections()


__all__ = [
    "build_mtls_client",
    "close_async_http_client",
    "get_async_http_client",
    "get_default_async_http_client",
    "resolve_async_http_client",
    "retry_with_backoff_async",
]
