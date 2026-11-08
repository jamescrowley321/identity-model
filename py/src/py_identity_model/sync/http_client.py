"""
Synchronous HTTP client with connection pooling and retry logic.

This module provides the library default client and automatic retry logic
for transient failures like rate limiting. Timeouts, TLS and retry settings
come from the client's :class:`~py_identity_model.core.config.Config`; the
library reads no environment variables.

The library default client (:func:`get_default_http_client`) is built from
``Config()`` and used by every entry point called without ``http_client=``.
It is one :class:`HTTPClient` per process: each thread gets its own underlying
``httpx.Client``, and a forked child gets a new default client rather than the
parent's connections.
"""

from __future__ import annotations

from functools import wraps
import threading
import time
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
from ..core.process_local import ProcessLocal
from ..core.trust_scope import owned_trust_scope
from ..logging_config import logger
from .managed_client import HTTPClient, build_httpx_client


if TYPE_CHECKING:
    from collections.abc import Callable

    from ..core.models import MtlsClientAuth


_P = ParamSpec("_P")


class _DefaultHTTPClient(HTTPClient):
    """The library default client: thread-local connections.

    Each thread gets its own ``httpx.Client`` built from the config, created
    on first use. :meth:`close` closes only the calling thread's client; the
    next use in that thread builds a new one.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._owned = True
        self._trust_scope = owned_trust_scope(config)
        self._closed = False
        self._local = threading.local()

    @property
    def client(self) -> httpx.Client:
        client: httpx.Client | None = getattr(self._local, "client", None)
        if client is None:
            client = build_httpx_client(self._config)
            self._local.client = client
        return client

    def close(self) -> None:
        client: httpx.Client | None = getattr(self._local, "client", None)
        if client is not None:
            client.close()
            self._local.client = None


_default_client: ProcessLocal[_DefaultHTTPClient] = ProcessLocal(
    lambda inherited: _DefaultHTTPClient(
        inherited.config if inherited is not None else Config()
    )
)


def get_default_http_client() -> HTTPClient:
    """Return the library default client, built from ``Config()``.

    Used by every sync entry point called without ``http_client=``. One
    instance per process, while each thread gets its own ``httpx.Client``
    connection pool. A forked child builds its own and never uses the
    parent's connections.
    """
    return _default_client.get()


def _reset_default_http_client(config: Config | None = None) -> None:
    """Replace the default client with a fresh one (testing only).

    The new default is built from *config* (``Config()`` when ``None``).
    Closes the calling thread's connections of the previous default.
    """
    previous = _default_client.replace(
        _DefaultHTTPClient(config if config is not None else Config())
    )
    if previous is not None:
        previous.close()


def _log_retry(message: str, delay: float, attempt: int, retries: int) -> None:
    """Log a retry attempt warning."""
    logger.warning(f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})")


def retry_with_backoff(
    max_retries: int | None = None, base_delay: float | None = None
) -> Callable[
    [Callable[Concatenate[httpx.Client, _P], httpx.Response]],
    Callable[Concatenate[HTTPClient, _P], httpx.Response],
]:
    """
    Decorator to retry HTTP requests with exponential backoff.

    Retries on transient errors including rate limiting (429) and server errors (5xx).
    The decorated function takes an ``httpx.Client`` first; the wrapper takes the
    managed :class:`HTTPClient` instead, passes its ``httpx.Client`` through, and
    reads the retry settings from its config.

    Args:
        max_retries: Maximum number of retry attempts (default: the client's
            ``Config.http_retry_max_attempts``). Must not be negative.
        base_delay: Base delay in seconds for exponential backoff (default: the
            client's ``Config.http_retry_base_delay``). Must not be negative.

    Returns:
        Decorated function that retries on 429 and 5xx errors with exponential backoff

    Raises:
        ValueError: If *max_retries* or *base_delay* is negative.
    """
    if max_retries is not None and max_retries < 0:
        raise ValueError("max_retries must be at least 0")
    if base_delay is not None and base_delay < 0:
        raise ValueError("base_delay must be at least 0")

    def decorator(
        func: Callable[Concatenate[httpx.Client, _P], httpx.Response],
    ) -> Callable[Concatenate[HTTPClient, _P], httpx.Response]:
        @wraps(func)
        def wrapper(
            client: HTTPClient, *args: _P.args, **kwargs: _P.kwargs
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
                    response = func(client.client, *args, **kwargs)

                    # Check if response needs retry (429 or 5xx with retries remaining)
                    if should_retry_response(response, attempt, retries):
                        delay = resolve_retry_delay(response, delay_base, attempt)
                        _log_retry(
                            f"HTTP {response.status_code}",
                            delay,
                            attempt,
                            retries,
                        )
                        time.sleep(delay)
                        continue

                    check_no_redirect(response)
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = calculate_delay(delay_base, attempt)
                        _log_retry(f"Request error: {e}", delay, attempt, retries)
                        time.sleep(delay)
                        continue
                    raise

            # Exhausted all retries - return last response or raise last exception
            if last_exception:
                raise last_exception
            raise RuntimeError("No response received after retries")

        return wrapper

    return decorator


def get_http_client() -> httpx.Client:
    """
    Get the calling thread's ``httpx.Client`` of the library default client.

    Returns:
        httpx.Client: Connection-pooled client built from ``Config()``

    Note:
        - Thread-safe: Each thread gets its own client instance
        - The client uses default limits:
          - max_connections: 100
          - max_keepalive_connections: 20
          - keepalive_expiry: 5.0 seconds
    """
    return get_default_http_client().client


def build_mtls_client(mtls: MtlsClientAuth, config: Config) -> httpx.Client:
    """Build a short-lived HTTP client presenting a client certificate (mTLS).

    Used for RFC 8705 mutual-TLS client authentication: the certificate is
    presented at the TLS layer, so a dedicated client is required (httpx has
    no per-request ``cert=``). The caller **owns** the returned client and
    must close it once the request completes.

    Args:
        mtls: The mTLS client-authentication configuration.
        config: Supplies the timeout and the server CA bundle.

    Returns:
        A new ``httpx.Client`` configured with the client certificate.
    """
    return httpx.Client(
        verify=build_mtls_ssl_context(mtls, config),
        timeout=config.http_timeout,
        follow_redirects=False,
    )


_WRAPPED_CLIENT_MTLS_ERROR = (
    "mtls cannot be combined with a wrapped httpx client: its own TLS "
    "settings cannot be carried over to the certificate client. Pass "
    "HTTPClient(config=Config(ca_bundle=...)) instead."
)


def resolve_http_client(
    mtls: MtlsClientAuth | None,
    http_client: HTTPClient | None,
) -> tuple[HTTPClient, httpx.Client | None]:
    """Resolve the HTTP client to use for a client-authenticating request.

    When *mtls* is configured, a short-lived cert-configured client is built
    (RFC 8705) and wrapped with the ``Config`` of *http_client* when one is
    given, else of the library default client. The request then goes through
    that cert client, never through *http_client*'s own connection pool,
    which cannot be guaranteed to present the certificate; *http_client*
    supplies only its settings (``ca_bundle``, ``http_timeout``, retries).
    Without *mtls*, *http_client* is used as-is, else the default client.

    Args:
        mtls: The request's mTLS configuration, or ``None``.
        http_client: An optional managed ``HTTPClient`` wrapper.

    Returns:
        ``(client, owned)`` — *client* is the managed client to use; *owned*
        is the ``httpx.Client`` the caller must close afterwards (mTLS), else
        ``None`` for shared/managed clients that must not be closed here.

    Raises:
        RuntimeError: If *http_client* has been closed.
        ValueError: If *mtls* is combined with an *http_client* that wraps a
            caller's own httpx client, whose TLS settings would be lost.
    """
    if mtls is None:
        if http_client is not None:
            return http_client, None
        return get_default_http_client(), None
    if http_client is not None:
        http_client.ensure_open()
        if not http_client.owns_client:
            raise ValueError(_WRAPPED_CLIENT_MTLS_ERROR)
        config = http_client.config
    else:
        config = get_default_http_client().config
    owned = build_mtls_client(mtls, config)
    return HTTPClient(owned, config=config), owned


def close_http_client() -> None:
    """
    Close the default client's ``httpx.Client`` for the current thread.

    This should be called when shutting down the application or cleaning up
    after request processing to properly release resources. In web frameworks,
    this can be called in teardown handlers or context managers.

    Note:
        This only closes the client for the current thread. Other threads
        maintain their own clients independently.
    """
    client = _default_client.peek()
    if client is not None:
        client.close()


def _reset_http_client() -> None:
    """
    Reset the HTTP client for the current thread (for testing purposes only).

    Closes the calling thread's ``httpx.Client`` of the default client; the
    next use builds a new one.
    """
    close_http_client()


__all__ = [
    "build_mtls_client",
    "close_http_client",
    "get_default_http_client",
    "get_http_client",
    "resolve_http_client",
    "retry_with_backoff",
]
