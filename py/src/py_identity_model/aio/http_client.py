"""
Asynchronous HTTP client with connection pooling and retry logic.

This module provides a singleton async HTTP client with connection pooling and
automatic retry logic for transient failures like rate limiting.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

from __future__ import annotations

import asyncio
from functools import wraps
import threading
from typing import TYPE_CHECKING, TypedDict

import httpx

from ..core.http_utils import (
    calculate_delay,
    check_no_redirect,
    get_retry_config,
    get_timeout,
    resolve_retry_delay,
    should_retry_response,
)
from ..core.mtls import build_mtls_ssl_context
from ..logging_config import logger
from ..ssl_config import get_ssl_verify


if TYPE_CHECKING:
    from ..core.models import MtlsClientAuth
    from .managed_client import AsyncHTTPClient


# Thread lock for async client creation (protects multi-threaded initialization)
_async_client_creation_lock = threading.Lock()


class _AsyncClientState(TypedDict):
    """Module-level mutable state container (avoids `global` statements)."""

    client: httpx.AsyncClient | None


_state: _AsyncClientState = {
    "client": None,
}

# Dedicated cleanup lock — created eagerly to avoid initialization races.
# asyncio.Lock() is safe to create outside an event loop; it binds to the
# running loop on first acquire.
_cleanup_lock = asyncio.Lock()


def _log_retry(message: str, delay: float, attempt: int, retries: int) -> None:
    """Log a retry attempt warning."""
    logger.warning(f"{message}, retrying in {delay}s (attempt {attempt + 1}/{retries})")


def _get_retry_params(
    max_retries: int | None, base_delay: float | None
) -> tuple[int, float]:
    """
    Get retry parameters from arguments or environment.

    Args:
        max_retries: Explicit max retries or None
        base_delay: Explicit base delay or None

    Returns:
        tuple[int, float]: (retries, delay_base)
    """
    env_max_retries, env_base_delay = get_retry_config()
    retries = max_retries if max_retries is not None else env_max_retries
    delay_base = base_delay if base_delay is not None else env_base_delay
    return retries, delay_base


def retry_with_backoff_async(
    max_retries: int | None = None, base_delay: float | None = None
):
    """
    Decorator to retry async HTTP requests on rate limiting with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts (default: from HTTP_RETRY_MAX_ATTEMPTS env or 3)
        base_delay: Base delay in seconds for exponential backoff (default: from HTTP_RETRY_BASE_DELAY env or 1.0)

    Returns:
        Decorated async function that retries on 429 and 5xx errors

    Environment Variables:
        HTTP_RETRY_MAX_ATTEMPTS: Default max retries if not specified
        HTTP_RETRY_BASE_DELAY: Default base delay if not specified
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries, delay_base = _get_retry_params(max_retries, base_delay)
            last_exception: httpx.RequestError | None = None

            # max(0, ...) so an explicit negative max_retries argument cannot
            # reproduce range(0) -- the env path is bounded in get_retry_config,
            # but the decorator also takes the value directly.
            for attempt in range(max(0, retries) + 1):
                try:
                    response = await func(*args, **kwargs)

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
    Get a persistent async HTTP client with connection pooling.

    Returns a singleton httpx.AsyncClient that reuses connections, improving
    performance for multiple HTTP requests. Use @retry_with_backoff_async
    decorator on HTTP calls for automatic retry logic.

    Returns:
        httpx.AsyncClient: Configured async HTTP client with connection pooling

    Environment Variables:
        HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)

    Note:
        The client uses default limits:
        - max_connections: 100
        - max_keepalive_connections: 20
        - keepalive_expiry: 5.0 seconds

        Thread-safe: Uses a lock to prevent race conditions when creating
        the async client from multiple threads simultaneously.
    """
    # Fast path: client already exists
    if _state["client"] is not None:
        return _state["client"]

    # Slow path: need to create client with lock
    with _async_client_creation_lock:
        # Double-check: another thread might have created it while we waited
        if _state["client"] is not None:
            return _state["client"]

        # Create client - httpx.AsyncClient creation is synchronous and safe
        timeout = get_timeout()
        _state["client"] = httpx.AsyncClient(
            verify=get_ssl_verify(),
            timeout=timeout,
            follow_redirects=False,
        )
        return _state["client"]


def build_mtls_client(mtls: MtlsClientAuth) -> httpx.AsyncClient:
    """Build a short-lived async HTTP client presenting a client certificate.

    Used for RFC 8705 mutual-TLS client authentication: the certificate is
    presented at the TLS layer, so a dedicated client is required (httpx has
    no per-request ``cert=``). The caller **owns** the returned client and
    must ``aclose()`` it once the request completes.

    Args:
        mtls: The mTLS client-authentication configuration.

    Returns:
        A new ``httpx.AsyncClient`` configured with the client certificate.
    """
    return httpx.AsyncClient(
        verify=build_mtls_ssl_context(mtls),
        timeout=get_timeout(),
        follow_redirects=False,
    )


def resolve_async_http_client(
    mtls: MtlsClientAuth | None,
    http_client: AsyncHTTPClient | None,
) -> tuple[httpx.AsyncClient, httpx.AsyncClient | None]:
    """Resolve the async HTTP client to use for a client-authenticating request.

    At most one of *mtls* / *http_client* may be supplied. When *mtls* is
    configured, a short-lived cert-configured client is built (RFC 8705); a
    managed *http_client* is used as-is; otherwise the shared singleton client
    is used.

    A managed *http_client* cannot be guaranteed to present the requested
    client certificate at the TLS layer, and the ``prepare_*`` body branch has
    already dropped ``client_secret``/Basic auth for the mTLS case — so
    supplying both would silently emit an unauthenticated request. Reject that
    combination explicitly rather than downgrading.

    Args:
        mtls: The request's mTLS configuration, or ``None``.
        http_client: An optional managed ``AsyncHTTPClient`` wrapper.

    Returns:
        ``(client, owned)`` — *client* is the client to use; *owned* is the
        same object when the caller must ``aclose()`` it afterwards (mTLS),
        else ``None`` for shared/managed clients that must not be closed here.

    Raises:
        ValueError: If both *mtls* and *http_client* are supplied.
    """
    if mtls is not None and http_client is not None:
        raise ValueError(
            "Cannot combine a managed http_client with mtls: a managed client "
            "cannot be guaranteed to present the mTLS client certificate. Pass "
            "one or the other."
        )
    if http_client is not None:
        return http_client.client, None
    if mtls is not None:
        client = build_mtls_client(mtls)
        return client, client
    return get_async_http_client(), None


async def close_async_http_client() -> None:
    """
    Close the persistent async HTTP client and clear the cache.

    This should be called when shutting down the application to properly
    clean up resources. Not calling this will leave connections open, but
    they will be cleaned up when the process exits.

    Note:
        This function uses asyncio.Lock for proper async cleanup without
        blocking the event loop.
    """
    if _state["client"] is not None:
        async with _cleanup_lock:
            if _state["client"] is not None:
                await _state["client"].aclose()
                _state["client"] = None


def _reset_async_http_client() -> None:
    """
    Reset the async HTTP client cache (for testing purposes only).

    This function is intended for use in tests to clear the cached async
    HTTP client instance. It should not be called in production code.

    IMPORTANT: This does NOT close the underlying connections. Callers
    must await close_async_http_client() first to properly release
    sockets and prevent ResourceWarning during garbage collection.
    """
    with _async_client_creation_lock:
        _state["client"] = None


__all__ = [
    "build_mtls_client",
    "close_async_http_client",
    "get_async_http_client",
    "resolve_async_http_client",
    "retry_with_backoff_async",
]
