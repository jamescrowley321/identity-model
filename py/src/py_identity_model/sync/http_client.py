"""
Synchronous HTTP client with connection pooling and retry logic.

This module provides thread-local HTTP clients with connection pooling and
automatic retry logic for transient failures like rate limiting.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3)
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

from __future__ import annotations

from functools import wraps
import threading
import time
from typing import TYPE_CHECKING

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
    from .managed_client import HTTPClient


# time.sleep() converts its argument to a signed 64-bit nanosecond count and
# raises OverflowError past it; on Linux the kernel also rejects an absolute
# deadline past that range, so the usable limit shrinks with machine uptime.
# HTTP_RETRY_MAX_DELAY is documented "> 0" with no upper bound, and a bound the
# operator did not choose is the failure mode this module avoids, so the sync
# client sleeps in slices instead. The slice length is the one asyncio uses
# for its selector timeout (MAXIMUM_SELECT_TIMEOUT), for the same reason.
SLEEP_SLICE_SECONDS = 24 * 60 * 60.0


def _sleep(seconds: float) -> None:
    """Wait ``seconds`` without a ceiling on the value.

    Exactly ``time.sleep(seconds)`` for any wait up to ``SLEEP_SLICE_SECONDS``,
    so nothing that observes the call (a mocked ``time.sleep`` in a consumer's
    tests, say) sees a different argument than before. A longer wait is taken
    in slices of that length, so a spec-valid ceiling cannot raise
    ``OverflowError`` out of the retry loop. Slices are counted rather than
    measured against a clock: a deadline loop never terminates under a mocked
    sleep, and passes ``seconds`` minus elapsed time to the real one.
    """
    while seconds > SLEEP_SLICE_SECONDS:
        time.sleep(SLEEP_SLICE_SECONDS)
        seconds -= SLEEP_SLICE_SECONDS
    if seconds > 0:
        time.sleep(seconds)


# Thread-local storage for sync HTTP client
_thread_local = threading.local()


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


def retry_with_backoff(max_retries: int | None = None, base_delay: float | None = None):
    """
    Decorator to retry HTTP requests with exponential backoff.

    Retries on transient errors including rate limiting (429) and server errors (5xx).

    Args:
        max_retries: Maximum number of retry attempts (default: from HTTP_RETRY_MAX_ATTEMPTS env or 3)
        base_delay: Base delay in seconds for exponential backoff (default: from HTTP_RETRY_BASE_DELAY env or 1.0)

    Returns:
        Decorated function that retries on 429 and 5xx errors with exponential backoff

    Environment Variables:
        HTTP_RETRY_MAX_ATTEMPTS: Default max retries if not specified
        HTTP_RETRY_BASE_DELAY: Default base delay if not specified
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries, delay_base = _get_retry_params(max_retries, base_delay)
            last_exception: httpx.RequestError | None = None

            # max(0, ...) so an explicit negative max_retries argument cannot
            # reproduce range(0) -- the env path is bounded in get_retry_config,
            # but the decorator also takes the value directly.
            for attempt in range(max(0, retries) + 1):
                try:
                    response = func(*args, **kwargs)

                    # Check if response needs retry (429 or 5xx with retries remaining)
                    if should_retry_response(response, attempt, retries):
                        delay = resolve_retry_delay(response, delay_base, attempt)
                        _log_retry(
                            f"HTTP {response.status_code}",
                            delay,
                            attempt,
                            retries,
                        )
                        _sleep(delay)
                        continue

                    check_no_redirect(response)
                    return response

                except httpx.RequestError as e:
                    last_exception = e
                    if attempt < retries:
                        delay = calculate_delay(delay_base, attempt)
                        _log_retry(f"Request error: {e}", delay, attempt, retries)
                        _sleep(delay)
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
    Get a thread-local HTTP client with connection pooling.

    Returns a thread-local httpx.Client that reuses connections within the
    same thread, improving performance for multiple HTTP requests. Each thread
    gets its own client instance, making this thread-safe for concurrent use
    in web applications (FastAPI, Flask) and messaging systems.

    Returns:
        httpx.Client: Configured HTTP client with connection pooling

    Environment Variables:
        HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)

    Note:
        - Thread-safe: Each thread gets its own client instance
        - The client uses default limits:
          - max_connections: 100
          - max_keepalive_connections: 20
          - keepalive_expiry: 5.0 seconds
        - Ideal for web frameworks and messaging applications where each
          request/message is handled in a separate thread
    """
    # Check if current thread already has a client
    if not hasattr(_thread_local, "client") or _thread_local.client is None:
        timeout = get_timeout()
        _thread_local.client = httpx.Client(
            verify=get_ssl_verify(),
            timeout=timeout,
            follow_redirects=False,
        )
    return _thread_local.client


def build_mtls_client(mtls: MtlsClientAuth) -> httpx.Client:
    """Build a short-lived HTTP client presenting a client certificate (mTLS).

    Used for RFC 8705 mutual-TLS client authentication: the certificate is
    presented at the TLS layer, so a dedicated client is required (httpx has
    no per-request ``cert=``). The caller **owns** the returned client and
    must close it once the request completes.

    Args:
        mtls: The mTLS client-authentication configuration.

    Returns:
        A new ``httpx.Client`` configured with the client certificate.
    """
    return httpx.Client(
        verify=build_mtls_ssl_context(mtls),
        timeout=get_timeout(),
        follow_redirects=False,
    )


def resolve_http_client(
    mtls: MtlsClientAuth | None,
    http_client: HTTPClient | None,
) -> tuple[httpx.Client, httpx.Client | None]:
    """Resolve the HTTP client to use for a client-authenticating request.

    At most one of *mtls* / *http_client* may be supplied. When *mtls* is
    configured, a short-lived cert-configured client is built (RFC 8705); a
    managed *http_client* is used as-is; otherwise the shared thread-local
    client is used.

    A managed *http_client* cannot be guaranteed to present the requested
    client certificate at the TLS layer, and the ``prepare_*`` body branch has
    already dropped ``client_secret``/Basic auth for the mTLS case — so
    supplying both would silently emit an unauthenticated request. Reject that
    combination explicitly rather than downgrading.

    Args:
        mtls: The request's mTLS configuration, or ``None``.
        http_client: An optional managed ``HTTPClient`` wrapper.

    Returns:
        ``(client, owned)`` — *client* is the client to use; *owned* is the
        same object when the caller must close it afterwards (mTLS), else
        ``None`` for shared/managed clients that must not be closed here.

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
    return get_http_client(), None


def close_http_client() -> None:
    """
    Close the HTTP client for the current thread.

    This should be called when shutting down the application or cleaning up
    after request processing to properly release resources. In web frameworks,
    this can be called in teardown handlers or context managers.

    Note:
        This only closes the client for the current thread. Other threads
        maintain their own clients independently.
    """
    if hasattr(_thread_local, "client") and _thread_local.client is not None:
        _thread_local.client.close()
        _thread_local.client = None


def _reset_http_client() -> None:
    """
    Reset the HTTP client for the current thread (for testing purposes only).

    This function is intended for use in tests to clear the thread-local
    HTTP client instance. It should not be called in production code.
    """
    if hasattr(_thread_local, "client"):
        if _thread_local.client is not None:
            _thread_local.client.close()
        _thread_local.client = None


__all__ = [
    "build_mtls_client",
    "close_http_client",
    "get_http_client",
    "resolve_http_client",
    "retry_with_backoff",
]
