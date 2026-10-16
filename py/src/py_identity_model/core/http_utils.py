"""
Shared HTTP utilities for retry logic.

This module provides common utilities used by both sync and async HTTP clients.
Timeouts, retry counts and JWKS limits come from the client's injected
:class:`~py_identity_model.core.config.Config`; nothing here reads the
environment.
"""

from datetime import UTC
from email.utils import parsedate_to_datetime
import time

import httpx

from ..exceptions import NetworkException


# Default HTTP configuration constants
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_RETRY_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY = 1.0
DEFAULT_MAX_JWKS_SIZE = 512 * 1024  # 512 KB
DEFAULT_MAX_JWKS_KEYS = 100

# Upper bound on a single retry wait. A misbehaving server can send a huge
# Retry-After; cap it so a request cannot stall for an unbounded time.
MAX_RETRY_DELAY_SECONDS = 120.0

# HTTP status codes for retry logic
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 399


def should_retry_response(response: httpx.Response, attempt: int, retries: int) -> bool:
    """
    Check if response should be retried.

    Args:
        response: HTTP response to check
        attempt: Current attempt number (0-indexed)
        retries: Maximum number of retries

    Returns:
        bool: True if should retry, False otherwise
    """
    return (
        response.status_code == HTTP_TOO_MANY_REQUESTS
        or response.status_code >= HTTP_INTERNAL_SERVER_ERROR
    ) and attempt < retries


def calculate_delay(base_delay: float, attempt: int) -> float:
    """
    Calculate exponential backoff delay.

    Args:
        base_delay: Base delay in seconds
        attempt: Current attempt number (0-indexed)

    Returns:
        float: Delay in seconds
    """
    return base_delay * (2**attempt)


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Parse an HTTP ``Retry-After`` header (RFC 9110 Section 10.2.3).

    Accepts both the delta-seconds and HTTP-date forms.

    Args:
        value: Raw header value, or ``None`` when absent.
        now: Reference epoch seconds for the HTTP-date form (defaults to
            the current time); accepted for deterministic testing.

    Returns:
        Delay in seconds (never negative), or ``None`` when the header is
        absent or cannot be parsed.
    """
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None

    if value.isdigit():
        return float(value)

    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if retry_at is None:
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=UTC)

    reference = time.time() if now is None else now
    return max(0.0, retry_at.timestamp() - reference)


def resolve_retry_delay(
    response: httpx.Response, base_delay: float, attempt: int
) -> float:
    """Delay to wait before the next retry of an HTTP response.

    Honors a server-provided ``Retry-After`` header when present, using the
    larger of it and the exponential backoff so a rate limiter's explicit
    pacing is respected. The result is capped at ``MAX_RETRY_DELAY_SECONDS``.
    """
    backoff = calculate_delay(base_delay, attempt)
    retry_after = parse_retry_after(response.headers.get("Retry-After"))
    if retry_after is None:
        return backoff
    return min(max(backoff, retry_after), MAX_RETRY_DELAY_SECONDS)


def check_no_redirect(response: httpx.Response) -> None:
    """Raise if the response is a redirect (3xx).

    Redirect following is disabled to prevent SSRF attacks where an
    attacker-controlled server redirects requests to internal resources.
    """
    if HTTP_REDIRECT_MIN <= response.status_code <= HTTP_REDIRECT_MAX:
        location = response.headers.get("location", "<not provided>")
        raise NetworkException(
            f"HTTP {response.status_code} redirect blocked — "
            f"target: '{location}'. Redirect following is disabled "
            f"to prevent SSRF attacks.",
            url=str(response.url),
            status_code=response.status_code,
        )


__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "DEFAULT_MAX_JWKS_KEYS",
    "DEFAULT_MAX_JWKS_SIZE",
    "DEFAULT_RETRY_BASE_DELAY",
    "DEFAULT_RETRY_MAX_ATTEMPTS",
    "HTTP_INTERNAL_SERVER_ERROR",
    "HTTP_REDIRECT_MAX",
    "HTTP_REDIRECT_MIN",
    "HTTP_TOO_MANY_REQUESTS",
    "MAX_RETRY_DELAY_SECONDS",
    "calculate_delay",
    "check_no_redirect",
    "parse_retry_after",
    "resolve_retry_delay",
    "should_retry_response",
]
