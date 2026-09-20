"""
Shared HTTP utilities for retry logic and configuration.

This module provides common utilities used by both sync and async HTTP clients.

Environment Variables:
    HTTP_RETRY_MAX_ATTEMPTS: Maximum number of retry attempts (default: 3).
        Also accepted as HTTP_RETRY_COUNT (documented alias).
    HTTP_RETRY_BASE_DELAY: Base delay in seconds for exponential backoff (default: 1.0)
    HTTP_TIMEOUT: Request timeout in seconds (default: 30.0)
"""

from collections.abc import Callable
from datetime import UTC
from email.utils import parsedate_to_datetime
import math
import os
import time

import httpx

from ..exceptions import NetworkException
from ..logging_config import logger


# Default HTTP configuration constants
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_RETRY_MAX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY = 1.0
DEFAULT_MAX_JWKS_SIZE = 512 * 1024  # 512 KB
DEFAULT_MAX_JWKS_KEYS = 100

#: Bounds applied to the environment-supplied values below. Every one of these is
#: read from the ambient environment, so a single typo in a deployment reaches
#: every entry point the library offers -- these keep a typo from becoming an
#: outage or, for the JWKS limits, from silently removing a memory bound.
RETRY_ATTEMPTS_FLOOR = 0  # documented opt-out: 0 disables retries

# Upper bound on a single retry wait. A misbehaving server can send a huge
# Retry-After; cap it so a request cannot stall for an unbounded time.
MAX_RETRY_DELAY_SECONDS = 120.0

# HTTP status codes for retry logic
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_REDIRECT_MIN = 300
HTTP_REDIRECT_MAX = 399


#: Names already warned about. These getters run on every request, so without
#: this a single bad value emits one WARNING per HTTP call and buries the one
#: line that would explain the misconfiguration.
_WARNED: set[str] = set()


def _warn_once(key: str, message: str, *args: object) -> None:
    """Log ``message`` at WARNING the first time ``key`` is seen."""
    if key in _WARNED:
        return
    _WARNED.add(key)
    logger.warning(message, *args)


def _env_number[T: (int, float)](
    name: str,
    default: T,
    cast: Callable[[str], T],
    aliases: tuple[str, ...] = (),
) -> T:
    """Read and parse a numeric env var, returning ``default`` when unusable.

    Unusable means absent, empty, unparseable, or -- for floats -- NaN/Inf.
    Warns once per variable: these getters run on every request, so a per-call
    warning would bury the one line explaining the misconfiguration.

    Bounds are the caller's business, because the right response to an
    out-of-range value differs per variable: a negative retry count means
    "don't retry" and clamps, while a non-positive JWKS size limit would reject
    every response and falls back instead.
    """
    raw = None
    resolved = name
    for candidate in (name, *aliases):
        candidate_raw = os.getenv(candidate)
        # Strip first so a whitespace-only value behaves like an empty one.
        # Legacy divergence from spec/config.md §Types, which classes both as
        # present-but-invalid: the original ``getenv(a) or getenv(b)`` fell
        # through to the alias, and legacy resolution reproduces that.
        if candidate_raw is not None and candidate_raw.strip() != "":
            raw, resolved = candidate_raw.strip(), candidate
            break
    if raw is None:
        return default

    try:
        value = cast(raw)
    except ValueError:
        _warn_once(resolved, "Invalid %s=%r; using default %s", resolved, raw, default)
        return default

    if isinstance(value, float) and not math.isfinite(value):
        _warn_once(
            resolved, "Non-finite %s=%s; using default %s", resolved, raw, default
        )
        return default

    return value


def get_retry_config() -> tuple[int, float]:
    """
    Get retry configuration from environment variables.

    Returns:
        tuple: (max_retries, base_delay)
    """
    # Accept the documented ``HTTP_RETRY_COUNT`` name as an alias of
    # ``HTTP_RETRY_MAX_ATTEMPTS`` (the README and the workspace docs advertise
    # ``HTTP_RETRY_COUNT``). ``HTTP_RETRY_MAX_ATTEMPTS`` wins when both are set;
    # an explicit ``0`` (disable retries) is honored.
    raw_retries = _env_number(
        "HTTP_RETRY_MAX_ATTEMPTS",
        DEFAULT_RETRY_MAX_ATTEMPTS,
        cast=int,
        aliases=("HTTP_RETRY_COUNT",),
    )
    # Clamp rather than default: a negative count reads as "don't retry", and the
    # floor is the documented opt-out. Left unclamped, callers computed
    # ``range(retries + 1)`` as ``range(0)`` and raised "No response received
    # after retries" without issuing a single request.
    #
    # Deliberately no upper bound: spec/config.md documents this key as ">= 0"
    # with no ceiling, and core/config.py's registry agrees. A ceiling here would
    # make one variable resolve two ways in one process.
    max_retries = max(RETRY_ATTEMPTS_FLOOR, raw_retries)
    if max_retries != raw_retries:
        _warn_once(
            "HTTP_RETRY_MAX_ATTEMPTS:floor",
            "Raised retry attempts %s to the %s minimum; a negative count "
            "cancels the request itself",
            raw_retries,
            RETRY_ATTEMPTS_FLOOR,
        )

    raw_delay = _env_number(
        "HTTP_RETRY_BASE_DELAY", DEFAULT_RETRY_BASE_DELAY, cast=float
    )
    # A negative base delay is not a shorter wait, it is a broken backoff curve;
    # fall back rather than clamp to zero, which would retry with no pause at all.
    if raw_delay < 0:
        _warn_once(
            "HTTP_RETRY_BASE_DELAY:sign",
            "Negative HTTP_RETRY_BASE_DELAY=%s; using default %s",
            raw_delay,
            DEFAULT_RETRY_BASE_DELAY,
        )
        base_delay = DEFAULT_RETRY_BASE_DELAY
    else:
        # This bounds the base. calculate_delay() bounds the product, which is
        # what actually reaches sleep().
        base_delay = min(raw_delay, MAX_RETRY_DELAY_SECONDS)

    return max_retries, base_delay


def get_timeout() -> float:
    """
    Get HTTP timeout from environment variable.

    Returns:
        float: Timeout in seconds
    """
    timeout = _env_number("HTTP_TIMEOUT", DEFAULT_HTTP_TIMEOUT, cast=float)
    # A non-positive timeout makes httpx fail the request immediately, so a typo
    # would present as a total outage rather than as a configuration error.
    if timeout <= 0:
        _warn_once(
            "HTTP_TIMEOUT:sign",
            "Non-positive HTTP_TIMEOUT=%s; using default %s",
            timeout,
            DEFAULT_HTTP_TIMEOUT,
        )
        return DEFAULT_HTTP_TIMEOUT
    return timeout


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


def get_max_jwks_size() -> int:
    """Get maximum JWKS response size from environment variable.

    Returns:
        int: Maximum response size in bytes.
    """
    size = _env_number("MAX_JWKS_SIZE", DEFAULT_MAX_JWKS_SIZE, cast=int)
    # A non-positive limit rejects every response, including legitimate ones, so
    # treat it as a typo. Every positive value is honoured: picking a maximum
    # would mean overriding a deliberate operator choice with an invented number.
    if size <= 0:
        _warn_once(
            "MAX_JWKS_SIZE:sign",
            "Non-positive MAX_JWKS_SIZE=%s; using default %s",
            size,
            DEFAULT_MAX_JWKS_SIZE,
        )
        return DEFAULT_MAX_JWKS_SIZE
    return size


def get_max_jwks_keys() -> int:
    """Get maximum number of keys allowed in a JWKS response.

    Returns:
        int: Maximum number of keys (always >= 1).
    """
    keys = _env_number("MAX_JWKS_KEYS", DEFAULT_MAX_JWKS_KEYS, cast=int)
    # The clamp to 1 is deliberate and specified (spec/config.md, jwks.max_keys):
    # a limit of 0 would reject every JWKS. It is kept as-is; only the diagnostic
    # is new, because a limit of 1 rejects any provider mid key-rotation and that
    # surfaces much later as a key-not-found failure.
    bounded = max(1, keys)
    if bounded != keys:
        _warn_once(
            "MAX_JWKS_KEYS:floor",
            "Raised MAX_JWKS_KEYS=%s to 1; a limit below 1 rejects every response",
            keys,
        )
    return bounded


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
    "get_max_jwks_keys",
    "get_max_jwks_size",
    "get_retry_config",
    "get_timeout",
    "parse_retry_after",
    "resolve_retry_delay",
    "should_retry_response",
]
