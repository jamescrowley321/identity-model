"""
SSL certificate configuration utilities.

Resolves the CA bundle for this library's own HTTPS requests, honouring the
legacy requests-era variables alongside the httpx-native ones. Resolution is
read-only: nothing here writes to os.environ, so importing this library never
changes the TLS trust store of anything else in the process.
"""

from functools import lru_cache
import os


@lru_cache(maxsize=1)
def get_ssl_verify() -> str | bool:
    """
    Get SSL verification configuration for httpx with full backward compatibility.

    This function is cached for performance. It checks environment variables in
    priority order and returns the appropriate value for httpx's verify parameter.

    Environment variables checked (in priority order):
    1. SSL_CERT_FILE - standard environment variable (highest priority)
    2. CURL_CA_BUNDLE - used by curl and httpx
    3. REQUESTS_CA_BUNDLE - legacy requests library (for backward compatibility)

    Returns:
        str: Path to CA bundle file if any environment variable is set
        bool: True for default system CA verification

    Note:
        Result is cached using @lru_cache (which is thread-safe). If environment
        variables change at runtime, call get_ssl_verify.cache_clear() to refresh.

    Thread Safety:
        This function is thread-safe via @lru_cache's built-in thread safety
        (Python 3.2+) and can be called from multiple threads concurrently
        in web applications (FastAPI, Flask, Django).

    Examples:
        >>> # Use in httpx client
        >>> async with httpx.AsyncClient(verify=get_ssl_verify()) as client:
        ...     response = await client.get(url)

        >>> # Synchronous usage
        >>> response = httpx.get(url, verify=get_ssl_verify())
    """
    for env_var in [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
    ]:
        if os.environ.get(env_var):
            return os.environ[env_var]
    return True  # Default: verify with system CA bundle


__all__ = ["get_ssl_verify"]
