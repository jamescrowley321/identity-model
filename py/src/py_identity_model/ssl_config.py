"""
SSL certificate configuration utilities.

This module provides backward compatibility for SSL certificate environment variables
when migrating from requests to httpx.
"""

from functools import lru_cache
import os


def ensure_ssl_compatibility() -> None:
    """
    Export a legacy REQUESTS_CA_BUNDLE setting as SSL_CERT_FILE, process-wide.

    Opt-in: nothing in this library calls it. Call it only when you want
    *other* libraries in the process to honour REQUESTS_CA_BUNDLE, which they
    would otherwise ignore. py-identity-model does not need it — its own
    requests resolve the same variables through :func:`get_ssl_verify`.

    If REQUESTS_CA_BUNDLE is set and neither SSL_CERT_FILE nor CURL_CA_BUNDLE
    is, this sets SSL_CERT_FILE to the REQUESTS_CA_BUNDLE value.

    Environment variables checked (in priority order):
    1. SSL_CERT_FILE - httpx native variable (highest priority)
    2. CURL_CA_BUNDLE - also respected by httpx
    3. REQUESTS_CA_BUNDLE - legacy requests library variable (for backward compatibility)

    Only fires when SSL_CERT_FILE is unset or empty and CURL_CA_BUNDLE is unset:
    it is a no-op when CURL_CA_BUNDLE carries the bundle, because stdlib ssl does
    not read that variable either. Exporting that case is out of scope here.

    Warning:
        This writes to os.environ, which is process-global and not thread-safe,
        and records no prior value to restore. SSL_CERT_FILE is honoured by
        stdlib ssl (and so by aiohttp and anything building a default
        SSLContext) and by urllib3 when it loads default certs. It is NOT read
        by requests, which honours REQUESTS_CA_BUNDLE then CURL_CA_BUNDLE and
        otherwise uses bundled certifi, nor by botocore/boto3, which use
        AWS_CA_BUNDLE and otherwise certifi. Call it once, early, from
        application code — never from library import.
    """
    # Truthiness, not membership: an empty SSL_CERT_FILE selects no bundle, and
    # get_ssl_verify() skips it for the same reason. Guarding on presence would
    # make `SSL_CERT_FILE=` (a bare compose entry) a silent no-op that leaves the
    # caller with the split trust store this function exists to close.
    if not os.environ.get("SSL_CERT_FILE"):
        # CURL_CA_BUNDLE is already set and httpx will use it
        if os.environ.get("CURL_CA_BUNDLE"):
            pass
        # Then check REQUESTS_CA_BUNDLE for backward compatibility
        elif os.environ.get("REQUESTS_CA_BUNDLE"):
            # Set SSL_CERT_FILE to REQUESTS_CA_BUNDLE value for httpx to use
            os.environ["SSL_CERT_FILE"] = os.environ["REQUESTS_CA_BUNDLE"]


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


__all__ = ["ensure_ssl_compatibility", "get_ssl_verify"]
