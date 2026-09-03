"""
Discovery policy and endpoint parsing for configurable security.

Inspired by Duende IdentityModel's DiscoveryPolicy, this module provides
configurable validation for OpenID Connect discovery operations.

Default policy enforces strict HTTPS with a loopback exception for
development. Use a relaxed policy for testing environments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlparse

from ..exceptions import ConfigurationException


_WELL_KNOWN_PATH = "/.well-known/openid-configuration"
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass
class DiscoveryPolicy:
    """Configurable security policy for discovery document validation.

    Controls how strictly the library validates discovery documents
    and their endpoints. The default is strict (production-safe).

    Attributes:
        require_https: Require HTTPS for the discovery endpoint and
            all advertised endpoints. Set ``False`` for development
            against HTTP servers.
        allow_http_on_loopback: Allow HTTP when the host is
            ``localhost``, ``127.0.0.1``, or ``::1``. Only applies
            when ``require_https`` is ``True``.
        validate_issuer: Validate the ``issuer`` field in the
            discovery document.
        validate_endpoints: Validate that advertised endpoint URLs
            are well-formed.
        require_key_set: Require a ``jwks_uri`` in the discovery
            document.
        additional_endpoint_base_addresses: Extra base URLs that
            advertised endpoints are allowed to use (for multi-domain
            or CDN setups).
        authority: Expected authority (scheme + host) for endpoint
            validation. When ``None``, derived from the discovery URL.
        allow_loopback_endpoints: Allow ``mtls_endpoint_aliases`` to target a
            loopback address (``127.0.0.0/8`` / ``::1``) for local development.
            Default ``False`` — a loopback-routed mTLS request is a limited SSRF
            to the client's own host, so it must be opted into. Link-local
            (cloud metadata, ``169.254.0.0/16``) and RFC1918/reserved hosts stay
            blocked regardless of this flag. Distinct from
            ``allow_http_on_loopback`` (which relaxes only the HTTPS scheme
            requirement, not internal-IP routing).
    """

    require_https: bool = True
    allow_http_on_loopback: bool = True
    validate_issuer: bool = True
    validate_endpoints: bool = True
    require_key_set: bool = True
    additional_endpoint_base_addresses: list[str] = field(default_factory=list)
    authority: str | None = None
    allow_loopback_endpoints: bool = False

    def cache_key(self) -> tuple:
        """A hashable, canonical identity of this policy for cache partitioning.

        The discovery cache keys entries on ``(address, policy.cache_key())`` so a
        response admitted under a lax policy is never served to a caller running a
        stricter one — the policy-bypass guard that previously keyed on
        ``require_https`` alone. Every field that influences how a discovery
        document is validated (see ``validate_and_parse_discovery_response``) is
        included, so two policies produce equal keys iff they would validate a
        document identically. ``additional_endpoint_base_addresses`` is frozen to
        a tuple so the whole result is hashable.
        """
        return (
            self.require_https,
            self.allow_http_on_loopback,
            self.validate_issuer,
            self.validate_endpoints,
            self.require_key_set,
            tuple(self.additional_endpoint_base_addresses),
            self.authority,
            self.allow_loopback_endpoints,
        )


@dataclass
class DiscoveryEndpoint:
    """Parsed discovery endpoint URL with extracted authority.

    Attributes:
        url: The full discovery URL (with well-known path appended
            if not already present).
        authority: The scheme + host portion of the URL.
    """

    url: str
    authority: str


def is_loopback(host: str) -> bool:
    """Check if a host is a loopback address.

    Recognizes ``localhost``, ``127.0.0.1``, ``::1``, and
    ``127.x.x.x`` addresses. Uses ``ipaddress`` for safe parsing
    so that DNS names like ``127.evil.com`` are not matched.
    """
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_discovery_url(url: str) -> DiscoveryEndpoint:
    """Parse a discovery URL and extract its authority.

    If the URL does not end with the well-known path, it is appended
    automatically.

    Args:
        url: The discovery endpoint URL or base issuer URL.

    Returns:
        DiscoveryEndpoint with the full URL and extracted authority.

    Raises:
        ConfigurationException: If the URL is malformed.
    """
    if not url:
        raise ConfigurationException("Discovery URL cannot be empty")

    parsed = urlparse(url)
    if not parsed.scheme:
        raise ConfigurationException(f"Discovery URL must include a scheme: {url}")
    if parsed.scheme not in ("http", "https"):
        raise ConfigurationException(
            f"Discovery URL must use HTTP or HTTPS scheme, got: {parsed.scheme}"
        )
    if not parsed.netloc:
        raise ConfigurationException(f"Discovery URL must include a host: {url}")
    if parsed.query or parsed.fragment:
        raise ConfigurationException(
            "Discovery URL must not contain query or fragment components"
        )

    authority = f"{parsed.scheme}://{parsed.netloc}"

    full_url = url
    if not parsed.path.rstrip("/").endswith(_WELL_KNOWN_PATH.rstrip("/")):
        full_url = url.rstrip("/") + _WELL_KNOWN_PATH

    # Normalize: strip trailing slash to avoid 404s on servers
    # that don't accept the trailing-slash variant
    full_url = full_url.rstrip("/")

    return DiscoveryEndpoint(url=full_url, authority=authority)


def resolve_discovery_policy(
    policy: DiscoveryPolicy | None,
    require_https: bool,
) -> DiscoveryPolicy:
    """Resolve the effective discovery policy for a cached validation call.

    Encodes the single precedence rule shared by the sync and async cached
    ``validate_token`` paths: an explicit ``policy`` governs when provided;
    otherwise fall back to a default policy carrying only the legacy
    ``require_https`` toggle. In :class:`TokenValidationConfig` terms,
    ``discovery_policy`` wins over ``require_https`` — the boolean is the
    narrow, pre-existing knob and the full policy is the general one.
    """
    if policy is not None:
        return policy
    return DiscoveryPolicy(require_https=require_https)


def validate_url_scheme(
    url: str | None,
    policy: DiscoveryPolicy,
) -> None:
    """Validate a URL's scheme against the discovery policy.

    Args:
        url: The URL to validate.
        policy: The discovery policy to apply.

    Raises:
        ConfigurationException: If the URL scheme violates the policy.
    """
    if not url:
        raise ConfigurationException("URL cannot be empty")

    parsed = urlparse(url)

    if not parsed.scheme:
        raise ConfigurationException(f"URL must include a scheme: {url}")

    # Always restrict to HTTP/HTTPS regardless of require_https setting
    # to prevent SSRF via ftp://, file://, gopher://, etc.
    if parsed.scheme not in ("http", "https"):
        raise ConfigurationException(
            f"URL must use HTTP or HTTPS scheme, got: {parsed.scheme}"
        )

    if not policy.require_https:
        return

    if parsed.scheme == "https":
        return

    if parsed.scheme == "http" and policy.allow_http_on_loopback:
        host = parsed.hostname or ""
        if is_loopback(host):
            return

    raise ConfigurationException(
        f"HTTPS is required by discovery policy. "
        f"Got: {url}. Set require_https=False or use a loopback address."
    )


__all__ = [
    "DiscoveryEndpoint",
    "DiscoveryPolicy",
    "is_loopback",
    "parse_discovery_url",
    "resolve_discovery_policy",
    "validate_url_scheme",
]
