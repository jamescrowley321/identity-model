"""
Shared response processing logic for HTTP responses.

This module provides common response validation and parsing logic used by both
sync and async implementations.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from ..exceptions import ConfigurationException, DiscoveryException
from ..logging_config import logger
from .discovery_policy import DiscoveryPolicy
from .http_utils import get_max_jwks_keys, get_max_jwks_size
from .models import (
    AuthorizationCodeTokenResponse,
    ClientCredentialsTokenResponse,
    DiscoveryDocumentResponse,
    JsonWebKey,
    JwksResponse,
    RefreshTokenResponse,
    TokenIntrospectionResponse,
    UserInfoResponse,
)
from .parsers import jwks_from_dict
from .validators import (
    validate_https_url_with_policy,
    validate_issuer_with_policy,
    validate_parameter_values,
    validate_required_parameters,
)


if TYPE_CHECKING:
    import httpx


def _get_url_authority(url: str) -> str:
    """Extract scheme://host from a URL, lowercased per RFC 3986 §3.2.2."""
    if not url:
        return ""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _parse_ip_literal(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the IP address a host denotes, or ``None`` if it is a hostname.

    Recognises not only canonical dotted-quad / IPv6 literals but the alternate
    IPv4 encodings the OS resolver (``inet_aton``) honours — decimal
    (``2130706433``), octal (``0177.0.0.1``) and hex (``0x7f.0.0.1``) forms of
    an internal address. ``ipaddress.ip_address`` rejects those with
    ``ValueError`` (so a naive check treats them as harmless hostnames), yet the
    connection still routes to the internal address — the SSRF-evasion class.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None  # not an IPv4 literal in any encoding — a real hostname
    return ipaddress.ip_address(packed)


def _reject_internal_ip_host(
    url: str, parameter_name: str, policy: DiscoveryPolicy | None = None
) -> None:
    """Reject a URL whose host is an internal/reserved IP *literal*.

    ``mtls_endpoint_aliases`` (RFC 8705 §5) legitimately point to a foreign
    *hostname*, so they cannot be authority-matched to the issuer like the
    same-host endpoints. But a discovery document must never be able to route a
    certificate-bearing request to a link-local cloud-metadata endpoint
    (``169.254.169.254``), loopback, or an RFC1918 host — a credential-exfil /
    SSRF primitive. This blocks IP-literal internal targets in every encoding
    the resolver accepts (dotted-quad, IPv6, and decimal/octal/hex forms).

    Loopback (``127.0.0.0/8`` / ``::1``) may be opted into for local development
    via ``policy.allow_loopback_endpoints`` — a loopback-routed request is a
    limited (localhost-only) SSRF, so it is the one internal class safe to allow
    behind a flag. Link-local and RFC1918/reserved are the real SSRF targets and
    are never permitted, regardless of the flag.

    Limitation: it does NOT stop a *hostname* that resolves to an internal IP
    (DNS-rebinding SSRF); defending that needs resolve-and-pin at the HTTP layer
    and is tracked separately (T9).

    Raises:
        DiscoveryException: If ``url``'s host is an internal/reserved IP literal.
    """
    host = urlparse(url).hostname
    if not host:
        return
    ip = _parse_ip_literal(host)
    if ip is None:
        return  # a hostname, not an IP literal — allowed (see limitation above)
    if ip.is_loopback and policy is not None and policy.allow_loopback_endpoints:
        return  # local-dev opt-in; link-local / RFC1918 still fall through below
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise DiscoveryException(
            f"{parameter_name} host '{host}' is an internal/reserved IP address "
            f"({ip}); refusing to route a request there"
        )


def _validate_endpoint_authority(
    url: str,
    parameter_name: str,
    response_json: dict,
    policy: DiscoveryPolicy,
    discovery_url: str = "",
) -> None:
    """Validate that an endpoint URL's authority matches expected values.

    The expected authority is ``policy.authority`` when set, or derived from
    the discovery document's ``issuer``. The authority of the discovery URL
    itself is also allowed (handles Docker/proxy setups where the fetch
    hostname differs from the issuer). Additional allowed authorities come
    from ``policy.additional_endpoint_base_addresses``.

    Raises:
        DiscoveryException: If the endpoint URL's authority does not match.
    """

    ep_authority = _get_url_authority(url)

    # Build allowed authorities set (case-insensitive per RFC 3986 §3.2.2)
    if policy.authority:
        allowed = {_get_url_authority(policy.authority)}
    else:
        issuer = response_json.get("issuer", "")
        allowed = {_get_url_authority(issuer)} if issuer else set()

    # The discovery URL's authority is implicitly trusted — we already
    # fetched the document from it.
    if discovery_url:
        allowed.add(_get_url_authority(discovery_url))

    for addr in policy.additional_endpoint_base_addresses or []:
        allowed.add(_get_url_authority(addr))

    # Discard empty string from set (from empty URLs)
    allowed.discard("")

    if not allowed:
        raise DiscoveryException(
            f"Cannot validate {parameter_name} authority: "
            f"no authority constraint available (issuer is empty and "
            f"no policy.authority or additional_endpoint_base_addresses set)"
        )

    if ep_authority not in allowed:
        raise DiscoveryException(
            f"{parameter_name} authority '{ep_authority}' does not match "
            f"expected authorities: {sorted(allowed)}. If this is a legitimate "
            f"endpoint on a different host (RFC 8414 / RFC 9126 permit this), add "
            f"its base address to DiscoveryPolicy.additional_endpoint_base_addresses."
        )


def validate_and_parse_discovery_response(
    response: httpx.Response,
    policy: DiscoveryPolicy | None = None,
) -> dict:
    """
    Validate and parse discovery document HTTP response.

    Args:
        response: HTTP response from discovery endpoint
        policy: Optional discovery policy for configurable validation.
            When ``None``, strict defaults apply.

    Returns:
        dict: Parsed discovery document JSON

    Raises:
        DiscoveryException: If response is invalid
    """
    # Check content type - extract media type before any parameters (e.g., charset)
    content_type_header = response.headers.get("Content-Type", "")
    media_type = content_type_header.split(";")[0].strip().lower()
    if media_type != "application/json":
        raise DiscoveryException(
            f"Invalid content type. Expected application/json, got: "
            f"{response.headers.get('Content-Type', 'unknown')}"
        )

    # Parse JSON
    try:
        response_json = response.json()
    except ValueError as e:
        raise DiscoveryException(f"Invalid JSON response: {e!s}") from e

    # Validate required parameters
    validate_required_parameters(response_json)

    # Validate issuer format (policy-aware)
    validate_issuer_with_policy(response_json.get("issuer", ""), policy)

    # Validate parameter values
    validate_parameter_values(response_json)

    # Enforce require_key_set policy
    if (policy is None or policy.require_key_set) and not response_json.get("jwks_uri"):
        raise DiscoveryException(
            "Discovery document does not contain a jwks_uri, "
            "required by policy (require_key_set=True)"
        )

    # Normalize policy for endpoint validation: treat None as strict defaults
    effective_policy = policy if policy is not None else DiscoveryPolicy()

    # Validate endpoint URLs (policy-aware)
    _endpoint_names = [
        "jwks_uri",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "registration_endpoint",
        "introspection_endpoint",
        "end_session_endpoint",
        "pushed_authorization_request_endpoint",
    ]
    try:
        discovery_url = str(response.url)
    except RuntimeError:
        discovery_url = ""
    for ep_name in _endpoint_names:
        ep_url = response_json.get(ep_name)
        validate_https_url_with_policy(ep_url, ep_name, policy)
        # Validate endpoint authority (derives from issuer when policy.authority not set)
        if ep_url and effective_policy.validate_endpoints:
            _validate_endpoint_authority(
                ep_url, ep_name, response_json, effective_policy, discovery_url
            )

    # RFC 8705 §5: ``mtls_endpoint_aliases`` map endpoint names to mTLS-specific
    # URLs on a host that may legitimately differ from the issuer, so the
    # same-host issuer-authority match above cannot apply. Still enforce the
    # scheme policy (block an HTTPS->HTTP downgrade of the mTLS control) and
    # reject internal/reserved IP-literal targets (block SSRF to link-local
    # cloud metadata / RFC1918 / loopback). Hostname-based SSRF (DNS rebinding)
    # is out of scope here (tracked as T9).
    mtls_aliases = response_json.get("mtls_endpoint_aliases")
    if isinstance(mtls_aliases, dict):
        for alias_name, alias_url in mtls_aliases.items():
            alias_param = f"mtls_endpoint_aliases.{alias_name}"
            validate_https_url_with_policy(alias_url, alias_param, policy)
            if isinstance(alias_url, str) and alias_url:
                _reject_internal_ip_host(alias_url, alias_param, effective_policy)

    return response_json


def build_discovery_response(
    response_json: dict,
    cache_control: str | None = None,
) -> DiscoveryDocumentResponse:
    """
    Build DiscoveryDocumentResponse from validated JSON.

    Args:
        response_json: Validated discovery document JSON
        cache_control: Cache-Control header value from the HTTP response

    Returns:
        DiscoveryDocumentResponse: Success response with discovery data
    """
    return DiscoveryDocumentResponse(
        # Core OpenID Connect endpoints
        issuer=response_json.get("issuer"),
        jwks_uri=response_json.get("jwks_uri"),
        authorization_endpoint=response_json.get("authorization_endpoint"),
        token_endpoint=response_json.get("token_endpoint"),
        # Required properties from OpenID Connect Discovery 1.0 specification
        response_types_supported=response_json.get(
            "response_types_supported",
        ),
        subject_types_supported=response_json.get(
            "subject_types_supported",
        ),
        id_token_signing_alg_values_supported=response_json.get(
            "id_token_signing_alg_values_supported",
        ),
        # Common optional properties
        userinfo_endpoint=response_json.get("userinfo_endpoint"),
        registration_endpoint=response_json.get("registration_endpoint"),
        introspection_endpoint=response_json.get("introspection_endpoint"),
        scopes_supported=response_json.get("scopes_supported"),
        response_modes_supported=response_json.get(
            "response_modes_supported",
        ),
        grant_types_supported=response_json.get("grant_types_supported"),
        acr_values_supported=response_json.get("acr_values_supported"),
        # Cryptographic algorithm support
        id_token_encryption_alg_values_supported=response_json.get(
            "id_token_encryption_alg_values_supported",
        ),
        id_token_encryption_enc_values_supported=response_json.get(
            "id_token_encryption_enc_values_supported",
        ),
        userinfo_signing_alg_values_supported=response_json.get(
            "userinfo_signing_alg_values_supported",
        ),
        userinfo_encryption_alg_values_supported=response_json.get(
            "userinfo_encryption_alg_values_supported",
        ),
        userinfo_encryption_enc_values_supported=response_json.get(
            "userinfo_encryption_enc_values_supported",
        ),
        request_object_signing_alg_values_supported=response_json.get(
            "request_object_signing_alg_values_supported",
        ),
        request_object_encryption_alg_values_supported=response_json.get(
            "request_object_encryption_alg_values_supported",
        ),
        request_object_encryption_enc_values_supported=response_json.get(
            "request_object_encryption_enc_values_supported",
        ),
        # Token endpoint authentication
        token_endpoint_auth_methods_supported=response_json.get(
            "token_endpoint_auth_methods_supported",
        ),
        # PKCE support
        code_challenge_methods_supported=response_json.get(
            "code_challenge_methods_supported",
        ),
        token_endpoint_auth_signing_alg_values_supported=response_json.get(
            "token_endpoint_auth_signing_alg_values_supported",
        ),
        # Display and UI
        display_values_supported=response_json.get(
            "display_values_supported",
        ),
        claim_types_supported=response_json.get("claim_types_supported"),
        claims_supported=response_json.get("claims_supported"),
        claims_locales_supported=response_json.get(
            "claims_locales_supported",
        ),
        ui_locales_supported=response_json.get("ui_locales_supported"),
        # Feature support flags
        claims_parameter_supported=response_json.get(
            "claims_parameter_supported",
        ),
        request_parameter_supported=response_json.get(
            "request_parameter_supported",
        ),
        request_uri_parameter_supported=response_json.get(
            "request_uri_parameter_supported",
        ),
        require_request_uri_registration=response_json.get(
            "require_request_uri_registration",
        ),
        # Pushed Authorization Requests (RFC 9126 §5)
        pushed_authorization_request_endpoint=response_json.get(
            "pushed_authorization_request_endpoint",
        ),
        require_pushed_authorization_requests=response_json.get(
            "require_pushed_authorization_requests",
        ),
        # Authorization-response issuer parameter support (RFC 9207 §3)
        authorization_response_iss_parameter_supported=response_json.get(
            "authorization_response_iss_parameter_supported",
        ),
        # JWT-Secured Authorization Response Mode (JARM §5) algorithm support
        authorization_signing_alg_values_supported=response_json.get(
            "authorization_signing_alg_values_supported",
        ),
        authorization_encryption_alg_values_supported=response_json.get(
            "authorization_encryption_alg_values_supported",
        ),
        authorization_encryption_enc_values_supported=response_json.get(
            "authorization_encryption_enc_values_supported",
        ),
        # Mutual-TLS support (RFC 8705 §3.3 / §5)
        mtls_endpoint_aliases=response_json.get("mtls_endpoint_aliases"),
        tls_client_certificate_bound_access_tokens=response_json.get(
            "tls_client_certificate_bound_access_tokens",
        ),
        # RP-Initiated Logout support (OpenID Connect RP-Initiated Logout 1.0 §2)
        end_session_endpoint=response_json.get("end_session_endpoint"),
        # Back-Channel Logout support (OpenID Connect Back-Channel Logout 1.0 §3)
        backchannel_logout_supported=response_json.get(
            "backchannel_logout_supported",
        ),
        backchannel_logout_session_supported=response_json.get(
            "backchannel_logout_session_supported",
        ),
        # Documentation and policy
        service_documentation=response_json.get("service_documentation"),
        op_policy_uri=response_json.get("op_policy_uri"),
        op_tos_uri=response_json.get("op_tos_uri"),
        cache_control=cache_control,
        is_successful=True,
    )


_VALID_JWKS_CONTENT_TYPES = frozenset({"application/json", "application/jwk-set+json"})


def _extract_jwks_keys(
    response_json: object,
) -> tuple[list[dict], str | None]:
    """Extract and validate the 'keys' array from a parsed JWKS response.

    Returns:
        Tuple of (raw_keys_list, error_string). On success error_string is None.
    """
    if not isinstance(response_json, dict):
        return [], (
            "Invalid JWKS response: expected a JSON object, "
            f"got {type(response_json).__name__}"
        )

    try:
        raw_keys = response_json["keys"]
    except KeyError:
        return [], "Invalid JWKS response: missing required 'keys' field"

    if not isinstance(raw_keys, list):
        return [], (
            "Invalid JWKS response: 'keys' field must be a JSON array, "
            f"got {type(raw_keys).__name__}"
        )

    max_keys = get_max_jwks_keys()
    if len(raw_keys) > max_keys:
        return [], (
            f"JWKS response contains too many keys: {len(raw_keys)} "
            f"exceeds limit of {max_keys}"
        )

    # Validate each element is a dict before downstream processing
    for i, key in enumerate(raw_keys):
        if not isinstance(key, dict):
            return [], (
                f"Invalid JWKS response: key at index {i} is not a JSON object, "
                f"got {type(key).__name__}"
            )

    return raw_keys, None


def _build_jwks_keys(raw_keys: list[dict]) -> tuple[list[JsonWebKey], str | None]:
    """Build JsonWebKeys, ignoring members the client cannot use.

    RFC 7517 §5: a key with an unknown curve or missing parameters is skipped
    rather than rejecting the whole set, so an unrelated key cannot block
    verification against a usable one. A set with no usable key is an error.

    Returns:
        ``(keys, None)`` on success, ``([], error)`` when no key is usable.
    """
    keys: list[JsonWebKey] = []
    skipped: list[str] = []
    for key in raw_keys:
        try:
            keys.append(jwks_from_dict(key))
        except ConfigurationException as e:
            logger.warning("Ignoring unusable JWK kid=%r: %s", key.get("kid"), e)
            skipped.append(str(e))
    if raw_keys and not keys:
        return [], f"JWKS has no usable keys: {'; '.join(skipped)}"
    return keys, None


def parse_jwks_response(response: httpx.Response) -> JwksResponse:
    """
    Parse JWKS HTTP response.

    Args:
        response: HTTP response from JWKS endpoint

    Returns:
        JwksResponse: Parsed JWKS response with keys
    """
    if response.is_success:
        # Check response size before parsing — Content-Length first to
        # avoid materialising the body for obviously-oversized responses.
        max_size = get_max_jwks_size()
        content_length = response.headers.get("Content-Length")
        try:
            cl_too_large = content_length is not None and int(content_length) > max_size
        except (ValueError, TypeError):
            logger.warning("Malformed Content-Length header: %s", content_length)
            cl_too_large = False
        if cl_too_large:
            size_desc = f"Content-Length {content_length}"
        elif len(response.content) > max_size:
            size_desc = f"{len(response.content)} bytes"
        else:
            size_desc = None
        if size_desc:
            return JwksResponse(
                is_successful=False,
                error=(
                    f"JWKS response too large: {size_desc} "
                    f"exceeds limit of {max_size} bytes"
                ),
            )

        content_type_header = response.headers.get("Content-Type", "")
        media_type = content_type_header.split(";")[0].strip().lower()
        if not media_type:
            return JwksResponse(
                is_successful=False,
                error="JWKS response missing Content-Type header",
            )
        if media_type not in _VALID_JWKS_CONTENT_TYPES:
            return JwksResponse(
                is_successful=False,
                error=(
                    f"Invalid JWKS Content-Type: expected application/json or "
                    f"application/jwk-set+json, got: {content_type_header}"
                ),
            )

        response_json = response.json()
        raw_keys, keys_error = _extract_jwks_keys(response_json)
        keys: list[JsonWebKey] = []
        if not keys_error:
            keys, keys_error = _build_jwks_keys(raw_keys)
        if keys_error:
            return JwksResponse(is_successful=False, error=keys_error)
        cache_control = response.headers.get("cache-control")
        return JwksResponse(is_successful=True, keys=keys, cache_control=cache_control)

    error_msg = (
        f"JSON web keys request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return JwksResponse(
        is_successful=False,
        error=error_msg,
    )


def parse_token_response(
    response: httpx.Response,
) -> ClientCredentialsTokenResponse:
    """
    Parse token HTTP response.

    Args:
        response: HTTP response from token endpoint

    Returns:
        ClientCredentialsTokenResponse: Parsed token response
    """
    if response.is_success:
        response_json = response.json()
        return ClientCredentialsTokenResponse(
            is_successful=True,
            token=response_json,
        )

    error_msg = (
        f"Token generation request failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return ClientCredentialsTokenResponse(
        is_successful=False,
        error=error_msg,
    )


def parse_auth_code_token_response(
    response: httpx.Response,
) -> AuthorizationCodeTokenResponse:
    """Parse authorization code token exchange HTTP response."""
    if response.is_success:
        return AuthorizationCodeTokenResponse(
            is_successful=True,
            token=response.json(),
        )

    error_msg = (
        f"Authorization code token exchange failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return AuthorizationCodeTokenResponse(
        is_successful=False,
        error=error_msg,
    )


def parse_refresh_token_response(
    response: httpx.Response,
) -> RefreshTokenResponse:
    """Parse refresh token grant HTTP response."""
    if response.is_success:
        return RefreshTokenResponse(is_successful=True, token=response.json())

    error_msg = (
        f"Token refresh failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return RefreshTokenResponse(is_successful=False, error=error_msg)


def parse_introspection_response(
    response: httpx.Response,
) -> TokenIntrospectionResponse:
    """Parse token introspection HTTP response (RFC 7662)."""
    if response.is_success:
        data = response.json()
        if not isinstance(data, dict):
            return TokenIntrospectionResponse(
                is_successful=False,
                error=f"Introspection response is not a JSON object: {type(data).__name__}",
            )
        return TokenIntrospectionResponse(
            is_successful=True,
            claims=data,
        )

    error_msg = (
        f"Token introspection failed with status code: "
        f"{response.status_code}. Response Content: {response.content}"
    )
    return TokenIntrospectionResponse(is_successful=False, error=error_msg)


def parse_userinfo_response(response: httpx.Response) -> UserInfoResponse:
    """
    Parse UserInfo HTTP response.

    Supports Content-Type detection per OIDC Core 1.0 Section 5.3.2/5.3.3:
    - application/json: Claims extracted as dict
    - application/jwt: Raw JWT string stored for caller to decode/validate

    Args:
        response: HTTP response from UserInfo endpoint

    Returns:
        UserInfoResponse: Parsed response with claims or raw JWT
    """
    if not response.is_success:
        error_msg = (
            f"UserInfo request failed with status code: "
            f"{response.status_code}. Response Content: {response.content}"
        )
        return UserInfoResponse(
            is_successful=False,
            error=error_msg,
        )

    content_type = response.headers.get("Content-Type", "")
    media_type = content_type.split(";")[0].strip().lower()

    if media_type == "application/jwt":
        return UserInfoResponse(
            is_successful=True,
            raw=response.text,
        )

    # Default to JSON parsing (application/json or unspecified)
    claims = response.json()
    return UserInfoResponse(
        is_successful=True,
        claims=claims,
    )


__all__ = [
    "build_discovery_response",
    "parse_auth_code_token_response",
    "parse_introspection_response",
    "parse_jwks_response",
    "parse_token_response",
    "parse_userinfo_response",
    "validate_and_parse_discovery_response",
]
