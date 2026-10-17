"""
FAPI 2.0 Security Profile compliance validation.

Provides validation helpers to check that OAuth 2.0 / OpenID Connect
configurations meet FAPI 2.0 Security Profile requirements.

FAPI 2.0 mandates:
- PAR (Pushed Authorization Requests, RFC 9126)
- PKCE with S256 (plain not allowed)
- Authorization code flow only (response_type "code")
- Sender-constrained tokens (DPoP or mTLS)
- Confidential clients with strong auth (private_key_jwt or tls_client_auth)
- Strong signing algorithms (PS256, ES256, EdDSA - not RS256)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse


if TYPE_CHECKING:
    from .models import DiscoveryDocumentResponse


# FAPI 2.0 Security Profile §5.4.1: PS256, ES256 or EdDSA (Ed25519).
FAPI2_ALLOWED_SIGNING_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
FAPI2_ALLOWED_AUTH_METHODS = frozenset(
    {"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}
)
FAPI2_REQUIRED_PKCE_METHOD = "S256"
FAPI2_REQUIRED_RESPONSE_TYPE = "code"


def _str_values(value: object) -> frozenset[str]:
    """The strings in a metadata array; anything else advertises nothing.

    Discovery metadata is server input, so a malformed array fails closed
    as an unsupported capability instead of raising.
    """
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return frozenset()
    return frozenset(value)


def _fapi_algorithms() -> str:
    return ", ".join(sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS))


def _required_metadata_missing(name: str) -> str:
    """Violation text for an absent REQUIRED OIDC Discovery 1.0 §3 field."""
    return (
        f"{name} not advertised; "
        "OpenID Connect Discovery 1.0 §3 marks it REQUIRED, with no default"
    )


@dataclass
class FAPIValidationResult:
    """Result of a FAPI 2.0 compliance check.

    ``is_compliant`` is derived from ``violations`` — it is ``True`` when
    ``violations`` is empty.  It cannot be set directly.
    """

    violations: list[str] = field(default_factory=list)
    is_compliant: bool = field(init=False)

    def __post_init__(self) -> None:
        self.is_compliant = len(self.violations) == 0


def validate_fapi_authorization_request(  # noqa: PLR0913  # FAPI 2.0 Security Profile requires all these fields
    *,
    response_type: str,
    code_challenge: str | None,
    code_challenge_method: str | None,
    redirect_uri: str,
    use_par: bool,
    algorithm: str | None = None,
) -> FAPIValidationResult:
    """Validate an authorization request against FAPI 2.0 requirements.

    All parameters are keyword-only to prevent positional argument mistakes.

    Args:
        response_type: OAuth 2.0 response type.
        code_challenge: PKCE code challenge value.
        code_challenge_method: PKCE method (must be ``"S256"``).
        redirect_uri: The redirect URI (must use ``https``).
        use_par: Whether PAR is being used.
        algorithm: Signing algorithm for JAR/DPoP (validated if provided).

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    violations: list[str] = []

    if response_type != FAPI2_REQUIRED_RESPONSE_TYPE:
        violations.append(f"response_type must be 'code', got '{response_type}'")

    if not code_challenge or not code_challenge.strip():
        violations.append("PKCE code_challenge is required")

    if code_challenge_method is None:
        violations.append("PKCE code_challenge_method is required")
    elif code_challenge_method != FAPI2_REQUIRED_PKCE_METHOD:
        violations.append(f"PKCE method must be 'S256', got '{code_challenge_method}'")

    if not use_par:
        violations.append("PAR (Pushed Authorization Requests) is required")

    if not isinstance(redirect_uri, str):
        violations.append("redirect_uri must be a string")
    else:
        parsed_uri = urlparse(redirect_uri.strip())
        if parsed_uri.scheme.lower() != "https":
            violations.append(f"redirect_uri must use HTTPS, got '{redirect_uri}'")
        elif not parsed_uri.hostname:
            violations.append(f"redirect_uri must have a host, got '{redirect_uri}'")

    if algorithm is not None and algorithm not in FAPI2_ALLOWED_SIGNING_ALGORITHMS:
        violations.append(
            f"Algorithm '{algorithm}' not allowed; use {_fapi_algorithms()}"
        )

    return FAPIValidationResult(violations=violations)


def validate_fapi_client_config(
    *,
    auth_method: str | None,
    use_dpop: bool = False,
    use_mtls: bool = False,
) -> FAPIValidationResult:
    """Validate client configuration against FAPI 2.0 requirements.

    Args:
        auth_method: Token endpoint authentication method (e.g.
            ``"private_key_jwt"`` or ``"tls_client_auth"``).  ``None``
            means public client (no authentication).
        use_dpop: Whether DPoP sender-constraining is enabled.
        use_mtls: Whether mTLS sender-constraining is enabled.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    violations: list[str] = []

    if auth_method is None:
        violations.append("Client authentication is required (confidential client)")
    elif auth_method not in FAPI2_ALLOWED_AUTH_METHODS:
        violations.append(
            f"Auth method '{auth_method}' is not FAPI 2.0 compliant; "
            f"use {', '.join(sorted(FAPI2_ALLOWED_AUTH_METHODS))}"
        )

    if not use_dpop and not use_mtls:
        violations.append("Sender-constrained tokens required (enable DPoP or mTLS)")

    return FAPIValidationResult(violations=violations)


def _flow_violations(discovery: DiscoveryDocumentResponse) -> list[str]:
    """Grant and response type: the authorization code flow."""
    violations: list[str] = []

    # Check supported grant types include authorization_code.
    # OPTIONAL; OIDC Discovery 1.0 §3 and RFC 8414 §2 default when omitted is
    # ["authorization_code", "implicit"] — compliant.
    grants = discovery.grant_types_supported
    if grants is not None and "authorization_code" not in _str_values(grants):
        violations.append("Server does not support authorization_code grant type")

    # Check response_types_supported includes "code" (authorization code flow).
    # REQUIRED by OIDC Discovery 1.0 §3, no default.  (The ["code"] default
    # belongs to Registration §2 client metadata, not provider metadata.)
    response_types = discovery.response_types_supported
    if response_types is None:
        violations.append(_required_metadata_missing("response_types_supported"))
    elif FAPI2_REQUIRED_RESPONSE_TYPE not in _str_values(response_types):
        violations.append(
            "Server does not support 'code' response type "
            "(authorization code flow required)"
        )

    return violations


def _client_auth_violations(discovery: DiscoveryDocumentResponse) -> list[str]:
    """Client authentication methods and their JWT algorithms."""
    violations: list[str] = []

    # Check token endpoint auth methods for strong client auth.
    # RFC 8414 §2 default when omitted is ["client_secret_basic"] — FAPI-prohibited.
    auth_methods = discovery.token_endpoint_auth_methods_supported
    if auth_methods is None:
        violations.append(
            "token_endpoint_auth_methods_supported not advertised; "
            "RFC 8414 default is client_secret_basic, which FAPI 2.0 prohibits"
        )
    else:
        supported = _str_values(auth_methods) & FAPI2_ALLOWED_AUTH_METHODS
        if not supported:
            violations.append(
                "Server does not support FAPI-compliant client auth "
                "(private_key_jwt or tls_client_auth)"
            )

    # The private_key_jwt assertion is a JWT, so FAPI 2.0 Security Profile
    # §5.4.1 applies to its algorithm.  RFC 8414 §2 scopes this field to JWT
    # client authentication, so it only matters when private_key_jwt is offered.
    if "private_key_jwt" in _str_values(auth_methods):
        auth_algs = discovery.token_endpoint_auth_signing_alg_values_supported
        if auth_algs is None:
            violations.append(
                "token_endpoint_auth_signing_alg_values_supported not advertised; "
                f"private_key_jwt needs one of {_fapi_algorithms()} "
                "(FAPI 2.0 Security Profile §5.4.1)"
            )
        elif not _str_values(auth_algs) & FAPI2_ALLOWED_SIGNING_ALGORITHMS:
            violations.append(
                "Server does not support FAPI-compliant token endpoint auth "
                f"signing algorithms ({_fapi_algorithms()})"
            )

    return violations


def _id_token_alg_violations(discovery: DiscoveryDocumentResponse) -> list[str]:
    """ID Token signing algorithms."""
    violations: list[str] = []

    # ID Token signing algorithms.
    # REQUIRED by OIDC Discovery 1.0 §3, no default.  (The RS256 default
    # belongs to Registration §2 client metadata, not provider metadata.)
    algs = discovery.id_token_signing_alg_values_supported
    if algs is None:
        violations.append(
            _required_metadata_missing("id_token_signing_alg_values_supported")
        )
    elif not _str_values(algs) & FAPI2_ALLOWED_SIGNING_ALGORITHMS:
        violations.append(
            "Server does not support FAPI-compliant signing algorithms "
            f"({_fapi_algorithms()})"
        )

    return violations


def _authorization_endpoint_violations(
    discovery: DiscoveryDocumentResponse,
) -> list[str]:
    """PKCE, PAR and the RFC 9207 ``iss`` parameter."""
    violations: list[str] = []

    # Check PKCE support — FAPI 2.0 Security Profile §5.3.2.2(5) requires S256.
    # RFC 8414 §2: when omitted, the server does not support PKCE.
    pkce_methods = discovery.code_challenge_methods_supported
    if pkce_methods is None:
        violations.append(
            "code_challenge_methods_supported not advertised; RFC 8414 §2 reads "
            "that as no PKCE support, and FAPI 2.0 Security Profile §5.3.2.2 "
            "requires S256"
        )
    elif FAPI2_REQUIRED_PKCE_METHOD not in _str_values(pkce_methods):
        violations.append(
            "Server does not support S256 PKCE "
            "(FAPI 2.0 requires code_challenge_methods_supported to include S256)"
        )

    # FAPI 2.0 Security Profile §5.3.2.2(2): PAR (RFC 9126) is required.
    if not discovery.pushed_authorization_request_endpoint:
        violations.append(
            "pushed_authorization_request_endpoint not advertised; FAPI 2.0 "
            "Security Profile §5.3.2.2 requires pushed authorization requests "
            "(RFC 9126)"
        )

    # FAPI 2.0 Security Profile §5.3.2.2(7): the server returns iss in the
    # authorization response.  RFC 9207 §3: absent means false.
    if discovery.authorization_response_iss_parameter_supported is not True:
        violations.append(
            "authorization_response_iss_parameter_supported is not true; FAPI 2.0 "
            "Security Profile §5.3.2.2 requires the iss authorization response "
            "parameter (RFC 9207 §3)"
        )

    return violations


def _sender_constraint_violations(discovery: DiscoveryDocumentResponse) -> list[str]:
    """Sender-constrained access tokens."""
    violations: list[str] = []

    # FAPI 2.0 Security Profile §5.3.2.1(4-5): access tokens are
    # sender-constrained with DPoP (RFC 9449 §5.1 metadata) or MTLS
    # (RFC 8705 §3.3 metadata, absent means false).  A DPoP proof is a JWT,
    # so §5.4.1 limits its algorithm too.
    supports_dpop = bool(
        _str_values(discovery.dpop_signing_alg_values_supported)
        & FAPI2_ALLOWED_SIGNING_ALGORITHMS
    )
    supports_mtls = discovery.tls_client_certificate_bound_access_tokens is True
    if not supports_dpop and not supports_mtls:
        violations.append(
            "Neither dpop_signing_alg_values_supported with one of "
            f"{_fapi_algorithms()} nor tls_client_certificate_bound_access_tokens: "
            "true is advertised; FAPI 2.0 Security Profile §5.3.2.1 requires "
            "sender-constrained access tokens (DPoP or MTLS)"
        )

    return violations


def validate_fapi_discovery(
    discovery: DiscoveryDocumentResponse,
) -> FAPIValidationResult:
    """Validate a discovery document for FAPI 2.0 server support.

    Checks that the authorization server advertises capabilities
    required by FAPI 2.0.  Absent REQUIRED metadata
    (``response_types_supported``, ``id_token_signing_alg_values_supported``,
    OIDC Discovery 1.0 §3) is a violation.  So is absent metadata for a
    capability FAPI 2.0 requires: PKCE, PAR, the RFC 9207 ``iss`` response
    parameter and sender-constrained access tokens.  Only
    ``grant_types_supported`` and ``token_endpoint_auth_methods_supported``
    take their OIDC Discovery 1.0 §3 / RFC 8414 §2 default when absent.

    Args:
        discovery: A discovery document response.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    if not discovery.is_successful:
        return FAPIValidationResult(
            violations=["Discovery document fetch failed"],
        )

    return FAPIValidationResult(
        violations=[
            *_flow_violations(discovery),
            *_client_auth_violations(discovery),
            *_id_token_alg_violations(discovery),
            *_authorization_endpoint_violations(discovery),
            *_sender_constraint_violations(discovery),
        ]
    )


__all__ = [
    "FAPI2_ALLOWED_AUTH_METHODS",
    "FAPI2_ALLOWED_SIGNING_ALGORITHMS",
    "FAPI2_REQUIRED_PKCE_METHOD",
    "FAPI2_REQUIRED_RESPONSE_TYPE",
    "FAPIValidationResult",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
]
