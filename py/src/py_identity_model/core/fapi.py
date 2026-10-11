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
- Strong signing algorithms (PS256, ES256 - not RS256)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlparse


if TYPE_CHECKING:
    from .models import DiscoveryDocumentResponse


FAPI2_ALLOWED_SIGNING_ALGORITHMS = frozenset({"PS256", "ES256"})
FAPI2_ALLOWED_AUTH_METHODS = frozenset(
    {"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}
)
FAPI2_REQUIRED_PKCE_METHOD = "S256"
FAPI2_REQUIRED_RESPONSE_TYPE = "code"


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
            f"Algorithm '{algorithm}' not allowed; "
            f"use {', '.join(sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS))}"
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


def validate_fapi_discovery(
    discovery: DiscoveryDocumentResponse,
) -> FAPIValidationResult:
    """Validate a discovery document for FAPI 2.0 server support.

    Checks that the authorization server advertises capabilities
    required by FAPI 2.0.  When optional metadata fields are absent, their
    RFC 8414 §2 defaults are assumed.  OIDC Discovery §3 marks
    ``response_types_supported`` and ``id_token_signing_alg_values_supported``
    REQUIRED with no default; discovery parsing already rejects a document
    without them, so the ``None`` branches below are reached only for a
    hand-built response.

    Args:
        discovery: A discovery document response.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    if not discovery.is_successful:
        return FAPIValidationResult(
            violations=["Discovery document fetch failed"],
        )

    violations: list[str] = []

    # Check supported grant types include authorization_code.
    # RFC 8414 §2 / OIDC Discovery §3 default when omitted is
    # ["authorization_code", "implicit"] — includes authorization_code.
    grants = discovery.grant_types_supported
    if grants is not None and "authorization_code" not in grants:
        violations.append("Server does not support authorization_code grant type")

    # Check response_types_supported includes "code" (authorization code flow).
    # OIDC Discovery §3 marks this REQUIRED with no default. An absent value
    # is not reported here (see the docstring).
    response_types = discovery.response_types_supported
    if response_types is not None and "code" not in response_types:
        violations.append(
            "Server does not support 'code' response type "
            "(authorization code flow required)"
        )

    # Check token endpoint auth methods for strong client auth.
    # RFC 8414 §2 default when omitted is ["client_secret_basic"] — FAPI-prohibited.
    auth_methods = discovery.token_endpoint_auth_methods_supported
    if auth_methods is None:
        violations.append(
            "token_endpoint_auth_methods_supported not advertised; "
            "RFC 8414 default is client_secret_basic, which FAPI 2.0 prohibits"
        )
    else:
        supported = set(auth_methods) & FAPI2_ALLOWED_AUTH_METHODS
        if not supported:
            violations.append(
                "Server does not support FAPI-compliant client auth "
                "(private_key_jwt or tls_client_auth)"
            )

    # Check signing algorithms.
    # OIDC Discovery §3 marks this REQUIRED with no default. The RS256 default
    # belongs to the client's id_token_signed_response_alg (Registration §2).
    algs = discovery.id_token_signing_alg_values_supported
    if algs is None:
        violations.append(
            "id_token_signing_alg_values_supported not advertised "
            "(REQUIRED by OIDC Discovery §3); the client registration default "
            "is RS256, which FAPI 2.0 prohibits"
        )
    else:
        fapi_algs = set(algs) & FAPI2_ALLOWED_SIGNING_ALGORITHMS
        if not fapi_algs:
            violations.append(
                "Server does not support FAPI-compliant signing algorithms "
                f"({', '.join(sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS))})"
            )

    # Check PKCE support — FAPI 2.0 mandates S256.
    pkce_methods = discovery.code_challenge_methods_supported
    if pkce_methods is not None and "S256" not in pkce_methods:
        violations.append(
            "Server does not support S256 PKCE "
            "(FAPI 2.0 requires code_challenge_methods_supported to include S256)"
        )

    return FAPIValidationResult(violations=violations)


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
