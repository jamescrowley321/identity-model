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

from dataclasses import InitVar, dataclass, field, replace
from ipaddress import ip_address
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .authorize_url import build_par_authorization_url
from .jar import create_request_object
from .models import (
    AuthorizationCodeTokenRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RequestObjectKey,
    TokenValidationConfig,
)
from .mtls import resolve_mtls_endpoint
from .state_validation import validate_authorize_callback_issuer


if TYPE_CHECKING:
    from .authorize_response import AuthorizeCallbackResponse
    from .dpop import DPoPKey
    from .models import DiscoveryDocumentResponse
    from .state_validation import StateValidationResult


# FAPI 2.0 Security Profile §5.4.1: PS256, ES256 or EdDSA (Ed25519).
FAPI2_ALLOWED_SIGNING_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
FAPI2_ALLOWED_AUTH_METHODS = frozenset(
    {"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}
)
_MTLS_AUTH_METHODS = frozenset({"tls_client_auth", "self_signed_tls_client_auth"})
FAPI2_REQUIRED_PKCE_METHOD = "S256"
FAPI2_REQUIRED_RESPONSE_TYPE = "code"
# FAPI 2.0 Security Profile §5.3.3.2: clients should not send longer nonces.
FAPI2_MAX_NONCE_LENGTH = 64
# FAPI 2.0 Message Signing §5.3.2: a request object's exp is at most 60
# minutes after its nbf.
FAPI2_MAX_REQUEST_OBJECT_LIFETIME = 3600


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


def _redirect_uri_violations(redirect_uri: object, *, native_app: bool) -> list[str]:
    """``https`` redirect URIs; ``http`` only for a native app's loopback.

    FAPI 2.0 Security Profile §5.3.2.2(8) forbids ``http`` redirect URIs
    except for native clients using loopback interface redirection
    (RFC 8252 §7.3).
    """
    if not isinstance(redirect_uri, str):
        return ["redirect_uri must be a string"]
    parsed = urlparse(redirect_uri.strip())
    scheme = parsed.scheme.lower()
    if not parsed.hostname:
        return [f"redirect_uri must have a host, got '{redirect_uri}'"]
    if scheme == "https":
        return []
    if scheme == "http" and native_app and _is_loopback(parsed.hostname):
        return []
    return [
        f"redirect_uri must use HTTPS, got '{redirect_uri}'; http is allowed only "
        "for a native app's loopback redirect (FAPI 2.0 Security Profile "
        "§5.3.2.2, RFC 8252 §7.3)"
    ]


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _algorithm_violation(what: str, algorithm: str) -> list[str]:
    if algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS:
        return []
    return [
        f"{what} algorithm '{algorithm}' not allowed; use {_fapi_algorithms()} "
        "(FAPI 2.0 Security Profile §5.4.1)"
    ]


def validate_fapi_authorization_request(
    request: PushedAuthorizationRequest,
    *,
    native_app: bool = False,
) -> FAPIValidationResult:
    """Validate a pushed authorization request against FAPI 2.0.

    Checks FAPI 2.0 Security Profile §5.3.3.2: ``response_type=code``, PKCE
    with ``S256``, a ``nonce`` of at most 64 characters, and the redirect URI
    rules of §5.3.2.2.  The request's client authentication and DPoP key are
    checked as in :func:`validate_fapi_client_config`, without the
    assertion-audience check (that needs the issuer).

    Args:
        request: The pushed authorization request (RFC 9126) to send.
        native_app: Allow an ``http`` loopback redirect URI (RFC 8252 §7.3).

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    violations: list[str] = []

    if request.response_type != FAPI2_REQUIRED_RESPONSE_TYPE:
        violations.append(
            f"response_type must be 'code', got '{request.response_type}'"
        )

    code_challenge = request.code_challenge
    if not code_challenge or not code_challenge.strip():
        violations.append("PKCE code_challenge is required")

    method = request.code_challenge_method
    if method is None:
        violations.append("PKCE code_challenge_method is required")
    elif method != FAPI2_REQUIRED_PKCE_METHOD:
        violations.append(f"PKCE method must be 'S256', got '{method}'")

    if request.nonce is not None and len(request.nonce) > FAPI2_MAX_NONCE_LENGTH:
        violations.append(
            f"nonce is {len(request.nonce)} characters; FAPI 2.0 Security "
            f"Profile §5.3.3.2 limits it to {FAPI2_MAX_NONCE_LENGTH}"
        )

    violations.extend(
        _redirect_uri_violations(request.redirect_uri, native_app=native_app)
    )
    violations.extend(
        _client_violations(
            private_key_jwt=request.private_key_jwt,
            mtls=request.mtls,
            dpop_key=request.dpop_key,
        )
    )

    return FAPIValidationResult(violations=violations)


def _client_violations(
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
    dpop_key: DPoPKey | None,
) -> list[str]:
    """Client authentication and sender constraint (§5.3.3.1, §5.4.1)."""
    return [
        *_client_authentication_violations(private_key_jwt=private_key_jwt, mtls=mtls),
        *_sender_constraint_request_violations(dpop_key=dpop_key, mtls=mtls),
    ]


def _client_authentication_violations(
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
) -> list[str]:
    violations: list[str] = []
    if private_key_jwt is None and mtls is None:
        violations.append(
            "Client authentication is required: private_key_jwt or mTLS "
            "(FAPI 2.0 Security Profile §5.3.3.1)"
        )
    if private_key_jwt is not None:
        violations.extend(
            _algorithm_violation("private_key_jwt", private_key_jwt.algorithm)
        )
    if mtls is not None and mtls.auth_method not in FAPI2_ALLOWED_AUTH_METHODS:
        violations.append(
            f"mTLS auth method '{mtls.auth_method}' is not FAPI 2.0 compliant; "
            f"use {', '.join(sorted(FAPI2_ALLOWED_AUTH_METHODS))}"
        )
    return violations


def _sender_constraint_request_violations(
    *,
    dpop_key: DPoPKey | None,
    mtls: MtlsClientAuth | None,
) -> list[str]:
    if dpop_key is not None:
        return _algorithm_violation("DPoP", dpop_key.algorithm)
    if mtls is None:
        return [
            "Sender-constrained tokens required: a DPoP key or mTLS "
            "(FAPI 2.0 Security Profile §5.3.3.1)"
        ]
    return []


def _assertion_audience_violations(
    private_key_jwt: PrivateKeyJwt | None, issuer: str
) -> list[str]:
    """§5.3.3.1: the assertion ``aud`` is the issuer, never the endpoint URL."""
    if private_key_jwt is None:
        return []
    aud = private_key_jwt.audience or private_key_jwt.issuer
    if aud == issuer:
        return []
    return [
        f"private_key_jwt assertion aud would be {aud!r}, not the issuer "
        f"{issuer!r} (FAPI 2.0 Security Profile §5.3.3.1)"
    ]


def validate_fapi_client_config(
    *,
    issuer: str,
    private_key_jwt: PrivateKeyJwt | None = None,
    mtls: MtlsClientAuth | None = None,
    dpop_key: DPoPKey | None = None,
) -> FAPIValidationResult:
    """Validate a client's authentication and sender constraint for FAPI 2.0.

    FAPI 2.0 Security Profile §5.3.3.1: the client authenticates with
    ``private_key_jwt`` or mTLS and sender-constrains its tokens with DPoP or
    mTLS.  A ``private_key_jwt`` assertion's ``aud`` must be the issuer as a
    single string, so an ``audience`` or ``issuer`` naming anything else, or
    neither being set (the endpoint-URL fallback), is a violation.  JWT
    algorithms are limited by §5.4.1.

    Args:
        issuer: The authorization server's issuer identifier.
        private_key_jwt: The ``private_key_jwt`` settings, if used.
        mtls: The mTLS client certificate settings, if used.
        dpop_key: The DPoP key, if tokens are DPoP-bound.

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    return FAPIValidationResult(
        violations=[
            *_client_violations(
                private_key_jwt=private_key_jwt, mtls=mtls, dpop_key=dpop_key
            ),
            *_assertion_audience_violations(private_key_jwt, issuer),
        ]
    )


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


def _request_object_key_violations(
    key: RequestObjectKey | None, advertised: tuple[str, ...] | None
) -> list[str]:
    """Message Signing §5.3.2: FAPI algorithm, lifetime of at most 3600 s."""
    if key is None:
        return []
    violations = _algorithm_violation("request object", key.algorithm)
    if not 0 < key.lifetime <= FAPI2_MAX_REQUEST_OBJECT_LIFETIME:
        violations.append(
            f"request object lifetime must be 1 to "
            f"{FAPI2_MAX_REQUEST_OBJECT_LIFETIME} seconds, got {key.lifetime} "
            "(FAPI 2.0 Message Signing §5.3.2)"
        )
    if (
        # A non-FAPI algorithm is already reported above.
        advertised is not None
        and key.algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS
        and key.algorithm not in advertised
    ):
        violations.append(
            f"Server does not advertise request object algorithm "
            f"'{key.algorithm}' in request_object_signing_alg_values_supported"
        )
    return violations


def _server_support_violations(
    discovery: DiscoveryDocumentResponse,
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
) -> list[str]:
    """The server must support the client's chosen auth and token binding.

    :func:`validate_fapi_discovery` only checks that *some* FAPI method is
    offered; the profile's own method has to be one of them.
    """
    violations: list[str] = []
    methods = _str_values(discovery.token_endpoint_auth_methods_supported)
    if private_key_jwt is not None:
        if "private_key_jwt" not in methods:
            violations.append(
                "Server does not advertise private_key_jwt in "
                "token_endpoint_auth_methods_supported"
            )
        auth_algs = _str_values(
            discovery.token_endpoint_auth_signing_alg_values_supported
        )
        if private_key_jwt.algorithm not in auth_algs:
            violations.append(
                f"Server does not advertise private_key_jwt algorithm "
                f"'{private_key_jwt.algorithm}' in "
                "token_endpoint_auth_signing_alg_values_supported"
            )
        dpop_algs = _str_values(discovery.dpop_signing_alg_values_supported)
        if not dpop_algs & FAPI2_ALLOWED_SIGNING_ALGORITHMS:
            violations.append(
                "Server does not advertise DPoP with one of "
                f"{_fapi_algorithms()} (dpop_signing_alg_values_supported); a "
                "private_key_jwt client binds its tokens with DPoP"
            )
    if mtls is not None:
        # RFC 8705 §2.1 and §2.2 share one request shape; the PKI and
        # self-signed variants differ only in how the server checks the cert.
        if not methods & _MTLS_AUTH_METHODS:
            violations.append(
                "Server does not advertise an mTLS client authentication method "
                "(tls_client_auth or self_signed_tls_client_auth) in "
                "token_endpoint_auth_methods_supported"
            )
        if discovery.tls_client_certificate_bound_access_tokens is not True:
            violations.append(
                "Server does not advertise tls_client_certificate_bound_access_"
                "tokens: true; an mTLS client binds its tokens to its certificate"
            )
    return violations


# JARM (OAuth 2.0 JWT Secured Authorization Response Mode) §2.3.4: "jwt" picks
# the default mode for the response type.
JARM_RESPONSE_MODE = "jwt"

_MTLS_WITH_DPOP = (
    "An mTLS client's tokens are bound to its certificate; do not also pass a DPoP key"
)


class FAPIProfileError(ValueError):
    """A FAPI 2.0 client profile refused a configuration or request.

    ``violations`` lists every rule that was broken.
    """

    def __init__(self, violations: list[str]) -> None:
        super().__init__("; ".join(violations))
        self.violations = violations


def _raise_on(violations: list[str]) -> None:
    if violations:
        raise FAPIProfileError(violations)


@dataclass(frozen=True)
class FAPI2ClientProfile:
    """A fail-closed FAPI 2.0 Security Profile client.

    Construction raises :class:`FAPIProfileError` unless the discovery
    document passes :func:`validate_fapi_discovery`, the client authenticates
    with ``private_key_jwt`` (tokens DPoP-bound) or mTLS (tokens bound to the
    certificate), and the redirect URI is ``https`` (or an ``http`` loopback
    URI for a native app).  The issuer and endpoints come from the discovery
    document, never from the caller, and must be ``https`` URLs with a
    host.  A ``PrivateKeyJwt`` without ``issuer`` or ``audience`` gets the
    discovery issuer; one naming anything else is refused, so the assertion
    ``aud`` is never the endpoint URL (§5.3.3.1).

    The request builders fix the FAPI parameters (PAR,
    ``response_type=code``, PKCE ``S256``) and raise on anything that would
    weaken them, including a DPoP key whose algorithm the server does not
    advertise (RFC 9449 §5.1).  The profile is immutable.

    With ``request_object_key`` the pushed authorization request is a signed
    request object (FAPI 2.0 Message Signing §5.3.2): ``aud`` is the issuer,
    ``exp`` is at most 3600 s after ``nbf``, and the algorithm is one of
    PS256, ES256 or EdDSA and, when the server advertises
    ``request_object_signing_alg_values_supported``, one it lists.

    Args:
        discovery: The authorization server's discovery document.
        client_id: The registered client identifier.
        redirect_uri: The registered redirect URI.
        client_auth: ``PrivateKeyJwt`` or ``MtlsClientAuth``.
        native_app: Allow an ``http`` loopback redirect URI (RFC 8252 §7.3).
        jarm: Request JARM signed authorization responses
            (``response_mode=jwt``, FAPI 2.0 Message Signing §5.4); verify them
            with ``process_jarm_response(..., algorithms=signing_algorithms)``.
        scope: The scope the client requests.
        request_object_key: Sign the pushed authorization request as a JAR
            request object (RFC 9101) with this key.

    Attributes:
        issuer: The issuer from the discovery document.
        authorization_endpoint: Where the browser is sent with the request_uri.
        pushed_authorization_request_endpoint: The PAR endpoint (the mTLS
            alias for an mTLS client, RFC 8705 §5).
        token_endpoint: The token endpoint (the mTLS alias for an mTLS client).
        dpop_signing_algorithms: The §5.4.1 algorithms the server advertises
            in ``dpop_signing_alg_values_supported``; a request's DPoP key
            must use one of them.
        request_object_signing_algorithms: The server's
            ``request_object_signing_alg_values_supported``, or ``None`` when
            it does not advertise the field.
        private_key_jwt: ``client_auth`` with ``issuer`` set, for a
            ``private_key_jwt`` client.
        mtls: ``client_auth`` for an mTLS client.
    """

    discovery: InitVar[DiscoveryDocumentResponse]
    client_id: str
    redirect_uri: str
    client_auth: PrivateKeyJwt | MtlsClientAuth
    native_app: bool = False
    jarm: bool = False
    scope: str = "openid"
    request_object_key: RequestObjectKey | None = None
    issuer: str = field(init=False)
    authorization_endpoint: str = field(init=False)
    pushed_authorization_request_endpoint: str = field(init=False)
    token_endpoint: str = field(init=False)
    dpop_signing_algorithms: tuple[str, ...] = field(init=False)
    request_object_signing_algorithms: tuple[str, ...] | None = field(init=False)
    private_key_jwt: PrivateKeyJwt | None = field(init=False)
    mtls: MtlsClientAuth | None = field(init=False)

    def __post_init__(self, discovery: DiscoveryDocumentResponse) -> None:
        _raise_on(validate_fapi_discovery(discovery).violations)

        issuer = discovery.issuer or ""
        # Copies, so the caller's object cannot change the profile's settings.
        private_key_jwt: PrivateKeyJwt | None = None
        mtls: MtlsClientAuth | None = None
        if isinstance(self.client_auth, PrivateKeyJwt):
            auth = self.client_auth
            unset = auth.issuer is None and auth.audience is None
            private_key_jwt = replace(auth, issuer=issuer if unset else auth.issuer)
        elif isinstance(self.client_auth, MtlsClientAuth):
            mtls = replace(self.client_auth)
        else:
            raise FAPIProfileError(
                [
                    "client_auth must be PrivateKeyJwt or MtlsClientAuth "
                    "(FAPI 2.0 Security Profile §5.3.3.1)"
                ]
            )

        def endpoint(name: str) -> str:
            if mtls is not None:
                return resolve_mtls_endpoint(discovery, name) or ""
            return getattr(discovery, name) or ""

        advertised_request_object_algs = (
            discovery.request_object_signing_alg_values_supported
        )
        derived = {
            "issuer": issuer,
            "authorization_endpoint": discovery.authorization_endpoint or "",
            "pushed_authorization_request_endpoint": endpoint(
                "pushed_authorization_request_endpoint"
            ),
            "token_endpoint": endpoint("token_endpoint"),
            "dpop_signing_algorithms": tuple(
                sorted(
                    _str_values(discovery.dpop_signing_alg_values_supported)
                    & FAPI2_ALLOWED_SIGNING_ALGORITHMS
                )
            ),
            "request_object_signing_algorithms": (
                tuple(sorted(_str_values(advertised_request_object_algs)))
                if advertised_request_object_algs is not None
                else None
            ),
            "request_object_key": (
                replace(self.request_object_key) if self.request_object_key else None
            ),
            "private_key_jwt": private_key_jwt,
            "mtls": mtls,
        }
        for name, value in derived.items():
            object.__setattr__(self, name, value)

        violations: list[str] = []
        for name in (
            "issuer",
            "authorization_endpoint",
            "pushed_authorization_request_endpoint",
            "token_endpoint",
        ):
            url = derived[name]
            if not url:
                violations.append(f"{name} is required")
                continue
            parsed = urlparse(url)
            if parsed.scheme.lower() != "https":
                violations.append(f"{name} must use https, got {url!r}")
            elif not parsed.hostname:
                violations.append(f"{name} must have a host, got {url!r}")
        if not self.client_id:
            violations.append("client_id is required")
        violations.extend(
            _client_authentication_violations(
                private_key_jwt=private_key_jwt, mtls=mtls
            )
        )
        violations.extend(_assertion_audience_violations(private_key_jwt, issuer))
        violations.extend(
            _server_support_violations(
                discovery, private_key_jwt=private_key_jwt, mtls=mtls
            )
        )
        violations.extend(
            _redirect_uri_violations(self.redirect_uri, native_app=self.native_app)
        )
        violations.extend(
            _request_object_key_violations(
                derived["request_object_key"],
                derived["request_object_signing_algorithms"],
            )
        )
        _raise_on(violations)

    @property
    def signing_algorithms(self) -> list[str]:
        """Algorithms to accept for ID Tokens, JARM responses and DPoP (§5.4.1)."""
        return sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS)

    def _request_violations(self, dpop_key: DPoPKey | None) -> list[str]:
        """Re-check the settings a request carries (they are mutable objects)."""
        violations = _assertion_audience_violations(self.private_key_jwt, self.issuer)
        if dpop_key is None:
            return violations
        if self.mtls is not None:
            violations.append(_MTLS_WITH_DPOP)
        elif (
            # A non-FAPI algorithm is already reported by _client_violations.
            dpop_key.algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS
            and dpop_key.algorithm not in self.dpop_signing_algorithms
        ):
            violations.append(
                f"Server does not advertise DPoP algorithm '{dpop_key.algorithm}' "
                "in dpop_signing_alg_values_supported (RFC 9449 §5.1)"
            )
        return violations

    def _client_auth_copies(
        self,
    ) -> tuple[PrivateKeyJwt | None, MtlsClientAuth | None]:
        """Fresh copies for a request, so changing it cannot reach the profile."""
        return (
            replace(self.private_key_jwt) if self.private_key_jwt else None,
            replace(self.mtls) if self.mtls else None,
        )

    def id_token_validation_config(self) -> TokenValidationConfig:
        """ID Token validation settings for this profile.

        Signature algorithms are limited to PS256, ES256 and EdDSA (§5.4.1);
        ``iss``, ``aud``, ``exp``, ``iat`` and ``sub`` are required and the
        issuer and audience are pinned.  Pass it to ``validate_id_token`` with
        the discovery address.
        """
        return TokenValidationConfig(
            perform_disco=True,
            audience=self.client_id,
            issuer=self.issuer,
            algorithms=self.signing_algorithms,
            options={
                "verify_exp": True,
                "require": ["iss", "aud", "exp", "iat", "sub"],
            },
        )

    def pushed_authorization_request(
        self,
        *,
        state: str,
        code_challenge: str,
        nonce: str | None = None,
        dpop_key: DPoPKey | None = None,
    ) -> PushedAuthorizationRequest:
        """Build the pushed authorization request (§5.3.3.2).

        ``response_type`` is ``code`` and the PKCE method ``S256``; a JARM
        profile asks for ``response_mode=jwt``.  A ``private_key_jwt`` client
        must pass the flow's ``dpop_key``.  With ``request_object_key`` the
        parameters are sent as a signed request object (RFC 9126 §3, FAPI 2.0
        Message Signing §5.3.2).

        Raises:
            FAPIProfileError: The request would not be FAPI 2.0 compliant.
        """
        private_key_jwt, mtls = self._client_auth_copies()
        request = PushedAuthorizationRequest(
            address=self.pushed_authorization_request_endpoint,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scope,
            response_type=FAPI2_REQUIRED_RESPONSE_TYPE,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=FAPI2_REQUIRED_PKCE_METHOD,
            private_key_jwt=private_key_jwt,
            dpop_key=dpop_key,
            mtls=mtls,
            response_mode=JARM_RESPONSE_MODE if self.jarm else None,
        )
        _raise_on(
            [
                *validate_fapi_authorization_request(
                    request, native_app=self.native_app
                ).violations,
                *self._request_violations(dpop_key),
                *_request_object_key_violations(
                    self.request_object_key, self.request_object_signing_algorithms
                ),
            ]
        )
        if self.request_object_key is None:
            return request
        return self._signed(request, replace(self.request_object_key))

    def _signed(
        self, request: PushedAuthorizationRequest, key: RequestObjectKey
    ) -> PushedAuthorizationRequest:
        """The request with its parameters moved into a request object."""
        extra_claims = (
            {"response_mode": request.response_mode} if request.response_mode else {}
        )
        request_object = create_request_object(
            private_key=key.private_key,
            algorithm=key.algorithm,
            client_id=self.client_id,
            # Message Signing §5.3.2: aud is the issuer.
            audience=self.issuer,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            response_type=request.response_type,
            state=request.state,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            lifetime=key.lifetime,
            kid=key.kid,
            **extra_claims,
        )
        return PushedAuthorizationRequest(
            address=request.address,
            client_id=self.client_id,
            private_key_jwt=request.private_key_jwt,
            dpop_key=request.dpop_key,
            mtls=request.mtls,
            request=request_object,
        )

    def authorization_url(self, request_uri: str) -> str:
        """The authorization endpoint URL for a pushed request (§5.3.3.2).

        Carries only ``client_id`` and ``request_uri`` (RFC 9126 §4); see
        :func:`~py_identity_model.core.authorize_url.build_par_authorization_url`.
        """
        if not request_uri:
            raise FAPIProfileError(["request_uri is required"])
        return build_par_authorization_url(
            self.authorization_endpoint, self.client_id, request_uri
        )

    def validate_callback_issuer(
        self, response: AuthorizeCallbackResponse
    ) -> StateValidationResult:
        """Check the RFC 9207 ``iss`` authorization response parameter.

        ``iss`` is required and must equal the issuer (§5.3.3.2).
        """
        return validate_authorize_callback_issuer(response, self.issuer, require=True)

    def authorization_code_token_request(
        self,
        *,
        code: str,
        code_verifier: str,
        dpop_key: DPoPKey | None = None,
    ) -> AuthorizationCodeTokenRequest:
        """Build the authorization code token request.

        A ``private_key_jwt`` client must pass the flow's ``dpop_key``.

        Raises:
            FAPIProfileError: The request would not be FAPI 2.0 compliant.
        """
        private_key_jwt, mtls = self._client_auth_copies()
        violations = [
            *_client_violations(
                private_key_jwt=private_key_jwt, mtls=mtls, dpop_key=dpop_key
            ),
            *self._request_violations(dpop_key),
        ]
        if not code_verifier:
            violations.append("PKCE code_verifier is required")
        _raise_on(violations)
        return AuthorizationCodeTokenRequest(
            address=self.token_endpoint,
            client_id=self.client_id,
            code=code,
            redirect_uri=self.redirect_uri,
            code_verifier=code_verifier,
            private_key_jwt=private_key_jwt,
            dpop_key=dpop_key,
            mtls=mtls,
        )


__all__ = [
    "FAPI2_ALLOWED_AUTH_METHODS",
    "FAPI2_ALLOWED_SIGNING_ALGORITHMS",
    "FAPI2_MAX_NONCE_LENGTH",
    "FAPI2_MAX_REQUEST_OBJECT_LIFETIME",
    "FAPI2_REQUIRED_PKCE_METHOD",
    "FAPI2_REQUIRED_RESPONSE_TYPE",
    "FAPI2ClientProfile",
    "FAPIProfileError",
    "FAPIValidationResult",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
]
