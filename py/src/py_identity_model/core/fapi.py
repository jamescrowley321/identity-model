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
import enum
from ipaddress import ip_address
import math
from typing import TYPE_CHECKING, TypeGuard
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ed448
import jwt as pyjwt

from ..exceptions import WeakSigningKeyError
from .authorize_url import build_par_authorization_url
from .client_auth_method import ClientAuthMethod
from .jar import create_request_object
from .key_strength import enforce_signing_key_strength, load_signing_key
from .models import (
    AuthorizationCodeTokenRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    RequestObjectKey,
    SignedPushedAuthorizationRequest,
    TokenValidationConfig,
)
from .mtls import resolve_mtls_endpoint
from .state_validation import validate_authorize_callback_issuer


if TYPE_CHECKING:
    from collections.abc import Mapping

    from .authorize_response import AuthorizeCallbackResponse
    from .dpop import DPoPKey
    from .models import DiscoveryDocumentResponse
    from .state_validation import StateValidationResult


# FAPI 2.0 Security Profile §5.4.1: PS256, ES256 or EdDSA (Ed25519).
FAPI2_ALLOWED_SIGNING_ALGORITHMS = frozenset({"PS256", "ES256", "EdDSA"})
# FAPI 2.0 Security Profile §5.3.3.1. String values, because discovery
# metadata (``token_endpoint_auth_methods_supported``) is compared against them.
FAPI2_ALLOWED_AUTH_METHODS = frozenset(
    m.value
    for m in (
        ClientAuthMethod.PRIVATE_KEY_JWT,
        ClientAuthMethod.TLS_CLIENT_AUTH,
        ClientAuthMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
    )
)
_MTLS_AUTH_METHODS = frozenset(m.value for m in ClientAuthMethod if m.is_mtls)
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


class FAPIViolationCode(enum.Enum):
    """Which FAPI 2.0 rule a :class:`FAPIViolation` breaks.

    Match on the code; the violation's ``message`` is for people and may
    change between releases.
    """

    # The client's request or configuration.
    RESPONSE_TYPE_NOT_CODE = "response_type_not_code"
    """``response_type`` is not ``code`` (Security Profile §5.3.3.2)."""
    PKCE_CHALLENGE_MISSING = "pkce_challenge_missing"
    """No PKCE ``code_challenge`` (§5.3.3.2)."""
    PKCE_METHOD_NOT_S256 = "pkce_method_not_s256"
    """The PKCE method is absent or not ``S256`` (§5.3.3.2)."""
    PKCE_VERIFIER_MISSING = "pkce_verifier_missing"
    """The token request has no PKCE ``code_verifier``."""
    NONCE_TOO_LONG = "nonce_too_long"
    """``nonce`` is longer than 64 characters (§5.3.3.2)."""
    NONCE_INVALID = "nonce_invalid"
    """A request object's ``nonce`` claim is not a string."""
    REDIRECT_URI_INVALID = "redirect_uri_invalid"
    """The redirect URI is not a string or has no host."""
    REDIRECT_URI_NOT_HTTPS = "redirect_uri_not_https"
    """The redirect URI is not ``https`` and not a native app's loopback
    ``http`` URI (§5.3.2.2, RFC 8252 §7.3)."""
    CLIENT_ID_MISSING = "client_id_missing"
    """No ``client_id``."""
    CLIENT_AUTH_MISSING = "client_auth_missing"
    """No ``private_key_jwt`` or mTLS client authentication (§5.3.3.1)."""
    CLIENT_AUTH_TYPE_INVALID = "client_auth_type_invalid"
    """A profile's ``client_auth`` is not ``PrivateKeyJwt`` or ``MtlsClientAuth``."""
    CLIENT_AUTH_METHOD_NOT_ALLOWED = "client_auth_method_not_allowed"
    """An explicit ``client_auth_method`` FAPI 2.0 does not allow (§5.3.3.1)."""
    ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
    """A ``private_key_jwt``, DPoP or request object algorithm other than
    PS256, ES256 or EdDSA (§5.4.1)."""
    KEY_NOT_ALLOWED = "key_not_allowed"
    """A ``private_key_jwt`` or request object signing key §5.4.1 does not
    allow: an RSA key under 2048 bits or an EdDSA key that is not Ed25519."""
    SENDER_CONSTRAINT_MISSING = "sender_constraint_missing"
    """Neither a DPoP key nor mTLS sender-constrains the tokens (§5.3.3.1)."""
    MTLS_WITH_DPOP = "mtls_with_dpop"
    """An mTLS client also passed a DPoP key."""
    ASSERTION_AUDIENCE_NOT_ISSUER = "assertion_audience_not_issuer"
    """The ``private_key_jwt`` assertion ``aud`` would not be the issuer
    (§5.3.3.1)."""
    REQUEST_OBJECT_LIFETIME_INVALID = "request_object_lifetime_invalid"
    """The request object lifetime is not 1 to 3600 seconds, or it lacks a
    numeric ``exp`` or ``nbf`` (Message Signing §5.3.2)."""
    REQUEST_OBJECT_INVALID = "request_object_invalid"
    """A signed PAR's request object is not a JWT (RFC 9101 §2.1)."""
    REQUEST_OBJECT_ENCRYPTED = "request_object_encrypted"
    """A signed PAR's request object is encrypted, so its claims cannot be
    checked (RFC 9101 §6.1)."""
    REQUEST_OBJECT_CLIENT_ID_MISMATCH = "request_object_client_id_mismatch"
    """The request object's ``client_id`` is not the request's (RFC 9101 §5)."""
    REQUEST_OBJECT_ISSUER_MISMATCH = "request_object_issuer_mismatch"
    """The request object's ``iss`` is not the ``client_id`` (RFC 9101 §4)."""
    REQUEST_URI_MISSING = "request_uri_missing"
    """No ``request_uri`` for the authorization URL."""
    REFRESH_TOKEN_MISSING = "refresh_token_missing"
    """No refresh token for the refresh request."""
    ENDPOINT_MISSING = "endpoint_missing"
    """Discovery gives no issuer or endpoint the profile needs."""
    ENDPOINT_INVALID = "endpoint_invalid"
    """An issuer or endpoint URL is not ``https`` or has no host."""

    # What the authorization server advertises.
    DISCOVERY_FAILED = "discovery_failed"
    """The discovery document could not be fetched."""
    REQUIRED_METADATA_MISSING = "required_metadata_missing"
    """Discovery omits a field OIDC Discovery 1.0 §3 marks REQUIRED."""
    SERVER_GRANT_TYPE_UNSUPPORTED = "server_grant_type_unsupported"
    """The server does not offer the ``authorization_code`` grant."""
    SERVER_RESPONSE_TYPE_UNSUPPORTED = "server_response_type_unsupported"
    """The server does not offer the ``code`` response type."""
    SERVER_CLIENT_AUTH_UNSUPPORTED = "server_client_auth_unsupported"
    """The server does not offer a FAPI client authentication method, or the
    client's own one."""
    SERVER_AUTH_SIGNING_ALG_UNSUPPORTED = "server_auth_signing_alg_unsupported"
    """The server does not offer a FAPI ``private_key_jwt`` algorithm, or the
    client's own one."""
    SERVER_ID_TOKEN_ALG_UNSUPPORTED = "server_id_token_alg_unsupported"
    """The server does not sign ID Tokens with a FAPI algorithm."""
    SERVER_PKCE_UNSUPPORTED = "server_pkce_unsupported"
    """The server does not offer PKCE ``S256`` (§5.3.2.2)."""
    SERVER_PAR_UNSUPPORTED = "server_par_unsupported"
    """The server does not advertise a PAR endpoint, or advertises one that
    is not a URL string (§5.3.2.2, RFC 9126 §5)."""
    SERVER_ISS_PARAMETER_UNSUPPORTED = "server_iss_parameter_unsupported"
    """The server does not return ``iss`` in authorization responses
    (§5.3.2.2, RFC 9207)."""
    SERVER_SENDER_CONSTRAINT_UNSUPPORTED = "server_sender_constraint_unsupported"
    """The server offers neither DPoP nor mTLS-bound tokens (§5.3.2.1), or not
    the binding the client uses."""
    SERVER_DPOP_ALG_UNSUPPORTED = "server_dpop_alg_unsupported"
    """The server does not advertise the DPoP key's algorithm (RFC 9449 §5.1)."""
    SERVER_REQUEST_OBJECT_ALG_UNSUPPORTED = "server_request_object_alg_unsupported"
    """The server does not advertise the request object's algorithm."""


@dataclass(frozen=True)
class FAPIViolation:
    """One broken FAPI 2.0 rule: a typed ``code`` and a readable ``message``."""

    code: FAPIViolationCode
    message: str

    def __str__(self) -> str:
        return self.message


def _required_metadata_missing(name: str) -> FAPIViolation:
    """Violation for an absent REQUIRED OIDC Discovery 1.0 §3 field."""
    return FAPIViolation(
        FAPIViolationCode.REQUIRED_METADATA_MISSING,
        f"{name} not advertised; "
        "OpenID Connect Discovery 1.0 §3 marks it REQUIRED, with no default",
    )


@dataclass
class FAPIValidationResult:
    """Result of a FAPI 2.0 compliance check.

    ``is_compliant`` is derived from ``violations`` — it is ``True`` when
    ``violations`` is empty.  It cannot be set directly.
    """

    violations: list[FAPIViolation] = field(default_factory=list)
    is_compliant: bool = field(init=False)

    def __post_init__(self) -> None:
        self.is_compliant = len(self.violations) == 0

    @property
    def codes(self) -> list[FAPIViolationCode]:
        """The violations' codes, in order."""
        return [v.code for v in self.violations]


def _redirect_uri_violations(
    redirect_uri: object, *, native_app: bool
) -> list[FAPIViolation]:
    """``https`` redirect URIs; ``http`` only for a native app's loopback.

    FAPI 2.0 Security Profile §5.3.2.2(8) forbids ``http`` redirect URIs
    except for native clients using loopback interface redirection
    (RFC 8252 §7.3).
    """
    if not isinstance(redirect_uri, str):
        return [
            FAPIViolation(
                FAPIViolationCode.REDIRECT_URI_INVALID, "redirect_uri must be a string"
            )
        ]
    parsed = urlparse(redirect_uri.strip())
    scheme = parsed.scheme.lower()
    if not parsed.hostname:
        return [
            FAPIViolation(
                FAPIViolationCode.REDIRECT_URI_INVALID,
                f"redirect_uri must have a host, got '{redirect_uri}'",
            )
        ]
    if scheme == "https":
        return []
    if scheme == "http" and native_app and _is_loopback(parsed.hostname):
        return []
    return [
        FAPIViolation(
            FAPIViolationCode.REDIRECT_URI_NOT_HTTPS,
            f"redirect_uri must use HTTPS, got '{redirect_uri}'; http is allowed "
            "only for a native app's loopback redirect (FAPI 2.0 Security Profile "
            "§5.3.2.2, RFC 8252 §7.3)",
        )
    ]


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _algorithm_violation(what: str, algorithm: str) -> list[FAPIViolation]:
    if algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS:
        return []
    return [
        FAPIViolation(
            FAPIViolationCode.ALGORITHM_NOT_ALLOWED,
            f"{what} algorithm '{algorithm}' not allowed; use {_fapi_algorithms()} "
            "(FAPI 2.0 Security Profile §5.4.1)",
        )
    ]


def _signing_key_violations(
    what: str, private_key: str | bytes, algorithm: str
) -> list[FAPIViolation]:
    """§5.4.1: RSA of 2048 bits or more, EdDSA on Ed25519 (Ed448 refused).

    ES256 is bound to P-256, so the EC floor of 224 bits always holds. A key
    PyJWT can't prepare for *algorithm* is left to signing to reject.
    """
    if algorithm not in FAPI2_ALLOWED_SIGNING_ALGORITHMS:
        # Already reported as ALGORITHM_NOT_ALLOWED.
        return []
    try:
        enforce_signing_key_strength(private_key, algorithm)
    except WeakSigningKeyError as exc:
        return [
            FAPIViolation(
                FAPIViolationCode.KEY_NOT_ALLOWED,
                f"{what} {exc.kty} key is {exc.bits} bits; at least "
                f"{exc.min_bits} required (FAPI 2.0 Security Profile §5.4.1)",
            )
        ]
    key = load_signing_key(private_key, algorithm)
    if isinstance(key, ed448.Ed448PrivateKey | ed448.Ed448PublicKey):
        return [
            FAPIViolation(
                FAPIViolationCode.KEY_NOT_ALLOWED,
                f"{what} EdDSA key must be Ed25519 (FAPI 2.0 Security Profile §5.4.1)",
            )
        ]
    return []


def validate_fapi_authorization_request(
    request: PushedAuthorizationRequest | SignedPushedAuthorizationRequest,
    *,
    native_app: bool = False,
) -> FAPIValidationResult:
    """Validate a pushed authorization request against FAPI 2.0.

    Checks FAPI 2.0 Security Profile §5.3.3.2: ``response_type=code``, PKCE
    with ``S256``, a ``nonce`` of at most 64 characters, and the redirect URI
    rules of §5.3.2.2.  For a
    :class:`~py_identity_model.core.models.SignedPushedAuthorizationRequest`
    these are read from the request object's claims, and its header ``alg``
    (§5.4.1), ``exp - nbf`` of at most 3600 s (FAPI 2.0 Message Signing
    §5.3.2), and ``client_id`` and ``iss`` matching the request's
    ``client_id`` (RFC 9101 §4, §5) are checked too.  The request object's
    signature and ``aud`` are not checked; the ``aud`` = issuer check needs
    the issuer.  An encrypted (JWE) request object is reported as a
    violation, because its claims cannot be read.  The request's
    client authentication and DPoP key are checked as in
    :func:`validate_fapi_client_config`, without the assertion-audience check
    (that needs the issuer).  Like that function it checks the specification
    and is wider than :class:`FAPI2ClientProfile`.

    Args:
        request: The pushed authorization request (RFC 9126) to send.
        native_app: Allow an ``http`` loopback redirect URI (RFC 8252 §7.3).

    Returns:
        FAPIValidationResult with compliance status and any violations.
    """
    if isinstance(request, SignedPushedAuthorizationRequest):
        violations = _request_object_violations(
            request.request, request.client_id, native_app=native_app
        )
    else:
        violations = _authorization_parameter_violations(
            {name: getattr(request, name) for name in _AUTHORIZATION_PARAMETERS},
            native_app=native_app,
        )
    violations.extend(
        _client_violations(
            private_key_jwt=request.private_key_jwt,
            mtls=request.mtls,
            dpop_key=request.dpop_key,
            client_auth_method=request.client_auth_method,
        )
    )

    return FAPIValidationResult(violations=violations)


# Larger lifetimes are not printed: a huge int can exceed Python's
# int-to-str digit limit and raise while formatting the message.
_MAX_REPORTED_LIFETIME = 10**15

# A compact JWE has five dot-separated parts (RFC 7516 §7.1).
_JWE_COMPACT_DOTS = 4

# The §5.3.3.2 parameters: PAR form fields, or claims of a request object.
_AUTHORIZATION_PARAMETERS = (
    "response_type",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "redirect_uri",
)


def _authorization_parameter_violations(
    params: Mapping[str, object], *, native_app: bool
) -> list[FAPIViolation]:
    """§5.3.3.2 authorization parameters, as form fields or JWT claims."""
    violations: list[FAPIViolation] = []
    response_type = params.get("response_type")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")
    nonce = params.get("nonce")
    redirect_uri = params.get("redirect_uri")

    if response_type != FAPI2_REQUIRED_RESPONSE_TYPE:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.RESPONSE_TYPE_NOT_CODE,
                f"response_type must be 'code', got '{response_type}'",
            )
        )

    if not isinstance(code_challenge, str) or not code_challenge.strip():
        violations.append(
            FAPIViolation(
                FAPIViolationCode.PKCE_CHALLENGE_MISSING,
                "PKCE code_challenge is required",
            )
        )

    if code_challenge_method is None:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.PKCE_METHOD_NOT_S256,
                "PKCE code_challenge_method is required",
            )
        )
    elif code_challenge_method != FAPI2_REQUIRED_PKCE_METHOD:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.PKCE_METHOD_NOT_S256,
                f"PKCE method must be 'S256', got '{code_challenge_method}'",
            )
        )

    if nonce is not None and not isinstance(nonce, str):
        violations.append(
            FAPIViolation(FAPIViolationCode.NONCE_INVALID, "nonce must be a string")
        )
    elif isinstance(nonce, str) and len(nonce) > FAPI2_MAX_NONCE_LENGTH:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.NONCE_TOO_LONG,
                f"nonce is {len(nonce)} characters; FAPI 2.0 Security "
                f"Profile §5.3.3.2 limits it to {FAPI2_MAX_NONCE_LENGTH}",
            )
        )

    violations.extend(_redirect_uri_violations(redirect_uri, native_app=native_app))
    return violations


_REQUEST_OBJECT_NOT_JWT = FAPIViolation(
    FAPIViolationCode.REQUEST_OBJECT_INVALID,
    "request object is not a JWT (RFC 9101 §2.1)",
)


def _request_object_violations(
    request_object: str, client_id: str, *, native_app: bool
) -> list[FAPIViolation]:
    """A signed PAR's request object: header alg, lifetime and parameters."""
    if not isinstance(request_object, str):
        # The field can be reassigned after construction.
        return [_REQUEST_OBJECT_NOT_JWT]
    if request_object.count(".") == _JWE_COMPACT_DOTS:
        # A compact JWE (RFC 9101 §6.1): its claims cannot be read here.
        return [
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_ENCRYPTED,
                "request object is encrypted; only signed request objects can be "
                "checked",
            )
        ]
    try:
        header = pyjwt.get_unverified_header(request_object)
        claims = pyjwt.decode(request_object, options={"verify_signature": False})
    except pyjwt.PyJWTError:
        return [_REQUEST_OBJECT_NOT_JWT]

    violations: list[FAPIViolation] = []
    # RFC 9101 §5: client_id must match the form; a signed object's iss is it too.
    if claims.get("client_id") != client_id:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_CLIENT_ID_MISMATCH,
                f"request object client_id {claims.get('client_id')!r} does not "
                f"match the request's {client_id!r} (RFC 9101 §5)",
            )
        )
    if "iss" in claims and claims["iss"] != client_id:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_ISSUER_MISMATCH,
                f"request object iss {claims['iss']!r} is not the client_id "
                f"{client_id!r} (RFC 9101 §4)",
            )
        )

    algorithm = header.get("alg")
    violations.extend(
        _algorithm_violation(
            "request object",
            algorithm if isinstance(algorithm, str) else repr(algorithm),
        )
    )
    lifetime = _lifetime(claims.get("exp"), claims.get("nbf"))
    if lifetime is None:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_LIFETIME_INVALID,
                "request object must carry numeric exp and nbf "
                "(FAPI 2.0 Message Signing §5.3.2)",
            )
        )
    elif not 0 < lifetime <= FAPI2_MAX_REQUEST_OBJECT_LIFETIME:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_LIFETIME_INVALID,
                f"request object exp - nbf must be 1 to "
                f"{FAPI2_MAX_REQUEST_OBJECT_LIFETIME} seconds, got "
                f"{lifetime if abs(lifetime) < _MAX_REPORTED_LIFETIME else 'a value out of range'} "
                "(FAPI 2.0 Message Signing §5.3.2)",
            )
        )
    violations.extend(
        _authorization_parameter_violations(claims, native_app=native_app)
    )
    return violations


def _lifetime(exp: object, nbf: object) -> int | float | None:
    """``exp - nbf``, or ``None`` when either is not a usable number."""
    if not _is_number(exp) or not _is_number(nbf):
        return None
    try:
        lifetime = exp - nbf
        # A huge int lifetime is finite but cannot be converted to float.
        return (
            lifetime if isinstance(lifetime, int) or math.isfinite(lifetime) else None
        )
    except OverflowError:
        return None


def _is_number(value: object) -> TypeGuard[int | float]:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _client_violations(
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
    dpop_key: DPoPKey | None,
    client_auth_method: ClientAuthMethod | None = None,
) -> list[FAPIViolation]:
    """Client authentication and sender constraint (§5.3.3.1, §5.4.1)."""
    return [
        *_client_authentication_violations(
            private_key_jwt=private_key_jwt,
            mtls=mtls,
            client_auth_method=client_auth_method,
        ),
        *_sender_constraint_request_violations(dpop_key=dpop_key, mtls=mtls),
    ]


def _client_authentication_violations(
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
    client_auth_method: ClientAuthMethod | None = None,
) -> list[FAPIViolation]:
    violations: list[FAPIViolation] = []
    # An explicit method is what gets sent, whatever credentials are present.
    if (
        client_auth_method is not None
        and client_auth_method.value not in FAPI2_ALLOWED_AUTH_METHODS
    ):
        violations.append(
            FAPIViolation(
                FAPIViolationCode.CLIENT_AUTH_METHOD_NOT_ALLOWED,
                f"client_auth_method '{client_auth_method.value}' is not FAPI 2.0 "
                f"compliant; use {', '.join(sorted(FAPI2_ALLOWED_AUTH_METHODS))} "
                "(FAPI 2.0 Security Profile §5.3.3.1)",
            )
        )
    if private_key_jwt is None and mtls is None:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.CLIENT_AUTH_MISSING,
                "Client authentication is required: private_key_jwt or mTLS "
                "(FAPI 2.0 Security Profile §5.3.3.1)",
            )
        )
    if private_key_jwt is not None:
        violations.extend(
            _algorithm_violation("private_key_jwt", private_key_jwt.algorithm)
        )
        violations.extend(
            _signing_key_violations(
                "private_key_jwt",
                private_key_jwt.private_key,
                private_key_jwt.algorithm,
            )
        )
    return violations


def _sender_constraint_request_violations(
    *,
    dpop_key: DPoPKey | None,
    mtls: MtlsClientAuth | None,
) -> list[FAPIViolation]:
    if dpop_key is not None:
        return _algorithm_violation("DPoP", dpop_key.algorithm)
    if mtls is None:
        return [
            FAPIViolation(
                FAPIViolationCode.SENDER_CONSTRAINT_MISSING,
                "Sender-constrained tokens required: a DPoP key or mTLS "
                "(FAPI 2.0 Security Profile §5.3.3.1)",
            )
        ]
    return []


def _assertion_audience_violations(
    private_key_jwt: PrivateKeyJwt | None, issuer: str
) -> list[FAPIViolation]:
    """§5.3.3.1: the assertion ``aud`` is the issuer, never the endpoint URL."""
    if private_key_jwt is None:
        return []
    aud = private_key_jwt.audience or private_key_jwt.issuer
    if aud == issuer:
        return []
    return [
        FAPIViolation(
            FAPIViolationCode.ASSERTION_AUDIENCE_NOT_ISSUER,
            f"private_key_jwt assertion aud would be {aud!r}, not the issuer "
            f"{issuer!r} (FAPI 2.0 Security Profile §5.3.3.1)",
        )
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
    algorithms and the ``private_key_jwt`` key are limited by §5.4.1: RSA
    keys of at least 2048 bits and Ed25519 for EdDSA.

    This checks the specification, so it is wider than
    :class:`FAPI2ClientProfile`.  It accepts two combinations §5.3.3.1
    allows and the profile refuses: ``private_key_jwt`` with mTLS-bound
    tokens, and mTLS client authentication with a DPoP key.  It does not see
    the discovery document or the redirect URI, so it also skips the
    profile's checks that the server supports the chosen methods, that the
    issuer and endpoints are ``https`` URLs, and that the redirect URI is
    allowed.  Build a :class:`FAPI2ClientProfile` to get every check.

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


def _flow_violations(discovery: DiscoveryDocumentResponse) -> list[FAPIViolation]:
    """Grant and response type: the authorization code flow."""
    violations: list[FAPIViolation] = []

    # Check supported grant types include authorization_code.
    # OPTIONAL; OIDC Discovery 1.0 §3 and RFC 8414 §2 default when omitted is
    # ["authorization_code", "implicit"] — compliant.
    grants = discovery.grant_types_supported
    if grants is not None and "authorization_code" not in _str_values(grants):
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_GRANT_TYPE_UNSUPPORTED,
                "Server does not support authorization_code grant type",
            )
        )

    # Check response_types_supported includes "code" (authorization code flow).
    # REQUIRED by OIDC Discovery 1.0 §3, no default.  (The ["code"] default
    # belongs to Registration §2 client metadata, not provider metadata.)
    response_types = discovery.response_types_supported
    if response_types is None:
        violations.append(_required_metadata_missing("response_types_supported"))
    elif FAPI2_REQUIRED_RESPONSE_TYPE not in _str_values(response_types):
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_RESPONSE_TYPE_UNSUPPORTED,
                "Server does not support 'code' response type "
                "(authorization code flow required)",
            )
        )

    return violations


def _client_auth_violations(
    discovery: DiscoveryDocumentResponse,
) -> list[FAPIViolation]:
    """Client authentication methods and their JWT algorithms."""
    violations: list[FAPIViolation] = []

    # Check token endpoint auth methods for strong client auth.
    # RFC 8414 §2 default when omitted is ["client_secret_basic"] — FAPI-prohibited.
    auth_methods = discovery.token_endpoint_auth_methods_supported
    if auth_methods is None:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_CLIENT_AUTH_UNSUPPORTED,
                "token_endpoint_auth_methods_supported not advertised; "
                "RFC 8414 default is client_secret_basic, which FAPI 2.0 prohibits",
            )
        )
    else:
        supported = _str_values(auth_methods) & FAPI2_ALLOWED_AUTH_METHODS
        if not supported:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_CLIENT_AUTH_UNSUPPORTED,
                    "Server does not support FAPI-compliant client auth "
                    "(private_key_jwt or tls_client_auth)",
                )
            )

    # The private_key_jwt assertion is a JWT, so FAPI 2.0 Security Profile
    # §5.4.1 applies to its algorithm.  RFC 8414 §2 scopes this field to JWT
    # client authentication, so it only matters when private_key_jwt is offered.
    if "private_key_jwt" in _str_values(auth_methods):
        auth_algs = discovery.token_endpoint_auth_signing_alg_values_supported
        if auth_algs is None:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_AUTH_SIGNING_ALG_UNSUPPORTED,
                    "token_endpoint_auth_signing_alg_values_supported not "
                    f"advertised; private_key_jwt needs one of {_fapi_algorithms()} "
                    "(FAPI 2.0 Security Profile §5.4.1)",
                )
            )
        elif not _str_values(auth_algs) & FAPI2_ALLOWED_SIGNING_ALGORITHMS:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_AUTH_SIGNING_ALG_UNSUPPORTED,
                    "Server does not support FAPI-compliant token endpoint auth "
                    f"signing algorithms ({_fapi_algorithms()})",
                )
            )

    return violations


def _id_token_alg_violations(
    discovery: DiscoveryDocumentResponse,
) -> list[FAPIViolation]:
    """ID Token signing algorithms."""
    violations: list[FAPIViolation] = []

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
            FAPIViolation(
                FAPIViolationCode.SERVER_ID_TOKEN_ALG_UNSUPPORTED,
                "Server does not support FAPI-compliant signing algorithms "
                f"({_fapi_algorithms()})",
            )
        )

    return violations


def _authorization_endpoint_violations(
    discovery: DiscoveryDocumentResponse,
) -> list[FAPIViolation]:
    """PKCE, PAR and the RFC 9207 ``iss`` parameter."""
    violations: list[FAPIViolation] = []

    # Check PKCE support — FAPI 2.0 Security Profile §5.3.2.2(5) requires S256.
    # RFC 8414 §2: when omitted, the server does not support PKCE.
    pkce_methods = discovery.code_challenge_methods_supported
    if pkce_methods is None:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_PKCE_UNSUPPORTED,
                "code_challenge_methods_supported not advertised; RFC 8414 §2 "
                "reads that as no PKCE support, and FAPI 2.0 Security Profile "
                "§5.3.2.2 requires S256",
            )
        )
    elif FAPI2_REQUIRED_PKCE_METHOD not in _str_values(pkce_methods):
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_PKCE_UNSUPPORTED,
                "Server does not support S256 PKCE (FAPI 2.0 requires "
                "code_challenge_methods_supported to include S256)",
            )
        )

    # FAPI 2.0 Security Profile §5.3.2.2(2): PAR (RFC 9126) is required.
    # RFC 9126 §5: the endpoint is a URL, so only a non-empty string counts.
    par_endpoint = discovery.pushed_authorization_request_endpoint
    if par_endpoint is None or par_endpoint == "":
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_PAR_UNSUPPORTED,
                "pushed_authorization_request_endpoint not advertised; FAPI 2.0 "
                "Security Profile §5.3.2.2 requires pushed authorization requests "
                "(RFC 9126)",
            )
        )
    elif not isinstance(par_endpoint, str) or not par_endpoint.strip():
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_PAR_UNSUPPORTED,
                "pushed_authorization_request_endpoint must be a URL string, got "
                f"{par_endpoint!r} (RFC 9126 §5)",
            )
        )

    # FAPI 2.0 Security Profile §5.3.2.2(7): the server returns iss in the
    # authorization response.  RFC 9207 §3: absent means false.
    if discovery.authorization_response_iss_parameter_supported is not True:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_ISS_PARAMETER_UNSUPPORTED,
                "authorization_response_iss_parameter_supported is not true; FAPI "
                "2.0 Security Profile §5.3.2.2 requires the iss authorization "
                "response parameter (RFC 9207 §3)",
            )
        )

    return violations


def _sender_constraint_violations(
    discovery: DiscoveryDocumentResponse,
) -> list[FAPIViolation]:
    """Sender-constrained access tokens."""
    violations: list[FAPIViolation] = []

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
            FAPIViolation(
                FAPIViolationCode.SERVER_SENDER_CONSTRAINT_UNSUPPORTED,
                "Neither dpop_signing_alg_values_supported with one of "
                f"{_fapi_algorithms()} nor tls_client_certificate_bound_access_"
                "tokens: true is advertised; FAPI 2.0 Security Profile §5.3.2.1 "
                "requires sender-constrained access tokens (DPoP or MTLS)",
            )
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
            violations=[
                FAPIViolation(
                    FAPIViolationCode.DISCOVERY_FAILED,
                    "Discovery document fetch failed",
                )
            ],
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
) -> list[FAPIViolation]:
    """FAPI algorithm and key (§5.4.1), lifetime of at most 3600 s (MS §5.3.2)."""
    if key is None:
        return []
    violations = [
        *_algorithm_violation("request object", key.algorithm),
        *_signing_key_violations("request object", key.private_key, key.algorithm),
    ]
    if not 0 < key.lifetime <= FAPI2_MAX_REQUEST_OBJECT_LIFETIME:
        violations.append(
            FAPIViolation(
                FAPIViolationCode.REQUEST_OBJECT_LIFETIME_INVALID,
                f"request object lifetime must be 1 to "
                f"{FAPI2_MAX_REQUEST_OBJECT_LIFETIME} seconds, got {key.lifetime} "
                "(FAPI 2.0 Message Signing §5.3.2)",
            )
        )
    if (
        # A non-FAPI algorithm is already reported above.
        advertised is not None
        and key.algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS
        and key.algorithm not in advertised
    ):
        violations.append(
            FAPIViolation(
                FAPIViolationCode.SERVER_REQUEST_OBJECT_ALG_UNSUPPORTED,
                f"Server does not advertise request object algorithm "
                f"'{key.algorithm}' in request_object_signing_alg_values_supported",
            )
        )
    return violations


def _server_support_violations(
    discovery: DiscoveryDocumentResponse,
    *,
    private_key_jwt: PrivateKeyJwt | None,
    mtls: MtlsClientAuth | None,
) -> list[FAPIViolation]:
    """The server must support the client's chosen auth and token binding.

    :func:`validate_fapi_discovery` only checks that *some* FAPI method is
    offered; the profile's own method has to be one of them.
    """
    violations: list[FAPIViolation] = []
    methods = _str_values(discovery.token_endpoint_auth_methods_supported)
    if private_key_jwt is not None:
        if "private_key_jwt" not in methods:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_CLIENT_AUTH_UNSUPPORTED,
                    "Server does not advertise private_key_jwt in "
                    "token_endpoint_auth_methods_supported",
                )
            )
        auth_algs = _str_values(
            discovery.token_endpoint_auth_signing_alg_values_supported
        )
        if private_key_jwt.algorithm not in auth_algs:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_AUTH_SIGNING_ALG_UNSUPPORTED,
                    f"Server does not advertise private_key_jwt algorithm "
                    f"'{private_key_jwt.algorithm}' in "
                    "token_endpoint_auth_signing_alg_values_supported",
                )
            )
        dpop_algs = _str_values(discovery.dpop_signing_alg_values_supported)
        if not dpop_algs & FAPI2_ALLOWED_SIGNING_ALGORITHMS:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_DPOP_ALG_UNSUPPORTED,
                    "Server does not advertise DPoP with one of "
                    f"{_fapi_algorithms()} (dpop_signing_alg_values_supported); a "
                    "private_key_jwt client binds its tokens with DPoP",
                )
            )
    if mtls is not None:
        # RFC 8705 §2.1 and §2.2 share one request shape; the PKI and
        # self-signed variants differ only in how the server checks the cert.
        if not methods & _MTLS_AUTH_METHODS:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_CLIENT_AUTH_UNSUPPORTED,
                    "Server does not advertise an mTLS client authentication "
                    "method (tls_client_auth or self_signed_tls_client_auth) in "
                    "token_endpoint_auth_methods_supported",
                )
            )
        if discovery.tls_client_certificate_bound_access_tokens is not True:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_SENDER_CONSTRAINT_UNSUPPORTED,
                    "Server does not advertise tls_client_certificate_bound_access_"
                    "tokens: true; an mTLS client binds its tokens to its "
                    "certificate",
                )
            )
    return violations


# JARM (OAuth 2.0 JWT Secured Authorization Response Mode) §2.3.4: "jwt" picks
# the default mode for the response type.
JARM_RESPONSE_MODE = "jwt"

_MTLS_WITH_DPOP = FAPIViolation(
    FAPIViolationCode.MTLS_WITH_DPOP,
    "An mTLS client's tokens are bound to its certificate; do not also pass a DPoP key",
)


class FAPIProfileError(ValueError):
    """A FAPI 2.0 client profile refused a configuration or request.

    ``violations`` lists every rule that was broken; match on their ``code``.
    """

    def __init__(self, violations: list[FAPIViolation]) -> None:
        super().__init__("; ".join(v.message for v in violations))
        self.violations = violations

    @property
    def codes(self) -> list[FAPIViolationCode]:
        """The violations' codes, in order."""
        return [v.code for v in self.violations]


def _raise_on(violations: list[FAPIViolation]) -> None:
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

    The profile is narrower than the specification: a client uses exactly
    one of ``private_key_jwt`` (tokens DPoP-bound) or mTLS (tokens bound to
    the certificate), so it refuses ``private_key_jwt`` with mTLS-bound tokens
    and mTLS with a DPoP key, which :func:`validate_fapi_client_config`
    accepts because §5.3.3.1 allows them.

    The request builders fix the FAPI parameters (PAR,
    ``response_type=code``, PKCE ``S256``) and raise on anything that would
    weaken them, including a DPoP key whose algorithm the server does not
    advertise (RFC 9449 §5.1).  A DPoP-bound token request (authorization code
    or refresh) sets ``require_dpop_token_type``: FAPI 2.0 requires
    sender-constrained access tokens (Security Profile §5.3.2.1), so the
    protection is important and RFC 9449 §5's "MUST discard" applies.  A
    response with ``token_type`` other than ``DPoP`` fails instead of handing
    the client a Bearer token.  The profile is immutable.

    For an mTLS client the PAR and token endpoints (refresh included) are the
    server's ``mtls_endpoint_aliases`` when it advertises them (RFC 8705 §5,
    FAPI 2.0 Security Profile §5.2.2.1).

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
        # The client-auth types are frozen, so the caller's object is safe to keep.
        private_key_jwt: PrivateKeyJwt | None = None
        mtls: MtlsClientAuth | None = None
        if isinstance(self.client_auth, PrivateKeyJwt):
            auth = self.client_auth
            unset = auth.issuer is None and auth.audience is None
            private_key_jwt = replace(auth, issuer=issuer if unset else auth.issuer)
        elif isinstance(self.client_auth, MtlsClientAuth):
            mtls = self.client_auth
        else:
            raise FAPIProfileError(
                [
                    FAPIViolation(
                        FAPIViolationCode.CLIENT_AUTH_TYPE_INVALID,
                        "client_auth must be PrivateKeyJwt or MtlsClientAuth "
                        "(FAPI 2.0 Security Profile §5.3.3.1)",
                    )
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
            "private_key_jwt": private_key_jwt,
            "mtls": mtls,
        }
        for name, value in derived.items():
            object.__setattr__(self, name, value)

        violations: list[FAPIViolation] = []
        for name in (
            "issuer",
            "authorization_endpoint",
            "pushed_authorization_request_endpoint",
            "token_endpoint",
        ):
            url = derived[name]
            if not url:
                violations.append(
                    FAPIViolation(
                        FAPIViolationCode.ENDPOINT_MISSING, f"{name} is required"
                    )
                )
                continue
            parsed = urlparse(url)
            if parsed.scheme.lower() != "https":
                violations.append(
                    FAPIViolation(
                        FAPIViolationCode.ENDPOINT_INVALID,
                        f"{name} must use https, got {url!r}",
                    )
                )
            elif not parsed.hostname:
                violations.append(
                    FAPIViolation(
                        FAPIViolationCode.ENDPOINT_INVALID,
                        f"{name} must have a host, got {url!r}",
                    )
                )
        if not self.client_id:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.CLIENT_ID_MISSING, "client_id is required"
                )
            )
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
                self.request_object_key,
                derived["request_object_signing_algorithms"],
            )
        )
        _raise_on(violations)

    @property
    def signing_algorithms(self) -> list[str]:
        """Algorithms to accept for ID Tokens, JARM responses and DPoP (§5.4.1)."""
        return sorted(FAPI2_ALLOWED_SIGNING_ALGORITHMS)

    def _dpop_violations(self, dpop_key: DPoPKey | None) -> list[FAPIViolation]:
        """Check the request's DPoP key against this client and server."""
        if dpop_key is None:
            return []
        violations: list[FAPIViolation] = []
        if self.mtls is not None:
            violations.append(_MTLS_WITH_DPOP)
        elif (
            # A non-FAPI algorithm is already reported by _client_violations.
            dpop_key.algorithm in FAPI2_ALLOWED_SIGNING_ALGORITHMS
            and dpop_key.algorithm not in self.dpop_signing_algorithms
        ):
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.SERVER_DPOP_ALG_UNSUPPORTED,
                    f"Server does not advertise DPoP algorithm "
                    f"'{dpop_key.algorithm}' in dpop_signing_alg_values_supported "
                    "(RFC 9449 §5.1)",
                )
            )
        return violations

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
    ) -> PushedAuthorizationRequest | SignedPushedAuthorizationRequest:
        """Build the pushed authorization request (§5.3.3.2).

        ``response_type`` is ``code`` and the PKCE method ``S256``; a JARM
        profile asks for ``response_mode=jwt``.  A ``private_key_jwt`` client
        must pass the flow's ``dpop_key``.  With ``request_object_key`` the
        parameters are sent as a signed request object (RFC 9126 §3, FAPI 2.0
        Message Signing §5.3.2) in a
        :class:`~py_identity_model.core.models.SignedPushedAuthorizationRequest`.

        Raises:
            FAPIProfileError: The request would not be FAPI 2.0 compliant.
        """
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
            private_key_jwt=self.private_key_jwt,
            dpop_key=dpop_key,
            mtls=self.mtls,
            response_mode=JARM_RESPONSE_MODE if self.jarm else None,
        )
        _raise_on(
            [
                *validate_fapi_authorization_request(
                    request, native_app=self.native_app
                ).violations,
                *self._dpop_violations(dpop_key),
            ]
        )
        if self.request_object_key is None:
            return request
        return self._signed(request, self.request_object_key)

    def _signed(
        self, request: PushedAuthorizationRequest, key: RequestObjectKey
    ) -> SignedPushedAuthorizationRequest:
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
        return SignedPushedAuthorizationRequest(
            address=request.address,
            client_id=self.client_id,
            request=request_object,
            private_key_jwt=request.private_key_jwt,
            dpop_key=request.dpop_key,
            mtls=request.mtls,
        )

    def authorization_url(self, request_uri: str) -> str:
        """The authorization endpoint URL for a pushed request (§5.3.3.2).

        Carries only ``client_id`` and ``request_uri`` (RFC 9126 §4); see
        :func:`~py_identity_model.core.authorize_url.build_par_authorization_url`.

        Raises:
            FAPIProfileError: ``request_uri`` is not a non-blank string.
        """
        if not isinstance(request_uri, str) or not request_uri.strip():
            raise FAPIProfileError(
                [
                    FAPIViolation(
                        FAPIViolationCode.REQUEST_URI_MISSING,
                        "request_uri is required",
                    )
                ]
            )
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
        # Client authentication was checked at construction and the types
        # are frozen; only the per-request DPoP key needs checking.
        violations = [
            *_sender_constraint_request_violations(dpop_key=dpop_key, mtls=self.mtls),
            *self._dpop_violations(dpop_key),
        ]
        if not code_verifier:
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.PKCE_VERIFIER_MISSING,
                    "PKCE code_verifier is required",
                )
            )
        _raise_on(violations)
        return AuthorizationCodeTokenRequest(
            address=self.token_endpoint,
            client_id=self.client_id,
            code=code,
            redirect_uri=self.redirect_uri,
            code_verifier=code_verifier,
            private_key_jwt=self.private_key_jwt,
            dpop_key=dpop_key,
            mtls=self.mtls,
            require_dpop_token_type=dpop_key is not None,
        )

    def refresh_token_request(
        self,
        *,
        refresh_token: str,
        dpop_key: DPoPKey | None = None,
        scope: str | None = None,
    ) -> RefreshTokenRequest:
        """Build the refresh token request.

        A ``private_key_jwt`` client must pass the flow's ``dpop_key`` so the
        refreshed access token stays bound to it (§5.3.3.1, RFC 9449 §5).  An
        mTLS client's request goes to the token endpoint's mTLS alias.

        Raises:
            FAPIProfileError: The request would not be FAPI 2.0 compliant.
        """
        # Client authentication was checked at construction and the types
        # are frozen; only the per-request DPoP key needs checking.
        violations = [
            *_sender_constraint_request_violations(dpop_key=dpop_key, mtls=self.mtls),
            *self._dpop_violations(dpop_key),
        ]
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            violations.append(
                FAPIViolation(
                    FAPIViolationCode.REFRESH_TOKEN_MISSING, "refresh_token is required"
                )
            )
        _raise_on(violations)
        return RefreshTokenRequest(
            address=self.token_endpoint,
            client_id=self.client_id,
            refresh_token=refresh_token,
            scope=scope,
            private_key_jwt=self.private_key_jwt,
            mtls=self.mtls,
            dpop_key=dpop_key,
            require_dpop_token_type=dpop_key is not None,
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
    "FAPIViolation",
    "FAPIViolationCode",
    "validate_fapi_authorization_request",
    "validate_fapi_client_config",
    "validate_fapi_discovery",
]
