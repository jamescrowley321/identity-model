"""
Shared data models for py-identity-model.

This module contains all dataclasses and models used by both sync and async implementations.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode
from dataclasses import dataclass, field, fields
from enum import Enum
import json
from typing import TYPE_CHECKING, Any, ClassVar

from ..exceptions import (
    ConfigurationException,
    FailedResponseAccessError,
    SuccessfulResponseAccessError,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from .discovery_policy import DiscoveryPolicy
    from .dpop import DPoPKey


# ============================================================================
# Guarded Response Mixin
# ============================================================================


class _GuardedResponseMixin:
    """Mixin that guards field access based on response success state.

    Subclasses declare _guarded_fields as a frozenset of field names.
    Accessing a guarded field when is_successful is False raises
    FailedResponseAccessError with the original error message.
    Accessing 'error' when is_successful is True raises
    SuccessfulResponseAccessError.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset()

    _error_fields: ClassVar[frozenset[str]] = frozenset({"error", "error_description"})

    def __getattribute__(self, name: str):
        guarded = object.__getattribute__(self, "_guarded_fields")
        if name in guarded:
            is_successful = object.__getattribute__(self, "is_successful")
            if not is_successful:
                error = object.__getattribute__(self, "error")
                raise FailedResponseAccessError(name, error)
        elif name in object.__getattribute__(self, "_error_fields"):
            is_successful = object.__getattribute__(self, "is_successful")
            if is_successful:
                raise SuccessfulResponseAccessError(name)
        return object.__getattribute__(self, name)


# ============================================================================
# Base Request / Response Classes
# ============================================================================


@dataclass
class BaseRequest:
    """Base class for all API requests.

    Every request targets an endpoint URL via the *address* field.
    Subclasses add endpoint-specific parameters.
    """

    address: str


@dataclass(repr=False, eq=False)
class BaseResponse(_GuardedResponseMixin):
    """Base class for all API responses with success/error state.

    Inherits field-access guarding from ``_GuardedResponseMixin``.
    Subclasses override ``_guarded_fields`` and add data fields.
    Check ``is_successful`` before accessing data or error fields.

    .. note::

       ``dataclasses.asdict()`` and ``astuple()`` trigger the field-access
       guards and will raise.  Use ``vars(response)`` instead for dict
       conversion.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset()
    _secret_fields: ClassVar[frozenset[str]] = frozenset()

    is_successful: bool
    error: str | None = None

    __hash__ = None  # type: ignore[assignment]  # mutable dataclass

    def __repr__(self) -> str:
        """Safe repr that bypasses field-access guards and redacts secrets."""
        cls_name = type(self).__name__
        parts: list[str] = []
        for f in fields(self):
            val = object.__getattribute__(self, f.name)
            if f.name in self._secret_fields and val is not None:
                parts.append(f"{f.name}='[REDACTED]'")
            else:
                parts.append(f"{f.name}={val!r}")
        return f"{cls_name}({', '.join(parts)})"

    def __eq__(self, other: object) -> bool:
        """Safe equality that bypasses field-access guards."""
        if type(self) is not type(other):
            return NotImplemented
        return self.__dict__ == other.__dict__


# ============================================================================
# JSON Web Key (JWK) Models - RFC 7517
# ============================================================================


class JsonWebKeyParameterNames(Enum):
    """Parameter names as defined in RFC 7517"""

    # Required for all keys
    KTY = "kty"

    # Optional for all keys
    USE = "use"
    KEY_OPS = "key_ops"
    ALG = "alg"
    KID = "kid"

    # Optional JWK parameters
    X5U = "x5u"
    X5C = "x5c"
    X5T = "x5t"
    X5T_S256 = "x5t#S256"

    # Parameters for Elliptic Curve Keys
    CRV = "crv"
    X = "x"
    Y = "y"
    D = "d"

    # Parameters for RSA Keys
    N = "n"
    E = "e"
    P = "p"
    Q = "q"
    DP = "dp"
    DQ = "dq"
    QI = "qi"
    OTH = "oth"

    # Parameters for Symmetric Keys
    K = "k"

    def __str__(self) -> str:
        """Return the string value of the enum"""
        return self.value


class JsonWebAlgorithmsKeyTypes(Enum):
    EllipticCurve = "EC"
    RSA = "RSA"
    Octet = "oct"


@dataclass
class JsonWebKey:
    """
    A JSON Web Key (JWK) as defined in RFC 7517.
    The 'kty' (key type) parameter is required for all key types.
    Other parameters are required based on the key type.
    """

    # Required parameter for all keys
    kty: str

    # Optional parameters for all keys
    use: str | None = None
    key_ops: list[str] | None = None
    alg: str | None = None
    kid: str | None = None

    # Optional JWK parameters
    x5u: str | None = None
    x5c: list[str] | None = None
    x5t: str | None = None
    x5t_s256: str | None = None

    # Parameters for Elliptic Curve Keys
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    d: str | None = None  # Private key

    # Parameters for RSA Keys
    n: str | None = None  # Modulus
    e: str | None = None  # Exponent
    # RSA Private key parameters
    p: str | None = None
    q: str | None = None
    dp: str | None = None
    dq: str | None = None
    qi: str | None = None
    oth: list[dict[str, str]] | None = None

    # Parameters for Symmetric Keys
    k: str | None = None

    def __post_init__(self):
        """Validate the JWK after initialization"""
        if not self.kty:
            raise ConfigurationException(
                "The 'kty' (Key Type) parameter is required",
            )

        self._validate_key_parameters()

    def _validate_ec_key(self):
        """Validate EC key parameters per RFC 7518"""
        if not all([self.crv, self.x, self.y]):
            raise ConfigurationException(
                "EC keys require 'crv', 'x', and 'y' parameters",
            )

        valid_curves = ["P-256", "P-384", "P-521", "secp256k1"]
        if self.crv not in valid_curves:
            raise ConfigurationException(
                f"Unsupported curve: {self.crv}. Supported curves: {valid_curves}",
            )

    def _validate_rsa_key(self):
        """Validate RSA key parameters"""
        if not all([self.n, self.e]):
            raise ConfigurationException(
                "RSA keys require 'n' and 'e' parameters",
            )

    def _validate_symmetric_key(self):
        """Validate symmetric key parameters"""
        if self.k is None:
            raise ConfigurationException(
                "Symmetric keys require 'k' parameter",
            )

    def _validate_use_parameter(self):
        """Validate 'use' parameter per RFC 7517 Section 4.2"""
        if self.use is None:
            return

        valid_use_values = ["sig", "enc"]
        if self.use not in valid_use_values and not self.use.startswith(
            "https://",
        ):
            raise ConfigurationException(
                f"Invalid 'use' parameter: {self.use}. Must be 'sig', 'enc', or a URI",
            )

    def _validate_key_ops_parameter(self):
        """Validate 'key_ops' parameter per RFC 7517 Section 4.3"""
        if self.key_ops is None:
            return

        valid_key_ops = [
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ]
        for op in self.key_ops:
            if op not in valid_key_ops:
                raise ConfigurationException(
                    f"Invalid key operation: {op}. Valid operations: {valid_key_ops}",
                )

    def _validate_key_parameters(self):
        """Validate required parameters based on the key type"""
        # Validate key type specific parameters
        if self.kty == "EC":
            self._validate_ec_key()
        elif self.kty == "RSA":
            self._validate_rsa_key()
        elif self.kty == "oct":
            self._validate_symmetric_key()

        # Validate 'use' and 'key_ops' parameters
        self._validate_use_parameter()
        self._validate_key_ops_parameter()

        # Validate mutual exclusivity per RFC 7517 Section 4.3
        if self.use is not None and self.key_ops is not None:
            raise ConfigurationException(
                "The 'use' and 'key_ops' parameters are mutually exclusive",
            )

    @classmethod
    def from_json(cls, json_str: str) -> JsonWebKey:
        """Create a JWK from a JSON string"""
        if not json_str or not json_str.strip():
            raise ConfigurationException("JSON string cannot be empty")

        try:
            data = json.loads(json_str)

            # Validate that the parsed JSON is a dictionary
            if not isinstance(data, dict):
                raise ConfigurationException(
                    "Invalid JWK format: JSON must be an object, not a "
                    + type(data).__name__,
                )

            # Dynamically get valid field names from the JsonWebKey dataclass
            valid_fields = {field.name for field in fields(cls)}

            # Map JWK parameter names to Python field names
            mapped_data: dict[str, Any] = {}
            for k, v in data.items():
                if k == JsonWebKeyParameterNames.X5T_S256.value:
                    mapped_data["x5t_s256"] = v
                elif k == "key_ops" and isinstance(v, str):
                    # Ensure key_ops is a list
                    mapped_data[k] = [v]
                elif k == "x5c" and isinstance(v, str):
                    # Ensure x5c is a list
                    mapped_data[k] = [v]
                elif k == "oth" and isinstance(v, str):
                    # Ensure oth is a list (though a string oth is unusual)
                    mapped_data[k] = [
                        {"r": v},
                    ]  # Convert to expected dict format
                else:
                    mapped_data[k] = v

            # Filter to only include valid fields
            filtered_data = {k: v for k, v in mapped_data.items() if k in valid_fields}

            return cls(**filtered_data)
        except json.JSONDecodeError as e:
            raise ConfigurationException("Invalid JSON format") from e
        except (TypeError, AttributeError) as e:
            raise ConfigurationException(
                f"Invalid JWK format: {e!s}",
            ) from e

    def to_json(self) -> str:
        """Convert the JWK to a JSON string"""
        data = {}
        for k, v in self.__dict__.items():
            if v is not None:
                # Map Python field names back to JWK parameter names
                if k == "x5t_s256":
                    data[JsonWebKeyParameterNames.X5T_S256.value] = v
                else:
                    data[k] = v
        return json.dumps(data)

    @property
    def has_private_key(self) -> bool:
        """Check if the key contains private key parts"""
        if self.kty == "RSA":
            return all([self.d, self.p, self.q, self.dp, self.dq, self.qi])
        if self.kty == "EC":
            return self.d is not None
        return False

    @property
    def key_size(self) -> int:
        """Calculate the key size in bits"""
        if self.kty == "RSA":
            return len(self._decode_base64url(self.n)) * 8 if self.n else 0
        if self.kty == "EC":
            return len(self._decode_base64url(self.x)) * 8 if self.x else 0
        if self.kty == "oct":
            return len(self._decode_base64url(self.k)) * 8 if self.k else 0
        return 0

    @staticmethod
    def _decode_base64url(input_str: str | None) -> bytes:
        """Decode a base64url-encoded string"""
        if not input_str:
            return b""
        padding = "=" * (4 - len(input_str) % 4)
        return urlsafe_b64decode(input_str + padding)

    def as_dict(self):
        """Convert the JWK to a dictionary with all available properties.

        Python attribute names are mapped back to their RFC 7517 JWK member
        names (e.g. ``x5t_s256`` -> ``x5t#S256``) so the result round-trips
        through :meth:`from_json` and :func:`jwks_from_dict`. Providers such as
        Keycloak emit ``x5t#S256`` in their JWKS; without this mapping the
        dictionary form used ``x5t_s256`` and silently dropped the thumbprint
        on re-parse.

        **Absent members are omitted (contract):** only members with a non-``None``
        value appear in the result. This makes the mapping safe to hand to
        libraries — notably PyJWT's ``Algorithm.from_jwk`` — that classify a JWK
        as public vs. private by key *name presence* rather than value: a public
        key never carries a null ``d`` (or other private member) that would be
        misread as a private key. Use :attr:`has_private_key` for the value-based
        public/private test.
        """
        data = {}
        for key, value in self.__dict__.items():
            if value is None:
                continue
            # Map Python field names back to JWK parameter names
            if key == "x5t_s256":
                data[JsonWebKeyParameterNames.X5T_S256.value] = value
            else:
                data[key] = value
        return data


# ============================================================================
# Discovery Document Models - OpenID Connect Discovery 1.0
# ============================================================================


@dataclass
class DiscoveryDocumentRequest(BaseRequest):
    """Request for fetching an OpenID Connect discovery document.

    Attributes:
        address: The base URL of the identity provider
            (e.g. ``https://example.com``). The well-known path is
            appended automatically.
        policy: Optional discovery policy for configuring validation
            behavior. When ``None``, strict defaults apply.
    """

    policy: DiscoveryPolicy | None = None


@dataclass(repr=False, eq=False)
class DiscoveryDocumentResponse(BaseResponse):
    """Response from an OpenID Connect discovery document fetch.

    Check ``is_successful`` before accessing data fields. Accessing guarded
    fields on a failed response raises
    ``FailedResponseAccessError``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "issuer",
            "jwks_uri",
            "authorization_endpoint",
            "token_endpoint",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "userinfo_endpoint",
            "registration_endpoint",
            "scopes_supported",
            "response_modes_supported",
            "grant_types_supported",
            "acr_values_supported",
            "id_token_encryption_alg_values_supported",
            "id_token_encryption_enc_values_supported",
            "userinfo_signing_alg_values_supported",
            "userinfo_encryption_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "request_object_signing_alg_values_supported",
            "request_object_encryption_alg_values_supported",
            "request_object_encryption_enc_values_supported",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "display_values_supported",
            "claim_types_supported",
            "claims_supported",
            "claims_locales_supported",
            "ui_locales_supported",
            "claims_parameter_supported",
            "request_parameter_supported",
            "request_uri_parameter_supported",
            "require_request_uri_registration",
            "service_documentation",
            "op_policy_uri",
            "op_tos_uri",
            "introspection_endpoint",
            "code_challenge_methods_supported",
            "pushed_authorization_request_endpoint",
            "require_pushed_authorization_requests",
            "end_session_endpoint",
            "backchannel_logout_supported",
            "backchannel_logout_session_supported",
            "authorization_response_iss_parameter_supported",
            "authorization_signing_alg_values_supported",
            "authorization_encryption_alg_values_supported",
            "authorization_encryption_enc_values_supported",
            "mtls_endpoint_aliases",
            "tls_client_certificate_bound_access_tokens",
        }
    )

    # Core OpenID Connect endpoints
    issuer: str | None = None
    jwks_uri: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None

    # Required properties from OpenID Connect Discovery 1.0 specification
    response_types_supported: list[str] | None = None
    subject_types_supported: list[str] | None = None
    id_token_signing_alg_values_supported: list[str] | None = None

    # Common optional properties
    userinfo_endpoint: str | None = None
    registration_endpoint: str | None = None
    introspection_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    acr_values_supported: list[str] | None = None

    # Cryptographic algorithm support
    id_token_encryption_alg_values_supported: list[str] | None = None
    id_token_encryption_enc_values_supported: list[str] | None = None
    userinfo_signing_alg_values_supported: list[str] | None = None
    userinfo_encryption_alg_values_supported: list[str] | None = None
    userinfo_encryption_enc_values_supported: list[str] | None = None
    request_object_signing_alg_values_supported: list[str] | None = None
    request_object_encryption_alg_values_supported: list[str] | None = None
    request_object_encryption_enc_values_supported: list[str] | None = None

    # Token endpoint authentication
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None

    # Display and UI
    display_values_supported: list[str] | None = None
    claim_types_supported: list[str] | None = None
    claims_supported: list[str] | None = None
    claims_locales_supported: list[str] | None = None
    ui_locales_supported: list[str] | None = None

    # PKCE support (RFC 8414)
    code_challenge_methods_supported: list[str] | None = None

    # Pushed Authorization Requests (RFC 9126 §5)
    pushed_authorization_request_endpoint: str | None = None
    require_pushed_authorization_requests: bool | None = None

    # Feature support flags
    claims_parameter_supported: bool | None = None
    request_parameter_supported: bool | None = None
    request_uri_parameter_supported: bool | None = None
    require_request_uri_registration: bool | None = None

    # Authorization-response issuer parameter support (RFC 9207 §3)
    authorization_response_iss_parameter_supported: bool | None = None

    # JWT-Secured Authorization Response Mode (JARM §5) algorithm support
    authorization_signing_alg_values_supported: list[str] | None = None
    authorization_encryption_alg_values_supported: list[str] | None = None
    authorization_encryption_enc_values_supported: list[str] | None = None

    # Mutual-TLS support (RFC 8705 §3.3 / §5)
    mtls_endpoint_aliases: dict | None = None
    tls_client_certificate_bound_access_tokens: bool | None = None

    # RP-Initiated Logout support (OpenID Connect RP-Initiated Logout 1.0 §2)
    end_session_endpoint: str | None = None

    # Back-Channel Logout support (OpenID Connect Back-Channel Logout 1.0 §3)
    backchannel_logout_supported: bool | None = None
    backchannel_logout_session_supported: bool | None = None

    # Documentation and policy
    service_documentation: str | None = None
    op_policy_uri: str | None = None
    op_tos_uri: str | None = None

    # HTTP cache metadata (not a guarded field — always accessible)
    cache_control: str | None = None


# ============================================================================
# JWKS Models - RFC 7517
# ============================================================================


@dataclass
class JwksRequest(BaseRequest):
    """Request for fetching a JSON Web Key Set.

    Attributes:
        address: The JWKS endpoint URL (typically from ``DiscoveryDocumentResponse.jwks_uri``).
        policy: Optional discovery policy for pre-flight URL scheme
            validation. When ``None``, strict defaults apply
            (HTTPS required outside loopback).
    """

    policy: DiscoveryPolicy | None = None


@dataclass(repr=False, eq=False)
class JwksResponse(BaseResponse):
    """Response from a JWKS endpoint fetch.

    Check ``is_successful`` before accessing ``keys``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"keys"})

    keys: list[JsonWebKey] | None = None
    cache_control: str | None = None


# ============================================================================
# Client Authentication - private_key_jwt (RFC 7523, OIDC Core 1.0 Section 9)
# ============================================================================


@dataclass
class PrivateKeyJwt:
    """``private_key_jwt`` client authentication parameters (RFC 7523).

    When supplied on a client-authenticating request, the client is
    authenticated by a signed JWT assertion (OpenID Connect Core 1.0
    Section 9) instead of a client secret.  It takes precedence over
    ``client_secret`` when both are present.

    Attributes:
        private_key: PEM-encoded private key used to sign the assertion
            (``bytes`` or ``str``).
        algorithm: Asymmetric signing algorithm (default ``"PS256"``).
            FAPI 2.0 requires ``PS256`` or ``ES256``.
        kid: Optional key ID placed in the assertion JWT header to aid the
            authorization server's key lookup.
        audience: Override for the assertion ``aud`` claim.  Defaults to the
            request ``address`` (the endpoint URL) when ``None``.
        lifetime: Assertion validity in seconds (default 300).
    """

    # repr suppressed: the raw PEM signing key must never leak into logs,
    # exception messages, or crash-reporter frame captures. Mirrors the
    # ``repr=False`` treatment of secret-bearing request models below.
    private_key: str | bytes = field(repr=False)
    algorithm: str = "PS256"
    kid: str | None = None
    audience: str | None = None
    lifetime: int = 300


@dataclass
class MtlsClientAuth:
    """Mutual-TLS client authentication parameters (RFC 8705).

    When supplied on a client-authenticating request, the client is
    authenticated by presenting an X.509 certificate at the TLS layer
    (``tls_client_auth`` or ``self_signed_tls_client_auth``) instead of a
    client secret. ``client_id`` is carried in the request body and no
    ``Authorization`` header is sent (RFC 8705 §2). It takes precedence over
    ``client_secret`` but sits below ``private_key_jwt`` when both are present.

    The certificate is presented at the TLS layer, so the sync/async HTTP
    wrappers build a short-lived, cert-configured client for the request.

    Attributes:
        certificate: Filesystem path to the PEM-encoded client certificate.
        private_key: Filesystem path to the PEM-encoded private key. ``repr``
            is suppressed so the key path never leaks into logs or crash
            reports, mirroring the ``private_key`` treatment on
            :class:`PrivateKeyJwt`.
        password: Optional password for an encrypted private key. Secret —
            ``repr`` suppressed.
        auth_method: The RFC 8705 §2 method name — ``"tls_client_auth"``
            (default, PKI-based) or ``"self_signed_tls_client_auth"``.
    """

    certificate: str
    private_key: str = field(repr=False)
    password: str | None = field(default=None, repr=False)
    auth_method: str = "tls_client_auth"


# ============================================================================
# Token Client Models
# ============================================================================


@dataclass
class ClientCredentialsTokenRequest(BaseRequest):
    """Request for an OAuth 2.0 client credentials token.

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        client_secret: The client secret (optional when authenticating with
            ``private_key_jwt``).
        scope: Space-delimited list of requested scopes (optional).
        private_key_jwt: ``private_key_jwt`` authentication parameters.  When
            set, takes precedence over ``client_secret`` (RFC 7523).
    """

    client_id: str
    client_secret: str | None = None
    scope: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class ClientCredentialsTokenResponse(BaseResponse):
    """Response from a client credentials token request.

    Check ``is_successful`` before accessing ``token``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None


# ============================================================================
# Authorization Code Token Models
# ============================================================================


@dataclass
class AuthorizationCodeTokenRequest(BaseRequest):
    """Request for exchanging an authorization code for tokens.

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        code: The authorization code received from the callback.
        redirect_uri: The same redirect URI used in the authorization request.
        code_verifier: PKCE code verifier (required when PKCE was used).
        client_secret: Client secret (optional for public clients per RFC 7636).
        scope: Space-delimited list of requested scopes (optional).
        private_key_jwt: ``private_key_jwt`` authentication parameters.  When
            set, takes precedence over ``client_secret`` (RFC 7523).
        dpop_key: When set, the token request is DPoP-bound (RFC 9449): a DPoP
            proof for the token endpoint is attached and the ``use_dpop_nonce``
            challenge is honored with a single retry.  FAPI 2.0 sender
            constraining.
    """

    client_id: str
    code: str
    redirect_uri: str
    code_verifier: str | None = None
    client_secret: str | None = None
    scope: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    dpop_key: DPoPKey | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class AuthorizationCodeTokenResponse(BaseResponse):
    """Response from an authorization code token exchange.

    Check ``is_successful`` before accessing ``token``.
    The token dict typically contains ``access_token``, ``token_type``,
    ``expires_in``, ``refresh_token``, and optionally ``id_token``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None


# ============================================================================
# Refresh Token Models - RFC 6749 Section 6
# ============================================================================


@dataclass
class RefreshTokenRequest(BaseRequest):
    """Request for refreshing an OAuth 2.0 access token.

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        refresh_token: The refresh token received from a prior authorization.
        scope: Optional space-delimited scopes (must be subset of original grant).
        client_secret: Client secret (optional for public clients).
    """

    client_id: str
    refresh_token: str
    scope: str | None = None
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class RefreshTokenResponse(BaseResponse):
    """Response from a refresh token grant.

    Check ``is_successful`` before accessing ``token``.
    The token dict typically contains a new ``access_token`` and may
    include a new ``refresh_token``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None


# ============================================================================
# Token Introspection Models - RFC 7662
# ============================================================================


@dataclass
class TokenIntrospectionRequest(BaseRequest):
    """Request for OAuth 2.0 Token Introspection (RFC 7662).

    Attributes:
        address: The introspection endpoint URL.
        token: The token to introspect.
        client_id: The client identifier for authentication.
        token_type_hint: Optional hint — ``"access_token"`` or ``"refresh_token"``.
        client_secret: Client secret for authentication (optional for public clients).
    """

    token: str
    client_id: str
    token_type_hint: str | None = None
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class TokenIntrospectionResponse(BaseResponse):
    """Response from a token introspection endpoint (RFC 7662).

    Check ``is_successful`` before accessing ``claims``.
    The ``claims`` dict contains at minimum ``active: bool``.
    When ``active`` is ``True``, additional claims like ``scope``,
    ``client_id``, ``username``, ``exp``, ``iat``, ``sub``, ``aud``,
    ``iss``, and ``jti`` may be present.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"claims"})

    claims: dict | None = None


# ============================================================================
# Pushed Authorization Request Models - RFC 9126
# ============================================================================


@dataclass
class PushedAuthorizationRequest(BaseRequest):
    """Request for OAuth 2.0 Pushed Authorization Request (RFC 9126).

    Pushes authorization parameters to the PAR endpoint and receives
    a ``request_uri`` for use in the authorization URL.

    Attributes:
        address: The pushed authorization request endpoint URL.
        client_id: The client identifier.
        redirect_uri: The registered redirect URI.
        scope: Space-delimited scopes (default ``"openid"``).
        response_type: OAuth 2.0 response type (default ``"code"``).
        state: CSRF protection value.
        nonce: OpenID Connect nonce.
        code_challenge: PKCE code challenge.
        code_challenge_method: PKCE method (``"S256"`` or ``"plain"``).
        client_secret: Client secret (optional for public clients).
        private_key_jwt: ``private_key_jwt`` authentication parameters.  When
            set, takes precedence over ``client_secret`` (RFC 7523).
        dpop_key: When set, the PAR is DPoP-bound (RFC 9449): a DPoP proof for
            the PAR endpoint is attached and the ``use_dpop_nonce`` challenge is
            honored with a single retry.  FAPI 2.0 sender constraining.
        response_mode: OAuth 2.0 ``response_mode`` to push (e.g. ``"jwt"`` /
            ``"query.jwt"`` for JWT-Secured Authorization Response Mode, JARM).
            Omitted from the pushed parameters when ``None``.
    """

    client_id: str
    redirect_uri: str
    scope: str = "openid"
    response_type: str = "code"
    state: str | None = None
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    dpop_key: DPoPKey | None = None
    mtls: MtlsClientAuth | None = None
    response_mode: str | None = None


@dataclass(repr=False, eq=False)
class PushedAuthorizationResponse(BaseResponse):
    """Response from a pushed authorization request endpoint (RFC 9126).

    Check ``is_successful`` before accessing ``request_uri``.
    Use ``request_uri`` in the authorization URL instead of inline parameters.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"request_uri", "expires_in"})
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"request_uri"})

    request_uri: str | None = None
    expires_in: int | None = None


# ============================================================================
# Device Authorization Grant Models - RFC 8628
# ============================================================================


@dataclass
class DeviceAuthorizationRequest(BaseRequest):
    """Request for OAuth 2.0 Device Authorization (RFC 8628).

    Attributes:
        address: The device authorization endpoint URL.
        client_id: The client identifier.
        scope: Space-delimited scopes (default ``"openid"``).
        client_secret: Client secret (optional for public clients).
    """

    client_id: str
    scope: str = "openid"
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class DeviceAuthorizationResponse(BaseResponse):
    """Response from the device authorization endpoint (RFC 8628).

    Check ``is_successful`` before accessing guarded fields.
    Display ``user_code`` and ``verification_uri`` to the user,
    then poll with :class:`DeviceTokenRequest`.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval",
        }
    )
    # ``device_code`` is the RFC 8628 polling credential; ``user_code`` /
    # ``verification_uri`` are meant to be shown to the user, so only the
    # device_code is redacted.
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"device_code"})

    device_code: str | None = None
    user_code: str | None = None
    verification_uri: str | None = None
    verification_uri_complete: str | None = None
    expires_in: int | None = None
    interval: int | None = None


@dataclass
class DeviceTokenRequest(BaseRequest):
    """Request for polling the token endpoint during device flow (RFC 8628).

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        device_code: The device code from :class:`DeviceAuthorizationResponse`.
        client_secret: Client secret (optional for public clients).
    """

    client_id: str
    device_code: str
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class DeviceTokenResponse(BaseResponse):
    """Response from a device token poll (RFC 8628).

    Check ``is_successful`` before accessing ``token``.
    When ``is_successful`` is ``False``, check ``error_code``:

    - ``"authorization_pending"`` - user hasn't authorized yet, poll again
    - ``"slow_down"`` - increase polling interval (see ``interval``)
    - ``"expired_token"`` - device code expired, restart flow
    - ``"access_denied"`` - user denied authorization

    ``error_code`` and ``interval`` are always accessible regardless
    of ``is_successful``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"token"})
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None
    error_code: str | None = None
    interval: int | None = None


# ============================================================================
# Token Exchange Models - RFC 8693
# ============================================================================


@dataclass
class TokenExchangeRequest(BaseRequest):
    """Request for OAuth 2.0 Token Exchange (RFC 8693).

    Attributes:
        address: The token endpoint URL.
        client_id: The client identifier.
        subject_token: Token representing the subject of the exchange.
        subject_token_type: URI indicating the subject token type
            (use constants from :mod:`py_identity_model.core.token_type`).
        actor_token: Token representing the actor (for delegation).
        actor_token_type: URI indicating the actor token type
            (required when ``actor_token`` is provided).
        resource: Target service URI.
        audience: Logical name of the target service.
        scope: Space-delimited requested scopes.
        requested_token_type: Desired type of the issued token.
        client_secret: Client secret (optional for public clients).
    """

    client_id: str
    subject_token: str
    subject_token_type: str
    actor_token: str | None = None
    actor_token_type: str | None = None
    resource: str | None = None
    audience: str | None = None
    scope: str | None = None
    requested_token_type: str | None = None
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class TokenExchangeResponse(BaseResponse):
    """Response from a token exchange request (RFC 8693).

    Check ``is_successful`` before accessing ``token`` or
    ``issued_token_type``.  The ``token`` dict contains standard
    OAuth 2.0 token fields (``access_token``, ``token_type``, etc.).
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {"token", "issued_token_type"}
    )
    _secret_fields: ClassVar[frozenset[str]] = frozenset({"token"})

    token: dict | None = None
    issued_token_type: str | None = None


# ============================================================================
# Token Revocation Models - RFC 7009
# ============================================================================


@dataclass
class TokenRevocationRequest(BaseRequest):
    """Request for OAuth 2.0 Token Revocation (RFC 7009).

    Attributes:
        address: The revocation endpoint URL.
        token: The token to revoke.
        client_id: The client identifier for authentication.
        token_type_hint: Optional hint — ``"access_token"`` or ``"refresh_token"``.
        client_secret: Client secret for authentication (optional for public clients).
    """

    token: str
    client_id: str
    token_type_hint: str | None = None
    client_secret: str | None = None
    private_key_jwt: PrivateKeyJwt | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class TokenRevocationResponse(BaseResponse):
    """Response from a token revocation endpoint (RFC 7009).

    A successful revocation returns ``is_successful=True`` with no data
    fields.  Per RFC 7009, the server responds with 200 even if the token
    was already invalid.
    """


# ============================================================================
# UserInfo Models - OpenID Connect Core 1.0 Section 5.3
# ============================================================================


@dataclass
class UserInfoRequest(BaseRequest):
    """Request for the OpenID Connect UserInfo endpoint.

    Attributes:
        address: The UserInfo endpoint URL.
        token: A valid access token with ``openid`` scope.
        expected_sub: Expected ``sub`` claim from the ID token for
            verification per OIDC Core 1.0 Section 5.3.4.  When provided,
            the ``sub`` in the UserInfo response is compared against this
            value and a mismatch produces an error response.
        dpop_key: When set, the UserInfo request is DPoP-bound (RFC 9449): the
            access token is presented with ``Authorization: DPoP <token>`` and
            a resource-request DPoP proof (carrying the ``ath`` access-token
            hash) is attached, honoring the ``use_dpop_nonce`` challenge with a
            single retry.  Required to use a sender-constrained access token at
            the resource server (FAPI 2.0).
        mtls: When set, the UserInfo/resource request presents this client
            certificate at the TLS layer (RFC 8705) — required to use an mTLS
            certificate-bound access token at the resource server.
    """

    token: str
    expected_sub: str | None = None
    dpop_key: DPoPKey | None = None
    mtls: MtlsClientAuth | None = None


@dataclass(repr=False, eq=False)
class UserInfoResponse(BaseResponse):
    """Response from the UserInfo endpoint.

    Check ``is_successful`` before accessing ``claims`` or ``raw``.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset({"claims", "raw"})

    claims: dict | None = None
    raw: str | None = None


# ============================================================================
# Dynamic Client Registration Models - RFC 7591 / RFC 7592
# ============================================================================


@dataclass
class ClientRegistrationRequest(BaseRequest):
    """Request to register a client (RFC 7591 Section 3, OIDC Registration 1.0).

    Attributes:
        address: The client registration endpoint URL.
        redirect_uris: Redirection URIs registered for the client.
        response_types / grant_types / application_type / contacts /
            client_name / logo_uri / client_uri / policy_uri / tos_uri /
            token_endpoint_auth_method / scope / jwks_uri: Optional client
            metadata (RFC 7591 Section 2).
        extra_metadata: Additional metadata merged into the request body
            (e.g. ``sector_identifier_uri``, ``subject_type``) so OIDC-specific
            fields flow without a dedicated attribute.
        initial_access_token: Optional bearer token for a protected
            registration endpoint (RFC 7591 Section 3).
    """

    redirect_uris: list[str]
    response_types: list[str] | None = None
    grant_types: list[str] | None = None
    application_type: str | None = None
    contacts: list[str] | None = None
    client_name: str | None = None
    logo_uri: str | None = None
    client_uri: str | None = None
    policy_uri: str | None = None
    tos_uri: str | None = None
    token_endpoint_auth_method: str | None = None
    scope: str | None = None
    jwks_uri: str | None = None
    extra_metadata: dict | None = None
    initial_access_token: str | None = None


@dataclass
class ClientReadRequest(BaseRequest):
    """Request to read a client configuration (RFC 7592 Section 2.1).

    Attributes:
        address: The client's ``registration_client_uri``.
        registration_access_token: Bearer token issued at registration.
    """

    registration_access_token: str


@dataclass
class ClientUpdateRequest(BaseRequest):
    """Request to update a client configuration (RFC 7592 Section 2.2).

    The PUT body MUST include ``client_id`` and the full client metadata;
    omitted fields are treated by the server as removed.

    Attributes:
        address: The client's ``registration_client_uri``.
        registration_access_token: Bearer token issued at registration.
        client_id: The registered client identifier (required in the body).
        redirect_uris: Full redirect URI list to persist.
        client_secret: Current client secret, echoed back when required.
        extra_metadata: Additional metadata merged into the request body.
    """

    registration_access_token: str
    client_id: str
    redirect_uris: list[str]
    response_types: list[str] | None = None
    grant_types: list[str] | None = None
    application_type: str | None = None
    contacts: list[str] | None = None
    client_name: str | None = None
    logo_uri: str | None = None
    client_uri: str | None = None
    policy_uri: str | None = None
    tos_uri: str | None = None
    token_endpoint_auth_method: str | None = None
    scope: str | None = None
    jwks_uri: str | None = None
    client_secret: str | None = None
    extra_metadata: dict | None = None


@dataclass
class ClientDeleteRequest(BaseRequest):
    """Request to deregister a client (RFC 7592 Section 2.3).

    Attributes:
        address: The client's ``registration_client_uri``.
        registration_access_token: Bearer token issued at registration.
    """

    registration_access_token: str


@dataclass(repr=False, eq=False)
class ClientRegistrationResponse(BaseResponse):
    """Response from the client registration endpoint (RFC 7591 / RFC 7592).

    Returned by register, read, and update operations.  Check
    ``is_successful`` before accessing ``client_id``, ``client_secret``,
    ``registration_access_token`` or ``registration_client_uri``.
    ``metadata`` echoes the full client configuration returned by the server.
    """

    _guarded_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "client_id",
            "client_secret",
            "registration_access_token",
            "registration_client_uri",
        }
    )
    _secret_fields: ClassVar[frozenset[str]] = frozenset(
        {"client_secret", "registration_access_token"}
    )

    client_id: str | None = None
    client_secret: str | None = None
    client_id_issued_at: int | None = None
    client_secret_expires_at: int | None = None
    registration_access_token: str | None = None
    registration_client_uri: str | None = None
    metadata: dict | None = None


@dataclass(repr=False, eq=False)
class ClientDeleteResponse(BaseResponse):
    """Response from deregistering a client (RFC 7592 Section 2.3).

    A successful deletion returns ``is_successful=True`` with no data fields
    (the server responds with 204 No Content).
    """


# ============================================================================
# Token Validation Models
# ============================================================================


@dataclass
class TokenValidationConfig:
    """
    Configuration for JWT token validation.

    Attributes:
        perform_disco: Whether to perform discovery to fetch JWKS and issuer
        key: Public key for JWT verification (manual mode, ``perform_disco=False``).
            Accepts either a :class:`JsonWebKey` — exactly what ``get_jwks``
            returns, so a key can round-trip straight back in — or a plain JWK
            ``dict`` (``{"kty": "RSA", "n": ..., "e": ...}``). ``None``-valued
            members are ignored during conversion, so a public key is never
            misclassified as private.
        audience: Expected audience claim(s) in the token
        algorithms: List of allowed signing algorithms (e.g., ['RS256'])
        issuer: Expected issuer claim.  A single string or a list of
            accepted issuers for multi-tenant validation.
        subject: Expected ``sub`` claim.  Validated after decoding.
        options: Additional PyJWT decode options (e.g., {'require': ['sub']}).
            Security-critical options (verify_signature, verify_exp, verify_nbf,
            verify_iat) cannot be disabled and will raise ConfigurationException
            if set to False.
        claims_validator: Optional injectable claims validator, run after the
                         standard checks pass. A ``ClaimsValidator`` is any
                         callable ``(claims) -> None`` — sync, or async in the
                         async context — that raises ``ClaimsValidationError``
                         (carrying a structured ``reason``/``claim``) to reject.
                         The decoded claims dict is passed as the only argument.
                         Any raised exception rejects the token; a
                         ``ClaimsValidationError`` (or any
                         ``TokenValidationException``) propagates with its reason
                         intact, other exceptions become a generic failure.
                         Compose several with ``combine_claims_validators`` and
                         reuse ``require_claims`` / ``require_claim_value`` /
                         ``require_scopes``.
        leeway: Clock skew tolerance in seconds for ``exp`` and ``nbf``
            claims.  Useful when clocks between the issuer and this
            server are not perfectly synchronized.
        allowed_issuers: Optional allowlist of approved issuer identifiers.
            **Purely opt-in.** When ``None`` (the default) discovery is assumed
            authoritative and its issuer is used as-is — default behaviour is
            unchanged. When set, the issuer used to validate the token (the
            discovery document's issuer in discovery mode, otherwise ``issuer``)
            MUST be a member, checked *before* the discovery result is trusted.
            Set it only for multi-tenant callers that resolve discovery from an
            untrusted token's ``iss`` — without it an attacker who stands up their
            own tenant and mints a validly-signed token would pass validation.
        discovery_policy: Optional :class:`DiscoveryPolicy` applied to the
            discovery document (and its advertised endpoints) on the cached
            ``validate_token`` path. When ``None`` (the default) a policy is
            derived from ``require_https`` alone — behaviour is unchanged. Set it
            to reach any of the other policy knobs (``validate_issuer``,
            ``validate_endpoints``, ``additional_endpoint_base_addresses``,
            ``authority``, ``allow_loopback_endpoints``, ``allow_http_on_loopback``)
            while still using the built-in discovery/JWKS TTL cache, instead of
            calling ``get_discovery_document`` directly and re-implementing
            caching. When provided, ``discovery_policy`` **takes precedence over**
            ``require_https`` (the policy's own ``require_https`` governs). The
            discovery cache is partitioned by the full policy, so a response
            admitted under a lax policy is never served to a stricter caller.

    Examples:
        >>> # Multi-tenant with clock skew tolerance
        >>> config = TokenValidationConfig(
        ...     perform_disco=True,
        ...     audience="my-api",
        ...     issuer=[
        ...         "https://idp1.example.com",
        ...         "https://idp2.example.com",
        ...     ],
        ...     leeway=30,
        ... )

        >>> # Custom claims validation
        >>> def validate_custom_claims(claims: dict) -> None:
        ...     if claims.get("role") != "admin":
        ...         raise ValueError("User is not an admin")
        >>>
        >>> config = TokenValidationConfig(
        ...     perform_disco=True,
        ...     claims_validator=validate_custom_claims,
        ... )
    """

    perform_disco: bool
    key: dict | JsonWebKey | None = None
    audience: str | None = None
    algorithms: list[str] | None = None
    issuer: str | list[str] | None = None
    subject: str | None = None
    options: dict | None = None
    claims_validator: Callable | None = None
    require_https: bool = True
    leeway: float | None = None
    allowed_issuers: list[str] | None = None
    discovery_policy: DiscoveryPolicy | None = None


__all__ = [
    # Authorization Code Token
    "AuthorizationCodeTokenRequest",
    "AuthorizationCodeTokenResponse",
    # Base Classes
    "BaseRequest",
    "BaseResponse",
    # Token Client
    "ClientCredentialsTokenRequest",
    "ClientCredentialsTokenResponse",
    # Dynamic Client Registration
    "ClientDeleteRequest",
    "ClientDeleteResponse",
    "ClientReadRequest",
    "ClientRegistrationRequest",
    "ClientRegistrationResponse",
    "ClientUpdateRequest",
    # Device Authorization Grant
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "DeviceTokenRequest",
    "DeviceTokenResponse",
    # Discovery
    "DiscoveryDocumentRequest",
    "DiscoveryDocumentResponse",
    "JsonWebAlgorithmsKeyTypes",
    "JsonWebKey",
    "JsonWebKeyParameterNames",
    "JwksRequest",
    "JwksResponse",
    # Pushed Authorization Request
    "PushedAuthorizationRequest",
    "PushedAuthorizationResponse",
    # Refresh Token
    "RefreshTokenRequest",
    "RefreshTokenResponse",
    # Token Exchange
    "TokenExchangeRequest",
    "TokenExchangeResponse",
    # Token Introspection
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    # Token Revocation
    "TokenRevocationRequest",
    "TokenRevocationResponse",
    # Token Validation
    "TokenValidationConfig",
    # UserInfo
    "UserInfoRequest",
    "UserInfoResponse",
]
