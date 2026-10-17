"""
Exception hierarchy for py-identity-model.

This module defines a comprehensive exception hierarchy for all errors
that can occur during OAuth 2.0 and OpenID Connect operations.
"""

from __future__ import annotations


class PyIdentityModelException(Exception):
    """Base exception for all py-identity-model errors."""

    def __init__(self, message: str, details: dict | None = None):
        """
        Initialize a PyIdentityModelException.

        Args:
            message: The error message.
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationException(PyIdentityModelException):
    """Raised when validation fails."""


class TokenValidationException(ValidationException):
    """Raised when token validation fails."""

    def __init__(
        self,
        message: str,
        token_part: str | None = None,
        details: dict | None = None,
    ):
        """
        Initialize a TokenValidationException.

        Args:
            message: The error message.
            token_part: The part of the token that failed validation
                       ('header', 'payload', or 'signature').
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message, details)
        self.token_part = token_part


class SignatureVerificationException(TokenValidationException):
    """Raised when token signature verification fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="signature", details=details)


class TokenExpiredException(TokenValidationException):
    """Raised when token has expired."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class InvalidAudienceException(TokenValidationException):
    """Raised when audience validation fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class InvalidIssuerException(TokenValidationException):
    """Raised when issuer validation fails."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class KeyNotFoundException(TokenValidationException):
    """Raised when no signing key in the JWK Set can verify a token.

    Only keys whose ``use`` is absent or ``sig`` are signing keys
    (RFC 7517 §4.2); a ``use: enc`` key is never used to verify a signature.
    Raised for a ``kid`` that names no signing key, after the forced JWKS
    refresh a kid miss triggers, and for a token with no ``kid`` when the set
    holds no signing key. ``details["kid"]`` is the header ``kid`` (``None``
    when absent) and ``details["available_kids"]`` the signing keys' ids.
    """

    def __init__(self, message: str, kid: str | None, available_kids: list):
        super().__init__(
            message,
            token_part="header",
            details={"kid": kid, "available_kids": available_kids},
        )


class AmbiguousKeyException(TokenValidationException):
    """Raised when a token with no ``kid`` matches more than one JWK.

    With no ``kid`` in the JOSE header, only signing keys (``use`` absent or
    ``sig``, RFC 7517 §4.2) are candidates; they are narrowed to keys whose
    ``alg`` is absent or equals the header ``alg`` (§4.4) and whose ``kty``
    matches it, each of those two steps applied only when it leaves a key.
    More than one key left means the verification key cannot be chosen. This
    is distinct from :class:`KeyNotFoundException`, raised when no signing
    key matches.
    ``details["available_kids"]`` lists the remaining keys' ids and
    ``details["key_count"]`` their number.
    """

    def __init__(self, message: str, available_kids: list, key_count: int):
        super().__init__(
            message,
            token_part="header",
            details={"available_kids": available_kids, "key_count": key_count},
        )


class KeyAlgorithmMismatchException(TokenValidationException):
    """Raised when the key chosen to verify a token declares another ``alg``.

    A JWK that declares ``alg`` is meant for that algorithm only
    (RFC 7517 §4.4), so a token whose header ``alg`` differs is not verified
    with it, whether the key was found by ``kid`` or selected without one.
    ``details`` carries the key's ``kid`` and ``key_alg`` and the token's
    ``jwt_alg``.
    """


class WeakKeyException(TokenValidationException):
    """Raised when the key chosen to verify a token is below the strength floor.

    An RSA key needs a modulus of at least 2048 bits (RFC 7518 §3.3, §3.5) and
    an EC key a coordinate of at least 224 bits (FAPI 2.0 Security Profile
    §5.4.1). OKP keys have a fixed size and no floor. The key is not skipped:
    choosing it and finding it too weak fails validation, with no JWK Set
    refresh. ``details`` holds the key's ``kid`` (``None`` when absent),
    ``kty``, its size in ``bits`` and the ``min_bits`` it needed.
    """

    def __init__(
        self, message: str, kid: str | None, kty: str, bits: int, min_bits: int
    ):
        super().__init__(
            message,
            token_part="header",
            details={"kid": kid, "kty": kty, "bits": bits, "min_bits": min_bits},
        )


class LogoutTokenValidationException(TokenValidationException):
    """Raised when Back-Channel Logout token validation fails.

    Covers the Logout-Token-specific rules from OpenID Connect Back-Channel
    Logout 1.0 §2.4 (required ``events`` member, ``sub``/``sid`` presence, and
    the ``nonce`` prohibition) that sit on top of standard JWT validation.
    """


class IdTokenValidationException(TokenValidationException):
    """Raised when OpenID Connect ID Token profile validation fails.

    Covers the ID-Token-specific rules from OpenID Connect Core 1.0 §3.1.3.7
    and §3.3.2.11 (required ``sub``, the opt-in ``azp`` authorized-party rules,
    ``nonce`` binding, ``auth_time``/``max_age`` freshness, and the
    ``at_hash``/``c_hash`` token/code binding) that sit on top of standard JWT
    validation.

    Subclasses ``TokenValidationException`` (mirroring
    ``LogoutTokenValidationException``) rather than ``ValidationException``
    directly: an ID-Token profile failure is a token-validation failure, so
    callers using the idiomatic ``except TokenValidationException`` fail
    **closed** on it. As a sibling it would escape that handler and fail open.
    """


class UntrustedAudienceException(IdTokenValidationException):
    """Raised when an ID Token carries an audience the client does not trust.

    OpenID Connect Core 1.0 §3.1.3.7 step 3: the ID Token MUST be rejected if
    it contains additional audiences not trusted by the Client. The trusted
    set is the client's ``client_id`` plus any caller-supplied
    ``trusted_audiences``. ``details["untrusted_audiences"]`` lists the
    rejected values.
    """

    def __init__(self, message: str, untrusted_audiences: list):
        super().__init__(
            message,
            token_part="payload",
            details={"untrusted_audiences": untrusted_audiences},
        )


class LogoutStateValidationException(ValidationException):
    """Raised when the ``state`` returned to the post-logout redirect URI
    does not match the value sent to the end-session endpoint.

    Covers the RP-Initiated Logout ``state`` round-trip check (OpenID Connect
    RP-Initiated Logout 1.0 §2/§3). It is a plain callback CSRF check — not a
    JWT/token error — so it subclasses ``ValidationException`` directly rather
    than ``TokenValidationException``.
    """


class AuthorizeCallbackException(ValidationException):
    """Raised when authorization callback validation fails."""


class JarmValidationException(AuthorizeCallbackException):
    """Raised when JWT-Secured Authorization Response Mode (JARM) processing fails.

    Covers JARM-specific failures (JARM §4): a missing ``response`` parameter,
    a rejected signing algorithm (``none``/symmetric/not-advertised), or a
    response JWT missing a mandatory ``iss``/``aud``/``exp`` claim. Signature,
    issuer, audience, and expiry mismatches surface as the underlying
    ``TokenValidationException`` subclasses (``SignatureVerificationException``,
    ``InvalidIssuerException``, ``InvalidAudienceException``,
    ``TokenExpiredException``) raised by the shared JWT decoder.

    Subclasses ``AuthorizeCallbackException`` because a JARM failure is an
    authorization-callback processing error.
    """


class CertificateBindingError(TokenValidationException):
    """Raised when mTLS certificate-bound access token validation fails.

    Covers the RFC 8705 §3 confirmation-method check: the token's
    ``cnf["x5t#S256"]`` thumbprint must match the client certificate
    presented at the TLS layer. Absent ``cnf``/``x5t#S256`` or a thumbprint
    mismatch raises this error.

    Subclasses ``TokenValidationException`` (not ``ValidationException``
    directly): a certificate-binding failure is a token-validation failure,
    so callers using the idiomatic ``except TokenValidationException`` must
    fail **closed** on it. As a sibling it would escape that handler and
    fail open — the exact replay it is meant to stop.
    """

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, token_part="payload", details=details)


class NetworkException(PyIdentityModelException):
    """Raised when network operations fail."""

    def __init__(
        self,
        message: str,
        url: str | None = None,
        status_code: int | None = None,
        details: dict | None = None,
    ):
        """
        Initialize a NetworkException.

        Args:
            message: The error message.
            url: The URL that was being accessed when the error occurred.
            status_code: The HTTP status code if available.
            details: Optional dictionary containing additional error context.
        """
        super().__init__(message, details)
        self.url = url
        self.status_code = status_code


class DiscoveryException(NetworkException):
    """Raised when discovery document cannot be fetched or parsed."""


class DiscoveryParseError(DiscoveryException):
    """The discovery response could not be decoded as JSON."""


class DiscoveryMissingFieldsError(DiscoveryException):
    """Discovery validation rejected these missing fields."""

    def __init__(self, message: str, fields: tuple[str, ...]) -> None:
        super().__init__(message)
        self.fields = fields


class DiscoveryIssuerMismatchError(DiscoveryException):
    """The document's issuer differs from the requested issuer."""

    def __init__(self, requested: str, returned: str) -> None:
        super().__init__(
            f"Discovery document issuer {returned!r} does not match "
            f"the requested issuer {requested!r}"
        )
        self.requested = requested
        self.returned = returned


class JwksException(NetworkException):
    """Raised when JWKS cannot be fetched or parsed."""


class TokenRequestException(NetworkException):
    """Raised when token request fails."""


class UserInfoException(NetworkException):
    """Raised when UserInfo request fails."""


class ConfigurationException(PyIdentityModelException):
    """Raised when configuration is invalid or incomplete."""


class DiscoveryHTTPSRequiredError(ConfigurationException):
    """A discovery URL violates the HTTPS requirement."""


class AzpRequiresClientIdError(ConfigurationException):
    """``validate_azp`` was enabled without a ``client_id`` to compare against.

    OIDC Core 1.0 §3.1.3.7 step 5 compares a present ``azp`` with the
    client's own ``client_id``; with none configured the check cannot run as
    asked, so it is a caller misconfiguration rather than a token defect.
    """

    def __init__(self) -> None:
        super().__init__(
            "validate_azp requires a client_id (the token validation audience) "
            "to compare 'azp' against"
        )


class FailedResponseAccessError(PyIdentityModelException):
    """Raised when accessing data fields on a failed response."""

    def __init__(self, field_name: str, error: str | None = None):
        error_detail = f": {error}" if error else ""
        message = (
            f"Cannot access '{field_name}' on a failed response{error_detail}. "
            f"Check 'is_successful' before accessing response data."
        )
        super().__init__(message)
        self.field_name = field_name


class SuccessfulResponseAccessError(PyIdentityModelException):
    """Raised when accessing the error field on a successful response."""

    def __init__(self, field_name: str = "error"):
        message = (
            f"Cannot access '{field_name}' on a successful response. "
            f"Check 'is_successful' before accessing error details."
        )
        super().__init__(message)
        self.field_name = field_name


__all__ = [
    "AmbiguousKeyException",
    "AuthorizeCallbackException",
    "AzpRequiresClientIdError",
    "CertificateBindingError",
    "ConfigurationException",
    "DiscoveryException",
    "DiscoveryHTTPSRequiredError",
    "DiscoveryIssuerMismatchError",
    "DiscoveryMissingFieldsError",
    "DiscoveryParseError",
    "FailedResponseAccessError",
    "IdTokenValidationException",
    "InvalidAudienceException",
    "InvalidIssuerException",
    "JarmValidationException",
    "JwksException",
    "KeyAlgorithmMismatchException",
    "KeyNotFoundException",
    "LogoutStateValidationException",
    "LogoutTokenValidationException",
    "NetworkException",
    "PyIdentityModelException",
    "SignatureVerificationException",
    "SuccessfulResponseAccessError",
    "TokenExpiredException",
    "TokenRequestException",
    "TokenValidationException",
    "UntrustedAudienceException",
    "UserInfoException",
    "ValidationException",
    "WeakKeyException",
]
