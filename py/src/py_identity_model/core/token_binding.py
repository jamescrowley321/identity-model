"""
Sender-constrained access tokens at the resource server.

A resource server that receives a bound token must check the binding: a
DPoP-bound token (``cnf.jkt``, RFC 9449 §6.1) needs the ``DPoP`` scheme and a
proof signed by the bound key (§7.1); a certificate-bound token
(``cnf["x5t#S256"]``, RFC 8705 §3) needs the client certificate it is bound to.

``validate_token`` runs :func:`check_token_binding` when it is given a
:class:`TokenPresentation` (how the token arrived on the request).
``TokenValidationConfig.required_binding`` refuses tokens without the named
binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import enum
from typing import TYPE_CHECKING

from ..exceptions import CertificateBindingError, ConfigurationException
from ..jwt_claim_types import ConfirmationMethods, JwtClaimTypes
from .dpop_verify import (
    DPoPErrorKind,
    DPoPProofRequest,
    DPoPValidationError,
    DPoPVerificationOptions,
    verify_dpop_proof,
)
from .mtls import validate_certificate_binding


if TYPE_CHECKING:
    from .models import TokenValidationConfig


PRESENTATION_REQUIRED = (
    "needs the request's presentation= (scheme, method, url, DPoP proof or "
    "client certificate)"
)
PROOF_REQUEST_MESSAGE = (
    "presentation.method and presentation.url are needed to verify a DPoP proof"
)
NO_CERTIFICATE_MESSAGE = (
    "required_binding=mtls but no client certificate was presented (RFC 8705 §3)"
)


class TokenBinding(enum.Enum):
    """The sender constraint a resource server requires of every token."""

    NONE = "none"
    """No binding required. A bound token is still checked when a
    :class:`TokenPresentation` is given."""
    DPOP = "dpop"
    """Only DPoP-bound tokens (``cnf.jkt``) with a valid proof (RFC 9449)."""
    MTLS = "mtls"
    """Only certificate-bound tokens (``cnf["x5t#S256"]``) presented over mTLS
    with the bound certificate (RFC 8705 §3)."""


class AuthorizationScheme(enum.Enum):
    """The ``Authorization`` header scheme the access token arrived with."""

    BEARER = "Bearer"
    """RFC 6750 §2.1."""
    DPOP = "DPoP"
    """RFC 9449 §7.1."""


@dataclass(frozen=True)
class TokenPresentation:
    """How an access token was presented on one request.

    Attributes:
        scheme: The ``Authorization`` scheme.
        method: The request's HTTP method (needed to verify a DPoP proof).
        url: The request's absolute URI, as the client addressed it (needed to
            verify a DPoP proof). Behind a proxy, use the external URI.
        dpop_proof: The ``DPoP`` header value, if any.
        client_certificate: The client certificate from the mTLS connection
            (PEM or DER), if any.
        expected_nonce: The DPoP nonce the server requires, if it enforces
            one (RFC 9449 §9).
    """

    scheme: AuthorizationScheme
    method: str | None = None
    url: str | None = None
    dpop_proof: str | None = None
    client_certificate: str | bytes | None = None
    expected_nonce: str | None = None


def require_presentation(
    config: TokenValidationConfig, presentation: TokenPresentation | None
) -> None:
    """Refuse a required binding with no presentation to check it against.

    Raises:
        ConfigurationException: If ``config.required_binding`` is not
            ``NONE`` and *presentation* is ``None``.
    """
    if presentation is None and config.required_binding is not TokenBinding.NONE:
        raise ConfigurationException(
            f"required_binding={config.required_binding.value} {PRESENTATION_REQUIRED}"
        )


def _check_dpop_binding(
    jkt: object,
    access_token: str,
    presentation: TokenPresentation,
    options: DPoPVerificationOptions | None,
) -> None:
    if presentation.scheme is not AuthorizationScheme.DPOP:
        raise DPoPValidationError(DPoPErrorKind.WRONG_SCHEME)
    if not presentation.dpop_proof:
        raise DPoPValidationError(DPoPErrorKind.PROOF_REQUIRED)
    # A non-string cnf.jkt (null included) can match no key; it must not reach
    # the verifier as "no expected jkt".
    if not isinstance(jkt, str):
        raise DPoPValidationError(DPoPErrorKind.JKT_MISMATCH)
    if presentation.method is None or presentation.url is None:
        raise ValueError(PROOF_REQUEST_MESSAGE)
    request = DPoPProofRequest(
        method=presentation.method,
        url=presentation.url,
        access_token=access_token,
        expected_jkt=jkt,
        expected_nonce=presentation.expected_nonce,
    )
    verify_dpop_proof(presentation.dpop_proof, request, options)


def check_token_binding(
    claims: dict,
    access_token: str,
    config: TokenValidationConfig,
    presentation: TokenPresentation | None,
) -> None:
    """Check the token's sender constraint against how it was presented.

    With no *presentation* nothing is checked (call
    :func:`require_presentation` first). Otherwise:

    - ``cnf.jkt`` present: the scheme must be ``DPoP`` and the proof must
      verify for this request and token, with the bound key (RFC 9449 §7.1).
    - no ``cnf.jkt``: the ``DPoP`` scheme, or ``required_binding=DPOP``, is
      refused as ``NOT_BOUND``.
    - ``required_binding=MTLS``: the client certificate must be present and
      match ``cnf["x5t#S256"]`` (RFC 8705 §3). Without that requirement a
      certificate-bound token is checked whenever a certificate is given.

    Args:
        claims: The decoded, signature-validated token claims.
        access_token: The access token as received.
        config: The validation config (``required_binding``, ``dpop``).
        presentation: How the token arrived, or ``None``.

    Raises:
        DPoPValidationError: If the DPoP binding fails.
        CertificateBindingError: If the certificate binding fails.
        ValueError: If a DPoP proof is checked without an absolute
            ``presentation.url`` or a ``presentation.method``.
    """
    if presentation is None:
        return
    cnf = claims.get(JwtClaimTypes.Confirmation.value)
    cnf = cnf if isinstance(cnf, dict) else {}
    binding = config.required_binding

    jkt_member = ConfirmationMethods.JwkThumbprint.value
    if jkt_member in cnf:
        _check_dpop_binding(cnf[jkt_member], access_token, presentation, config.dpop)
    elif (
        binding is TokenBinding.DPOP or presentation.scheme is AuthorizationScheme.DPOP
    ):
        raise DPoPValidationError(DPoPErrorKind.NOT_BOUND)

    certificate = presentation.client_certificate
    if binding is TokenBinding.MTLS:
        if certificate is None:
            raise CertificateBindingError(NO_CERTIFICATE_MESSAGE)
        validate_certificate_binding(claims, certificate)
    elif (
        certificate is not None
        and ConfirmationMethods.X509ThumbprintSha256.value in cnf
    ):
        validate_certificate_binding(claims, certificate)


__all__ = [
    "AuthorizationScheme",
    "TokenBinding",
    "TokenPresentation",
    "check_token_binding",
    "require_presentation",
]
