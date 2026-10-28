"""
Mutual-TLS (mTLS) client authentication and certificate-bound access tokens
per RFC 8705.

Provides:

- ``compute_certificate_thumbprint`` / ``certificate_thumbprint_from_file`` —
  the RFC 8705 §3.1 ``x5t#S256`` value (base64url-no-pad SHA-256 over the
  certificate DER), mirroring the DPoP thumbprint shape in :mod:`.dpop`.
- ``validate_certificate_binding`` — RFC 8705 §3 confirmation-method check that
  a certificate-bound access token's ``cnf["x5t#S256"]`` matches the client
  certificate presented at the TLS layer.
- ``apply_mtls_client_auth`` — injects ``client_id`` into the request body for
  the ``tls_client_auth`` / ``self_signed_tls_client_auth`` methods (RFC 8705
  §2: the certificate is presented at the TLS layer, so no ``Authorization``
  header is used).
- ``build_httpx_cert`` — turns an :class:`MtlsClientAuth` config into the value
  for httpx's client-construction ``cert=`` argument.
- ``resolve_mtls_endpoint`` — routes an endpoint through
  ``mtls_endpoint_aliases`` (RFC 8705 §5) when the AS advertises one.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
import hmac
from pathlib import Path
import ssl
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..exceptions import CertificateBindingError
from ..jwt_claim_types import ConfirmationMethods, JwtClaimTypes
from ..oidc_constants import TokenRequest


if TYPE_CHECKING:
    from .config import Config
    from .models import DiscoveryDocumentResponse, MtlsClientAuth


def _load_certificate(cert: str | bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER content.

    Args:
        cert: Certificate content — a PEM string/bytes or DER bytes. A ``str``
            is UTF-8 encoded before loading.

    Returns:
        The parsed :class:`cryptography.x509.Certificate`.

    Raises:
        ValueError: If *cert* is empty or cannot be parsed as PEM or DER.
    """
    if not cert or (isinstance(cert, str) and not cert.strip()):
        raise ValueError("certificate must not be empty")

    cert_bytes = cert.encode("utf-8") if isinstance(cert, str) else cert

    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(cert_bytes)
    except ValueError:
        raise ValueError("certificate is not valid PEM or DER X.509 content") from None


def compute_certificate_thumbprint(cert: str | bytes) -> str:
    """Compute the RFC 8705 §3.1 ``x5t#S256`` certificate thumbprint.

    The value is the base64url-encoded (no padding) SHA-256 hash of the
    certificate's DER encoding, matching the ``cnf["x5t#S256"]`` member of a
    certificate-bound access token.

    Args:
        cert: Client certificate content — PEM (``str``/``bytes``) or DER
            (``bytes``).

    Returns:
        The base64url-no-pad SHA-256 thumbprint string.

    Raises:
        ValueError: If *cert* is empty or not a valid certificate.
    """
    certificate = _load_certificate(cert)
    digest = certificate.fingerprint(hashes.SHA256())
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def certificate_thumbprint_from_file(path: str) -> str:
    """Compute the ``x5t#S256`` thumbprint of a certificate file.

    Args:
        path: Filesystem path to a PEM- or DER-encoded certificate.

    Returns:
        The base64url-no-pad SHA-256 thumbprint string.

    Raises:
        ValueError: If *path* is empty or the file is not a valid certificate.
        OSError: If the file cannot be read.
    """
    if not path or not path.strip():
        raise ValueError("path must not be empty")
    with Path(path).open("rb") as fh:
        return compute_certificate_thumbprint(fh.read())


def validate_certificate_binding(claims: dict, cert: str | bytes) -> None:
    """Validate an RFC 8705 §3 certificate-bound access token confirmation.

    Confirms the token's ``cnf["x5t#S256"]`` confirmation method matches the
    SHA-256 thumbprint of the client certificate presented at the TLS layer.
    The comparison is constant-time.

    Args:
        claims: Decoded access-token claims (must already be signature- and
            time-validated by the caller).
        cert: The client certificate presented on the mTLS connection — PEM
            (``str``/``bytes``) or DER (``bytes``).

    Raises:
        CertificateBindingError: If the ``cnf`` claim or its ``x5t#S256``
            member is absent, or the thumbprint does not match.
        ValueError: If *cert* is empty or not a valid certificate.
    """
    cnf = claims.get(JwtClaimTypes.Confirmation.value)
    if not isinstance(cnf, dict):
        raise CertificateBindingError(
            "Access token is not certificate-bound: missing 'cnf' claim "
            "(RFC 8705 Section 3.1)"
        )

    bound_thumbprint = cnf.get(ConfirmationMethods.X509ThumbprintSha256.value)
    if not bound_thumbprint or not isinstance(bound_thumbprint, str):
        raise CertificateBindingError(
            "Access token 'cnf' claim has no 'x5t#S256' certificate "
            "thumbprint (RFC 8705 Section 3.1)"
        )

    # A genuine base64url-no-pad thumbprint is always ASCII. Reject non-ASCII
    # values explicitly so the fail-closed contract holds: without this guard a
    # crafted token whose thumbprint contains non-ASCII characters makes
    # ``hmac.compare_digest`` raise ``TypeError`` instead of the documented
    # ``CertificateBindingError``, escaping callers that catch only the latter.
    if not bound_thumbprint.isascii():
        raise CertificateBindingError(
            "Access token 'cnf[x5t#S256]' is not a valid base64url thumbprint "
            "(non-ASCII characters) (RFC 8705 Section 3.1)"
        )

    presented_thumbprint = compute_certificate_thumbprint(cert)
    if not hmac.compare_digest(bound_thumbprint, presented_thumbprint):
        raise CertificateBindingError(
            "Certificate binding mismatch: token 'cnf[x5t#S256]' does not "
            "match the presented client certificate (RFC 8705 Section 3)"
        )


def apply_mtls_client_auth(params: dict[str, str], *, client_id: str) -> None:
    """Inject mTLS client authentication into *params* in place.

    For ``tls_client_auth`` / ``self_signed_tls_client_auth`` (RFC 8705 §2),
    the client certificate is presented at the TLS layer and ``client_id`` is
    carried in the request body; no ``Authorization`` header is used.

    Args:
        params: Request body parameters to mutate in place.
        client_id: The client identifier.
    """
    params[TokenRequest.CLIENT_ID.value] = client_id


def build_httpx_cert(mtls: MtlsClientAuth) -> tuple[str, str] | tuple[str, str, str]:
    """Build the value for httpx's client-construction ``cert=`` argument.

    Args:
        mtls: The mTLS client-authentication configuration.

    Returns:
        ``(certificate, private_key)`` — or ``(certificate, private_key,
        password)`` when :attr:`MtlsClientAuth.password` is set. Each element
        is a filesystem path to a PEM file, as required by httpx.
    """
    if mtls.password is not None:
        return (mtls.certificate, mtls.private_key, mtls.password)
    return (mtls.certificate, mtls.private_key)


def build_mtls_ssl_context(mtls: MtlsClientAuth, config: Config) -> ssl.SSLContext:
    """Build an ``ssl.SSLContext`` that presents the client certificate.

    httpx 0.28 no longer reliably applies a ``cert=`` argument when ``verify``
    is a CA-bundle *path* (only when it is ``False`` or an ``SSLContext``), so an
    mTLS client that also verifies the server against a custom CA would silently
    fail to present its certificate. Build the context explicitly instead:
    verify the server against ``config.ca_bundle`` (or the default store) and
    load the client certificate for RFC 8705 mutual-TLS authentication.
    """
    if config.ca_bundle is not None:
        context = ssl.create_default_context(cafile=config.ca_bundle)
    else:
        context = ssl.create_default_context()
    if mtls.password is not None:
        context.load_cert_chain(mtls.certificate, mtls.private_key, mtls.password)
    else:
        context.load_cert_chain(mtls.certificate, mtls.private_key)
    return context


def resolve_mtls_endpoint(
    disco: DiscoveryDocumentResponse,
    endpoint: str,
) -> str | None:
    """Resolve *endpoint* through ``mtls_endpoint_aliases`` when advertised.

    Per RFC 8705 §5, an authorization server may advertise mTLS-specific
    endpoint URLs in ``mtls_endpoint_aliases``. When a matching alias exists
    for *endpoint*, it is returned; otherwise *endpoint* is returned unchanged.
    Request models take an explicit ``address``, so call this when building
    one for an mTLS client; ``FAPI2ClientProfile`` applies it to every PAR,
    token and refresh request it builds for an mTLS client.

    Args:
        disco: The authorization server's discovery document.
        endpoint: The endpoint name to resolve (e.g. ``"token_endpoint"``).

    Returns:
        The mTLS endpoint URL alias when present, else the standard endpoint
        URL from the discovery document (``None`` if neither is set).
    """
    aliases = disco.mtls_endpoint_aliases
    if isinstance(aliases, dict):
        alias = aliases.get(endpoint)
        if alias:
            return alias
    return getattr(disco, endpoint, None)


__all__ = [
    "apply_mtls_client_auth",
    "build_httpx_cert",
    "build_mtls_ssl_context",
    "certificate_thumbprint_from_file",
    "compute_certificate_thumbprint",
    "resolve_mtls_endpoint",
    "validate_certificate_binding",
]
