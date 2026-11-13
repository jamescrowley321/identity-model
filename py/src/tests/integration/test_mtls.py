"""Integration tests for mutual-TLS client authentication and
certificate-bound access tokens (RFC 8705).

These tests hit a live OIDC provider. The RFC 8705 §5 discovery metadata is
verified against the real provider through the typed
``DiscoveryDocumentResponse``. The mTLS authentication flow and cert-bound
token confirmation require a provider that terminates TLS with client-cert
verification; the local node-oidc-provider fixture serves plain HTTP and does
not enable the mTLS feature, so those tests are gated on the ``mtls``
capability and skip with a documented gap (mirroring the T126 IdentityServer
provider-gap precedent). They run automatically against any configured provider
that advertises mTLS support.
"""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from py_identity_model import (
    CertificateBindingError,
    ClientCredentialsTokenRequest,
    MtlsClientAuth,
    TokenValidationException,
    compute_certificate_thumbprint,
    request_client_credentials_token,
    validate_certificate_binding,
)
from py_identity_model.core.mtls import resolve_mtls_endpoint


def _self_signed_cert() -> tuple[bytes, bytes]:
    """Generate a self-signed X.509 cert; return ``(cert_pem, key_pem)``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "integration-client")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@pytest.mark.integration
class TestMtlsDiscoveryMetadata:
    """RFC 8705 §5 discovery metadata parses from the live provider."""

    def test_mtls_discovery_fields_present_on_typed_response(self, discovery_document):
        """The typed response exposes the RFC 8705 discovery fields.

        This exercises the real discovery fetch + parse path end-to-end.
        Providers that do not support mTLS simply return ``None`` for both.
        """
        assert discovery_document.is_successful
        # Attributes must exist and be either None or the advertised value —
        # accessing them must not raise (guards allow it on a success response).
        aliases = discovery_document.mtls_endpoint_aliases
        bound = discovery_document.tls_client_certificate_bound_access_tokens
        assert aliases is None or isinstance(aliases, dict)
        assert bound is None or isinstance(bound, bool)

    def test_resolve_mtls_endpoint_against_live_discovery(self, discovery_document):
        """``resolve_mtls_endpoint`` returns a usable token endpoint URL.

        Falls back to the standard ``token_endpoint`` when the provider
        advertises no ``mtls_endpoint_aliases``.
        """
        resolved = resolve_mtls_endpoint(discovery_document, "token_endpoint")
        assert resolved == discovery_document.token_endpoint
        assert resolved is not None
        assert resolved.startswith("http")


@pytest.mark.integration
class TestMtlsClientAuthLive:
    """mTLS client authentication against a provider that supports it.

    Gap: the node-oidc-provider fixture serves plain HTTP and does not enable
    the mTLS feature, so a real client-cert handshake cannot be performed
    against it. These tests skip on that provider and run against any
    configured provider advertising mTLS (see T126 IdentityServer-gap
    precedent for the provider-gap pattern).
    """

    def test_mtls_client_credentials(
        self, provider_capabilities, discovery_document, test_config
    ):
        if "mtls" not in provider_capabilities:
            pytest.skip(
                "Provider does not support mTLS (RFC 8705): serves plain HTTP / "
                "does not advertise tls_client_auth or mtls_endpoint_aliases"
            )

        cert_path = test_config.get("TEST_MTLS_CERT")
        key_path = test_config.get("TEST_MTLS_KEY")
        client_id = test_config.get("TEST_MTLS_CLIENT_ID")
        if not (cert_path and key_path and client_id):
            pytest.skip("TEST_MTLS_CERT / TEST_MTLS_KEY / TEST_MTLS_CLIENT_ID not set")

        token_endpoint = resolve_mtls_endpoint(discovery_document, "token_endpoint")
        assert token_endpoint is not None
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                address=token_endpoint,
                client_id=client_id,
                scope=test_config.get("TEST_SCOPE", "openid"),
                mtls=MtlsClientAuth(
                    certificate_path=cert_path, private_key_path=key_path
                ),
            )
        )

        assert response.is_successful is True, f"mTLS token failed: {response.error}"
        assert response.token
        assert response.token.get("access_token")


@pytest.mark.integration
class TestCertificateBoundTokenValidation:
    """RFC 8705 §3 cert-bound token confirmation.

    The confirmation check is RP-side and does not require a real handshake:
    it compares the token's ``cnf[x5t#S256]`` to the SHA-256 thumbprint of the
    client certificate. This exercises the validation against a real X.509
    certificate parsed by the cryptography backend.
    """

    def test_matching_binding_accepts(self):
        cert_pem, _ = _self_signed_cert()
        thumbprint = compute_certificate_thumbprint(cert_pem)
        # A token whose cnf matches the presented cert must validate.
        validate_certificate_binding({"cnf": {"x5t#S256": thumbprint}}, cert_pem)

    def test_mismatched_binding_rejected(self):
        cert_pem, _ = _self_signed_cert()
        other_pem, _ = _self_signed_cert()
        other_thumbprint = compute_certificate_thumbprint(other_pem)
        with pytest.raises(CertificateBindingError):
            # A token bound to a different certificate must be rejected.
            validate_certificate_binding(
                {"cnf": {"x5t#S256": other_thumbprint}}, cert_pem
            )

    def test_binding_mismatch_fails_closed_for_generic_handler(self):
        """A resource server using the idiomatic ``except TokenValidationException``
        must fail CLOSED on a cert-binding mismatch.

        This is the behavioural proof of the exception-contract fix: because
        ``CertificateBindingError`` was a *sibling* of ``TokenValidationException``,
        a real RS handler that denies on ``TokenValidationException`` let a binding
        mismatch escape and fail OPEN — accepting a stolen bound token as a bearer.
        Exercised against a real X.509 cert + SHA-256 thumbprint, mirroring how an
        RS confirms RFC 8705 §3 on a live token.
        """
        cert_pem, _ = _self_signed_cert()
        other_pem, _ = _self_signed_cert()
        other_thumbprint = compute_certificate_thumbprint(other_pem)

        denied = False
        try:
            # Stolen cert-bound token replayed with the wrong client certificate.
            validate_certificate_binding(
                {"cnf": {"x5t#S256": other_thumbprint}}, cert_pem
            )
        except TokenValidationException:
            # The RS's generic token-validation handler caught it -> 401 deny.
            denied = True
        assert denied, (
            "cert-binding mismatch escaped `except TokenValidationException` and "
            "would fail open (stolen bound token accepted as bearer)"
        )
