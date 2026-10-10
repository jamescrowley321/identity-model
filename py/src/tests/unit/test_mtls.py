"""Unit tests for mutual-TLS client authentication and certificate-bound
access tokens (RFC 8705).

respx cannot perform a real mTLS handshake, so the network-facing tests assert
that the certificate is plumbed through the HTTP client and that the request
body/auth precedence is correct; the ``cnf`` binding and thumbprint logic are
exercised in isolation.
"""

from base64 import urlsafe_b64encode
from datetime import UTC, datetime
import ssl
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    CertificateBindingError,
    ClientCredentialsTokenRequest,
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
    DiscoveryDocumentRequest,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    TokenExchangeRequest,
    TokenIntrospectionRequest,
    TokenRevocationRequest,
    TokenValidationException,
    certificate_thumbprint_from_file,
    compute_certificate_thumbprint,
    get_discovery_document,
    request_authorization_code_token,
    request_client_credentials_token,
    validate_certificate_binding,
)
from py_identity_model.aio import (
    request_client_credentials_token as async_request_client_credentials_token,
)
import py_identity_model.aio.http_client as aio_http
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.core.device_auth_logic import (
    prepare_device_auth_request_data,
    prepare_device_token_request_data,
)
from py_identity_model.core.introspection_logic import (
    prepare_introspection_request_data,
)
from py_identity_model.core.models import DiscoveryDocumentResponse
from py_identity_model.core.mtls import (
    apply_mtls_client_auth,
    build_httpx_cert,
    build_mtls_ssl_context,
    resolve_mtls_endpoint,
)
from py_identity_model.core.par_logic import prepare_par_request_data
from py_identity_model.core.revocation_logic import prepare_revocation_request_data
from py_identity_model.core.token_client_logic import (
    prepare_auth_code_token_request_data,
    prepare_refresh_token_request_data,
    prepare_token_request_data,
)
from py_identity_model.core.token_exchange_logic import (
    prepare_token_exchange_request_data,
)
import py_identity_model.sync.http_client as sync_http
from py_identity_model.sync.managed_client import HTTPClient


ADDR = "https://as.example.com/endpoint"
TOKEN_URL = "https://as.example.com/token"


def _make_cert() -> tuple[bytes, bytes]:
    """Generate a self-signed X.509 cert; return ``(cert_pem, key_pem)``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-client")])
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


@pytest.fixture(scope="module")
def cert_pem() -> bytes:
    """A stable self-signed certificate (PEM) shared across the module."""
    return _make_cert()[0]


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory) -> tuple[str, str, bytes]:
    """Write a cert/key pair to disk; return ``(cert_path, key_path, cert_pem)``."""
    cert_pem, key_pem = _make_cert()
    d = tmp_path_factory.mktemp("mtls")
    cert_path = d / "client.crt"
    key_path = d / "client.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return str(cert_path), str(key_path), cert_pem


@pytest.fixture
def mtls(cert_files) -> MtlsClientAuth:
    cert_path, key_path, _ = cert_files
    return MtlsClientAuth(certificate=cert_path, private_key=key_path)


@pytest.mark.unit
class TestBuildMtlsSslContext:
    """build_mtls_ssl_context builds a context that presents the client cert.

    httpx 0.28 does not apply ``cert=`` when ``verify`` is a CA-path string, so
    the mTLS client must supply a fully-built SSLContext instead.
    """

    def test_returns_ssl_context_with_client_cert_loaded(self, mtls):
        # load_cert_chain would raise if the cert/key failed to load.
        assert isinstance(build_mtls_ssl_context(mtls), ssl.SSLContext)

    def test_verify_false_disables_server_verification(self, mtls, monkeypatch):
        monkeypatch.setattr("py_identity_model.core.mtls.get_ssl_verify", lambda: False)
        ctx = build_mtls_ssl_context(mtls)
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False

    def test_verify_cafile_requires_server_cert(self, mtls, cert_files, monkeypatch):
        # Reuse the client cert PEM path as a CA bundle to exercise the str path.
        monkeypatch.setattr(
            "py_identity_model.core.mtls.get_ssl_verify", lambda: cert_files[0]
        )
        assert build_mtls_ssl_context(mtls).verify_mode == ssl.CERT_REQUIRED


@pytest.mark.unit
class TestComputeCertificateThumbprint:
    def test_deterministic(self, cert_pem):
        assert compute_certificate_thumbprint(
            cert_pem
        ) == compute_certificate_thumbprint(cert_pem)

    def test_base64url_no_padding(self, cert_pem):
        tp = compute_certificate_thumbprint(cert_pem)
        assert "=" not in tp
        assert "+" not in tp
        assert "/" not in tp

    def test_matches_known_vector(self, cert_pem):
        """The value must equal base64url-no-pad SHA-256 over the cert DER."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        expected = (
            urlsafe_b64encode(cert.fingerprint(hashes.SHA256()))
            .rstrip(b"=")
            .decode("ascii")
        )
        assert compute_certificate_thumbprint(cert_pem) == expected

    def test_pem_str_and_bytes_agree(self, cert_pem):
        assert compute_certificate_thumbprint(
            cert_pem
        ) == compute_certificate_thumbprint(cert_pem.decode("ascii"))

    def test_pem_and_der_agree(self, cert_pem):
        der = x509.load_pem_x509_certificate(cert_pem).public_bytes(
            serialization.Encoding.DER
        )
        assert compute_certificate_thumbprint(
            cert_pem
        ) == compute_certificate_thumbprint(der)

    def test_distinct_certs_differ(self):
        pem_a, _ = _make_cert()
        pem_b, _ = _make_cert()
        assert compute_certificate_thumbprint(pem_a) != compute_certificate_thumbprint(
            pem_b
        )

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            compute_certificate_thumbprint("")

    def test_whitespace_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            compute_certificate_thumbprint("   ")

    def test_garbage_raises(self):
        with pytest.raises(ValueError, match="not valid PEM or DER"):
            compute_certificate_thumbprint("not-a-certificate")


@pytest.mark.unit
class TestCertificateThumbprintFromFile:
    def test_matches_in_memory(self, cert_files):
        cert_path, _, cert_pem = cert_files
        assert certificate_thumbprint_from_file(
            cert_path
        ) == compute_certificate_thumbprint(cert_pem)

    def test_empty_path_raises(self):
        with pytest.raises(ValueError, match="path must not be empty"):
            certificate_thumbprint_from_file("")

    def test_missing_file_raises_oserror(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            certificate_thumbprint_from_file(str(tmp_path / "nope.pem"))


@pytest.mark.unit
class TestValidateCertificateBinding:
    def test_matching_binding_passes(self, cert_pem):
        tp = compute_certificate_thumbprint(cert_pem)
        # No exception == pass.
        validate_certificate_binding({"cnf": {"x5t#S256": tp}}, cert_pem)

    def test_mismatched_thumbprint_raises(self, cert_pem):
        with pytest.raises(CertificateBindingError, match="mismatch"):
            validate_certificate_binding(
                {"cnf": {"x5t#S256": "not-the-right-thumbprint"}}, cert_pem
            )

    def test_wrong_cert_raises(self, cert_pem):
        """A token bound to a different cert must be rejected."""
        other_pem, _ = _make_cert()
        tp = compute_certificate_thumbprint(other_pem)
        with pytest.raises(CertificateBindingError, match="mismatch"):
            validate_certificate_binding({"cnf": {"x5t#S256": tp}}, cert_pem)

    def test_missing_cnf_raises(self, cert_pem):
        with pytest.raises(CertificateBindingError, match="missing 'cnf'"):
            validate_certificate_binding({"sub": "user"}, cert_pem)

    def test_cnf_not_dict_raises(self, cert_pem):
        with pytest.raises(CertificateBindingError, match="missing 'cnf'"):
            validate_certificate_binding({"cnf": "oops"}, cert_pem)

    def test_cnf_without_x5t_raises(self, cert_pem):
        """A DPoP-only cnf (jkt but no x5t#S256) must be rejected for mTLS."""
        with pytest.raises(CertificateBindingError, match="x5t#S256"):
            validate_certificate_binding({"cnf": {"jkt": "abc"}}, cert_pem)

    def test_x5t_not_string_raises(self, cert_pem):
        with pytest.raises(CertificateBindingError, match="x5t#S256"):
            validate_certificate_binding({"cnf": {"x5t#S256": 123}}, cert_pem)

    def test_non_ascii_x5t_raises_binding_error_not_typeerror(self, cert_pem):
        """A crafted non-ASCII thumbprint must fail closed as a
        CertificateBindingError, not escape as a TypeError from
        hmac.compare_digest (which cannot compare non-ASCII str)."""
        with pytest.raises(CertificateBindingError, match="base64url"):
            validate_certificate_binding({"cnf": {"x5t#S256": "abcé"}}, cert_pem)

    def test_binding_error_is_token_validation_exception(self, cert_pem):
        """A cert-binding failure must be catchable as ``TokenValidationException``
        so callers using the idiomatic ``except TokenValidationException`` fail
        CLOSED. Regression: ``CertificateBindingError`` was a *sibling* of
        ``TokenValidationException``, so such a handler let a binding failure
        escape and fail open — the exact replay the check is meant to stop."""
        assert issubclass(CertificateBindingError, TokenValidationException)
        with pytest.raises(TokenValidationException):
            validate_certificate_binding({"sub": "user"}, cert_pem)


@pytest.mark.unit
class TestApplyMtlsClientAuth:
    def test_sets_client_id(self):
        params: dict[str, str] = {"grant_type": "client_credentials"}
        apply_mtls_client_auth(params, client_id="my-client")
        assert params["client_id"] == "my-client"

    def test_no_assertion_or_secret_added(self):
        params: dict[str, str] = {}
        apply_mtls_client_auth(params, client_id="c")
        assert "client_assertion" not in params
        assert "client_secret" not in params


@pytest.mark.unit
class TestBuildHttpxCert:
    def test_two_tuple_without_password(self):
        cfg = MtlsClientAuth(certificate="/c.pem", private_key="/k.pem")
        assert build_httpx_cert(cfg) == ("/c.pem", "/k.pem")

    def test_three_tuple_with_password(self):
        cfg = MtlsClientAuth(
            certificate="/c.pem", private_key="/k.pem", password="hunter2"
        )
        assert build_httpx_cert(cfg) == ("/c.pem", "/k.pem", "hunter2")


@pytest.mark.unit
class TestResolveMtlsEndpoint:
    def _disco(self, **kwargs) -> DiscoveryDocumentResponse:
        return DiscoveryDocumentResponse(is_successful=True, **kwargs)

    def test_alias_used_when_present(self):
        disco = self._disco(
            token_endpoint="https://as/token",
            mtls_endpoint_aliases={"token_endpoint": "https://mtls.as/token"},
        )
        assert resolve_mtls_endpoint(disco, "token_endpoint") == "https://mtls.as/token"

    def test_falls_back_to_standard_when_alias_missing(self):
        disco = self._disco(
            token_endpoint="https://as/token",
            mtls_endpoint_aliases={"par_endpoint": "https://mtls.as/par"},
        )
        assert resolve_mtls_endpoint(disco, "token_endpoint") == "https://as/token"

    def test_falls_back_when_no_aliases_advertised(self):
        disco = self._disco(token_endpoint="https://as/token")
        assert resolve_mtls_endpoint(disco, "token_endpoint") == "https://as/token"

    def test_returns_none_when_endpoint_absent(self):
        disco = self._disco()
        assert resolve_mtls_endpoint(disco, "token_endpoint") is None


@pytest.mark.unit
class TestMtlsClientAuthRepr:
    """The private key path/PEM and password must never surface in repr."""

    def test_repr_suppresses_secrets(self):
        cfg = MtlsClientAuth(
            certificate="/etc/client.crt",
            private_key="/etc/super-secret.key",
            password="hunter2",
        )
        rendered = repr(cfg)
        assert "super-secret" not in rendered
        assert "hunter2" not in rendered
        # Non-secret fields remain visible for debuggability.
        assert "/etc/client.crt" in rendered
        assert "tls_client_auth" in rendered

    def test_repr_of_request_holding_config_does_not_leak(self):
        request = ClientCredentialsTokenRequest(
            address=TOKEN_URL,
            client_id="c",
            mtls=MtlsClientAuth(
                certificate="/etc/client.crt",
                private_key="/etc/super-secret.key",
                password="hunter2",
            ),
        )
        rendered = repr(request)
        assert "super-secret" not in rendered
        assert "hunter2" not in rendered


# (label, prepare_fn, request_obj) for every client-authenticating endpoint.
def _prepare_cases():
    return [
        (
            "client_credentials",
            prepare_token_request_data,
            ClientCredentialsTokenRequest(
                address=ADDR, client_id="c", client_secret="s", scope="api"
            ),
        ),
        (
            "auth_code",
            prepare_auth_code_token_request_data,
            AuthorizationCodeTokenRequest(
                address=ADDR,
                client_id="c",
                code="abc",
                redirect_uri="https://app/cb",
                client_secret="s",
            ),
        ),
        (
            "refresh",
            prepare_refresh_token_request_data,
            RefreshTokenRequest(
                address=ADDR, client_id="c", refresh_token="rt", client_secret="s"
            ),
        ),
        (
            "introspection",
            prepare_introspection_request_data,
            TokenIntrospectionRequest(
                address=ADDR, token="t", client_id="c", client_secret="s"
            ),
        ),
        (
            "revocation",
            prepare_revocation_request_data,
            TokenRevocationRequest(
                address=ADDR, token="t", client_id="c", client_secret="s"
            ),
        ),
        (
            "par",
            prepare_par_request_data,
            PushedAuthorizationRequest(
                address=ADDR,
                client_id="c",
                redirect_uri="https://app/cb",
                client_secret="s",
            ),
        ),
        (
            "device_auth",
            prepare_device_auth_request_data,
            DeviceAuthorizationRequest(address=ADDR, client_id="c", client_secret="s"),
        ),
        (
            "device_token",
            prepare_device_token_request_data,
            DeviceTokenRequest(
                address=ADDR, client_id="c", device_code="dc", client_secret="s"
            ),
        ),
        (
            "token_exchange",
            prepare_token_exchange_request_data,
            TokenExchangeRequest(
                address=ADDR,
                client_id="c",
                subject_token="st",
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                client_secret="s",
            ),
        ),
    ]


@pytest.mark.unit
class TestPrepareFunctionMtls:
    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_mtls_puts_client_id_in_body_no_auth(self, label, prepare_fn, request_obj):
        # mTLS only: cert is at the TLS layer, client_id in body, no Basic auth.
        request_obj.client_secret = None
        request_obj.mtls = MtlsClientAuth(certificate="/c.pem", private_key="/k.pem")
        params, _headers, auth = prepare_fn(request_obj)

        assert auth is None, label
        assert params["client_id"] == "c", label
        assert "client_assertion" not in params, label
        assert "client_secret" not in params, label

    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_mtls_takes_precedence_over_client_secret(
        self, label, prepare_fn, request_obj
    ):
        # Both client_secret and mtls set — mTLS must win (no Basic auth).
        request_obj.mtls = MtlsClientAuth(certificate="/c.pem", private_key="/k.pem")
        params, _headers, auth = prepare_fn(request_obj)

        assert auth is None, label
        assert params["client_id"] == "c", label

    @pytest.mark.parametrize(
        ("label", "prepare_fn", "request_obj"),
        _prepare_cases(),
        ids=lambda v: v if isinstance(v, str) else "",
    )
    def test_private_key_jwt_takes_precedence_over_mtls(
        self, label, prepare_fn, request_obj
    ):
        # private_key_jwt outranks mTLS (RFC 8705 precedence mirrors #213).
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        request_obj.mtls = MtlsClientAuth(certificate="/c.pem", private_key="/k.pem")
        request_obj.private_key_jwt = PrivateKeyJwt(
            private_key=private_pem, algorithm="PS256"
        )
        params, _headers, auth = prepare_fn(request_obj)

        assert auth is None, label
        # The assertion — not a bare client_id — proves private_key_jwt won.
        assert "client_assertion" in params, label


_BASE_DISCO = {
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/jwks",
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["PS256"],
}
_DISCO_URL = "https://example.com/.well-known/openid-configuration"


@pytest.mark.unit
class TestDiscoveryParsesMtlsFields:
    @respx.mock
    def test_parses_aliases_and_bound_flag(self):
        respx.get(_DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "tls_client_certificate_bound_access_tokens": True,
                    "mtls_endpoint_aliases": {
                        "token_endpoint": "https://mtls.example.com/token",
                    },
                },
            )
        )
        result = get_discovery_document(DiscoveryDocumentRequest(address=_DISCO_URL))

        assert result.is_successful is True
        assert result.tls_client_certificate_bound_access_tokens is True
        assert result.mtls_endpoint_aliases == {
            "token_endpoint": "https://mtls.example.com/token"
        }

    @respx.mock
    def test_absent_fields_default_none(self):
        respx.get(_DISCO_URL).mock(return_value=httpx.Response(200, json=_BASE_DISCO))
        result = get_discovery_document(DiscoveryDocumentRequest(address=_DISCO_URL))

        assert result.is_successful is True
        assert result.mtls_endpoint_aliases is None
        assert result.tls_client_certificate_bound_access_tokens is None


@pytest.mark.unit
class TestEndToEndMtls:
    """respx intercepts the transport, so the cert-configured client is exercised
    without a real handshake; the request body/headers prove correct plumbing."""

    @respx.mock
    def test_sync_client_credentials_mtls_no_basic_header(self, mtls):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = ClientCredentialsTokenRequest(
            address=TOKEN_URL, client_id="c", scope="api", mtls=mtls
        )
        response = request_client_credentials_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert body["client_id"] == ["c"]
        assert "client_assertion" not in body

    @respx.mock
    async def test_async_client_credentials_mtls_no_basic_header(self, mtls):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = ClientCredentialsTokenRequest(
            address=TOKEN_URL, client_id="c", scope="api", mtls=mtls
        )
        response = await async_request_client_credentials_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert body["client_id"] == ["c"]

    @respx.mock
    def test_sync_auth_code_mtls_no_basic_header(self, mtls):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="c",
            code="abc",
            redirect_uri="https://app/cb",
            mtls=mtls,
        )
        response = request_authorization_code_token(request)
        assert response.is_successful

        sent = route.calls.last.request
        assert sent.headers.get("authorization") is None
        body = parse_qs(sent.content.decode())
        assert body["client_id"] == ["c"]

    @respx.mock
    def test_owned_mtls_client_is_closed(self, mtls, monkeypatch):
        """The short-lived cert client must be closed after the request."""
        created: list[httpx.Client] = []
        real_build = sync_http.build_mtls_client

        def _tracking_build(cfg):
            client = real_build(cfg)
            created.append(client)
            return client

        monkeypatch.setattr(sync_http, "build_mtls_client", _tracking_build)
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": "x", "token_type": "Bearer"}
            )
        )
        request = ClientCredentialsTokenRequest(
            address=TOKEN_URL, client_id="c", mtls=mtls
        )
        request_client_credentials_token(request)

        assert len(created) == 1
        assert created[0].is_closed


@pytest.mark.unit
class TestResolveClientMtlsConflict:
    """A managed http_client cannot be guaranteed to present the mTLS client
    certificate, and prepare_*() has already dropped client_secret/Basic for the
    mTLS branch — so supplying both must fail loudly, not silently downgrade to
    an unauthenticated request (RFC 8705 §2)."""

    def test_sync_both_mtls_and_managed_client_raises(self, mtls):
        managed = HTTPClient()
        try:
            with pytest.raises(ValueError, match="Cannot combine"):
                sync_http.resolve_http_client(mtls, managed)
        finally:
            managed.close()

    def test_sync_mtls_only_builds_owned_client(self, mtls):
        client, owned = sync_http.resolve_http_client(mtls, None)
        try:
            assert owned is client  # caller must close it
        finally:
            client.close()

    def test_sync_managed_only_passes_through(self):
        managed = HTTPClient()
        try:
            client, owned = sync_http.resolve_http_client(None, managed)
            assert client is managed.client
            assert owned is None  # caller must NOT close a managed client
        finally:
            managed.close()

    async def test_async_both_mtls_and_managed_client_raises(self, mtls):
        managed = AsyncHTTPClient()
        try:
            with pytest.raises(ValueError, match="Cannot combine"):
                aio_http.resolve_async_http_client(mtls, managed)
        finally:
            await managed.close()

    async def test_async_mtls_only_builds_owned_client(self, mtls):
        client, owned = aio_http.resolve_async_http_client(mtls, None)
        try:
            assert owned is client
        finally:
            await client.aclose()
