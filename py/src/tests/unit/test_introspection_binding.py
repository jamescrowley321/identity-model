"""Introspected sender constraints (RFC 9449 §6.2/§7.2, RFC 8705 §3.2).

``check_introspection_binding`` checks an introspection response's ``cnf``
against the request's ``TokenPresentation`` with the rules and typed errors of
``check_token_binding``.
"""

from __future__ import annotations

import datetime
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from py_identity_model import (
    AuthorizationScheme,
    DPoPErrorKind,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    IntrospectedTokenError,
    IntrospectedTokenErrorKind,
    IntrospectionErrorKind,
    TokenBinding,
    TokenIntrospectionResponse,
    TokenPresentation,
    TokenValidationConfig,
    check_introspection_binding,
    compute_certificate_thumbprint,
    create_dpop_proof,
    generate_dpop_key,
)
from py_identity_model.core.token_binding import check_token_binding
from py_identity_model.exceptions import (
    CertificateBindingError,
    CertificateBindingErrorKind,
    ConfigurationException,
    TokenValidationException,
)


URL = "https://rs.example.com/api/resource"
METHOD = "GET"
OPAQUE_TOKEN = "opaque-access-token-value"
OTHER_TOKEN = "another-opaque-access-token"
# Shaped like a base64url SHA-256 thumbprint; matches no key or certificate.
UNMATCHED_THUMBPRINT = "A" * 43
CERTIFICATE_REQUIRED = (
    "No client certificate was presented for a certificate-bound access token "
    "or required_binding=mtls (RFC 8705 §3)"
)


def _cert_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def client_cert_pem() -> bytes:
    return _cert_pem()


@pytest.fixture(scope="module")
def other_cert_pem() -> bytes:
    return _cert_pem()


def _response(cnf: object = None, *, active: object = True):
    claims: dict[str, object] = {"active": active, "client_id": "app"}
    if cnf is not None:
        claims["cnf"] = cnf
    return TokenIntrospectionResponse(is_successful=True, claims=claims)


def _options() -> DPoPVerificationOptions:
    return DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache())


def _dpop(key, token: str = OPAQUE_TOKEN) -> TokenPresentation:
    return TokenPresentation(
        scheme=AuthorizationScheme.DPOP,
        method=METHOD,
        url=URL,
        dpop_proof=create_dpop_proof(key, METHOD, URL, access_token=token),
    )


def _mtls(cert) -> TokenPresentation:
    return TokenPresentation(
        scheme=AuthorizationScheme.BEARER,
        method=METHOD,
        url=URL,
        client_certificate=cert,
    )


def _check(response, presentation, **kwargs) -> None:
    kwargs.setdefault("dpop", _options())
    check_introspection_binding(response, OPAQUE_TOKEN, presentation, **kwargs)


def _kind(response, presentation, **kwargs) -> DPoPErrorKind:
    with pytest.raises(DPoPValidationError) as exc:
        _check(response, presentation, **kwargs)
    return exc.value.kind


@pytest.mark.unit
class TestDPoPBoundIntrospection:
    def test_no_presentation_rejected(self):
        key = generate_dpop_key()

        kind = _kind(_response({"jkt": key.jwk_thumbprint}), None)

        assert kind is DPoPErrorKind.PROOF_REQUIRED

    def test_matching_proof_accepted(self):
        key = generate_dpop_key()

        _check(_response({"jkt": key.jwk_thumbprint}), _dpop(key))

    def test_required_dpop_accepts_matching_proof(self):
        key = generate_dpop_key()

        _check(
            _response({"jkt": key.jwk_thumbprint}),
            _dpop(key),
            required_binding=TokenBinding.DPOP,
        )

    def test_proof_from_other_key_rejected(self):
        key = generate_dpop_key()

        kind = _kind(_response({"jkt": key.jwk_thumbprint}), _dpop(generate_dpop_key()))

        assert kind is DPoPErrorKind.JKT_MISMATCH

    def test_proof_for_other_token_rejected(self):
        # The proof's ath must hash the opaque token presented (RFC 9449 §7.1).
        key = generate_dpop_key()

        kind = _kind(_response({"jkt": key.jwk_thumbprint}), _dpop(key, OTHER_TOKEN))

        assert kind is DPoPErrorKind.ATH_MISMATCH

    def test_dpop_options_apply_to_the_proof(self):
        # An ES256 proof that the defaults accept is refused when the caller
        # allows only RS256: the options reach the proof verifier.
        key = generate_dpop_key("ES256")
        options = DPoPVerificationOptions(
            algorithms=frozenset({"RS256"}), replay_cache=InMemoryDPoPReplayCache()
        )

        kind = _kind(_response({"jkt": key.jwk_thumbprint}), _dpop(key), dpop=options)

        assert kind is DPoPErrorKind.UNSUPPORTED_ALGORITHM

    def test_bearer_scheme_rejected(self):
        key = generate_dpop_key()
        presentation = TokenPresentation(scheme=AuthorizationScheme.BEARER)

        kind = _kind(_response({"jkt": key.jwk_thumbprint}), presentation)

        assert kind is DPoPErrorKind.WRONG_SCHEME


@pytest.mark.unit
class TestCertificateBoundIntrospection:
    def test_no_presentation_rejected(self, client_cert_pem):
        response = _response(
            {"x5t#S256": compute_certificate_thumbprint(client_cert_pem)}
        )

        with pytest.raises(
            CertificateBindingError, match=f"^{re.escape(CERTIFICATE_REQUIRED)}$"
        ) as exc:
            _check(response, None)
        assert exc.value.kind is CertificateBindingErrorKind.CERTIFICATE_REQUIRED

    def test_matching_certificate_accepted(self, client_cert_pem):
        response = _response(
            {"x5t#S256": compute_certificate_thumbprint(client_cert_pem)}
        )

        _check(response, _mtls(client_cert_pem), required_binding=TokenBinding.MTLS)

    def test_other_certificate_rejected(self, client_cert_pem, other_cert_pem):
        response = _response(
            {"x5t#S256": compute_certificate_thumbprint(client_cert_pem)}
        )

        with pytest.raises(CertificateBindingError):
            _check(response, _mtls(other_cert_pem))

    def test_presentation_without_certificate_rejected(self, client_cert_pem):
        response = _response(
            {"x5t#S256": compute_certificate_thumbprint(client_cert_pem)}
        )

        with pytest.raises(
            CertificateBindingError, match=f"^{re.escape(CERTIFICATE_REQUIRED)}$"
        ) as exc:
            _check(response, _mtls(None))
        assert exc.value.kind is CertificateBindingErrorKind.CERTIFICATE_REQUIRED


@pytest.mark.unit
class TestUnboundIntrospection:
    @pytest.mark.parametrize("cnf", [None, {}, {"other": "member"}])
    def test_no_presentation_accepted(self, cnf):
        _check(_response(cnf), None)

    @pytest.mark.parametrize("cnf", ["jkt", ["jkt"], 1])
    def test_non_object_cnf_is_unbound_as_on_jwt_path(self, cnf):
        config = TokenValidationConfig(perform_disco=True)
        check_token_binding({"cnf": cnf}, OPAQUE_TOKEN, config, None)

        _check(_response(cnf), None)

    def test_bearer_presentation_accepted(self):
        _check(_response(), TokenPresentation(scheme=AuthorizationScheme.BEARER))

    def test_dpop_scheme_rejected_as_not_bound(self):
        key = generate_dpop_key()

        assert _kind(_response(), _dpop(key)) is DPoPErrorKind.NOT_BOUND

    def test_required_dpop_rejected_as_not_bound(self):
        presentation = TokenPresentation(scheme=AuthorizationScheme.BEARER)

        kind = _kind(_response(), presentation, required_binding=TokenBinding.DPOP)

        assert kind is DPoPErrorKind.NOT_BOUND

    def test_required_mtls_without_certificate_rejected(self):
        with pytest.raises(
            CertificateBindingError, match=f"^{re.escape(CERTIFICATE_REQUIRED)}$"
        ) as exc:
            _check(_response(), _mtls(None), required_binding=TokenBinding.MTLS)
        assert exc.value.kind is CertificateBindingErrorKind.CERTIFICATE_REQUIRED

    @pytest.mark.parametrize("binding", [TokenBinding.DPOP, TokenBinding.MTLS])
    def test_required_binding_without_presentation_is_config_error(self, binding):
        with pytest.raises(ConfigurationException):
            _check(_response(), None, required_binding=binding)


@pytest.mark.unit
class TestFailClosed:
    """Only an active, successful response can pass (RFC 7662 §2.2)."""

    @pytest.mark.parametrize("active", [False, None, "true", 1])
    @pytest.mark.parametrize("bound", [True, False])
    def test_inactive_response_rejected(self, active, bound):
        key = generate_dpop_key()
        cnf = {"jkt": key.jwk_thumbprint} if bound else None
        presentation = _dpop(key) if bound else None

        with pytest.raises(IntrospectedTokenError) as exc:
            _check(_response(cnf, active=active), presentation)

        assert exc.value.kind is IntrospectedTokenErrorKind.INACTIVE
        assert exc.value.introspection_error_kind is None

    def test_absent_active_rejected(self):
        response = TokenIntrospectionResponse(
            is_successful=True, claims={"client_id": "app"}
        )

        with pytest.raises(IntrospectedTokenError) as exc:
            _check(response, None)

        assert exc.value.kind is IntrospectedTokenErrorKind.INACTIVE

    def test_successful_response_without_claims_rejected(self):
        response = TokenIntrospectionResponse(is_successful=True, claims=None)

        with pytest.raises(IntrospectedTokenError) as exc:
            _check(response, None)

        assert exc.value.kind is IntrospectedTokenErrorKind.INACTIVE

    def test_failed_response_rejected(self):
        response = TokenIntrospectionResponse(is_successful=False, error="boom")

        with pytest.raises(IntrospectedTokenError) as exc:
            _check(response, None)

        assert exc.value.kind is IntrospectedTokenErrorKind.INTROSPECTION_FAILED
        assert exc.value.introspection_error_kind is None
        assert "boom" not in str(exc.value)

    def test_refused_signed_response_carries_error_kind(self):
        response = TokenIntrospectionResponse(
            is_successful=False,
            error="bad signature",
            error_kind=IntrospectionErrorKind.SIGNATURE,
        )

        with pytest.raises(IntrospectedTokenError) as exc:
            _check(response, None)

        assert exc.value.kind is IntrospectedTokenErrorKind.INTROSPECTION_FAILED
        assert exc.value.introspection_error_kind is IntrospectionErrorKind.SIGNATURE
        assert exc.value.details == {
            "kind": "introspection_failed",
            "introspection_error_kind": "signature",
        }

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            (
                _response(active=False),
                "Introspected access token is not active (RFC 7662 §2.2)",
            ),
            (
                TokenIntrospectionResponse(is_successful=False, error="boom"),
                "Token introspection failed; the access token's state is unknown "
                "and it is not accepted",
            ),
        ],
        ids=["inactive", "failed"],
    )
    def test_message_is_fixed_per_kind(self, response, message):
        with pytest.raises(IntrospectedTokenError) as exc:
            _check(response, None)

        assert exc.value.message == message

    def test_is_a_token_validation_exception(self):
        with pytest.raises(TokenValidationException):
            _check(_response(active=False), None)

    @pytest.mark.parametrize("binding", [TokenBinding.DPOP, TokenBinding.MTLS])
    def test_required_binding_without_presentation_is_config_error_first(self, binding):
        with pytest.raises(ConfigurationException):
            _check(_response(active=False), None, required_binding=binding)


@pytest.mark.unit
class TestSameRulesAsJwtPath:
    """The introspected ``cnf`` raises what the same JWT ``cnf`` raises."""

    @pytest.mark.parametrize("member", ["jkt", "x5t#S256"])
    def test_bound_without_presentation_matches_check_token_binding(self, member):
        cnf = {member: UNMATCHED_THUMBPRINT}
        config = TokenValidationConfig(perform_disco=True)

        with pytest.raises((DPoPValidationError, CertificateBindingError)) as jwt_exc:
            check_token_binding({"cnf": cnf}, OPAQUE_TOKEN, config, None)
        with pytest.raises((DPoPValidationError, CertificateBindingError)) as intr_exc:
            _check(_response(cnf), None)

        assert type(intr_exc.value) is type(jwt_exc.value)
        assert str(intr_exc.value) == str(jwt_exc.value)
