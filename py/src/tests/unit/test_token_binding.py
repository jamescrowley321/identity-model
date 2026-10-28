"""Sender-constrained access tokens at the resource server (RFC 9449 §7, RFC 8705 §3).

Drives ``validate_token`` (sync and async, manual-key mode) with a
``TokenPresentation`` through the issue #478 negative matrix rows that depend on
the access token: thumbprint binding, scheme, fail-closed required binding, and
the ``none`` back-compat default.
"""

from __future__ import annotations

import asyncio
from base64 import urlsafe_b64encode
from dataclasses import replace
import datetime
import re
import time
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import jwt as pyjwt
import pytest

from py_identity_model import (
    AuthorizationScheme,
    DPoPErrorKind,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    TokenBinding,
    TokenPresentation,
    TokenValidationConfig,
    compute_certificate_thumbprint,
    create_dpop_proof,
    generate_dpop_key,
    validate_token,
)
from py_identity_model.aio import validate_token as avalidate_token
from py_identity_model.exceptions import (
    CertificateBindingError,
    ConfigurationException,
)


URL = "https://rs.example.com/api/resource"
METHOD = "GET"
AUDIENCE = "urn:test:api"
ISSUER = "https://op.example.com"


def _exactly(message: str) -> str:
    """A ``pytest.raises`` pattern matching *message* and nothing else."""
    return f"^{re.escape(message)}$"


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_jwk(signing_key) -> dict:
    numbers = signing_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8)),
        "e": _b64(numbers.e.to_bytes(3)),
    }


@pytest.fixture(scope="module")
def client_cert_pem() -> bytes:
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


def _access_token(signing_key, cnf: dict | None = None) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    if cnf is not None:
        claims["cnf"] = cnf
    pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pyjwt.encode(claims, pem, algorithm="RS256")


def _config(public_jwk, binding: TokenBinding = TokenBinding.NONE):
    return TokenValidationConfig(
        perform_disco=False,
        key=public_jwk,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        required_binding=binding,
        dpop=DPoPVerificationOptions(replay_cache=InMemoryDPoPReplayCache()),
    )


def _dpop(token: str, key, *, url: str = URL, method: str = METHOD):
    return TokenPresentation(
        scheme=AuthorizationScheme.DPOP,
        method=method,
        url=url,
        dpop_proof=create_dpop_proof(key, method, url, access_token=token),
    )


@pytest.fixture(params=["sync", "async"])
def validate(request):
    """``validate_token`` with the same call shape for both APIs."""
    if request.param == "sync":
        return validate_token

    def _run(jwt, config, **kwargs):
        return asyncio.run(avalidate_token(jwt, config, **kwargs))

    return _run


def _kind(validate, token, config, presentation) -> DPoPErrorKind:
    with pytest.raises(DPoPValidationError) as exc:
        validate(token, config, presentation=presentation)
    return exc.value.kind


@pytest.mark.unit
class TestDPoPBoundToken:
    def test_matching_proof_accepted(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})

        claims = validate(token, _config(public_jwk), presentation=_dpop(token, key))

        assert claims["cnf"] == {"jkt": key.jwk_thumbprint}

    def test_required_dpop_accepts_bound_token(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        config = _config(public_jwk, TokenBinding.DPOP)

        assert validate(token, config, presentation=_dpop(token, key))["sub"] == "user"

    def test_thumbprint_mismatch_rejected(self, validate, signing_key, public_jwk):
        bound = generate_dpop_key()
        attacker = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": bound.jwk_thumbprint})

        assert (
            _kind(validate, token, _config(public_jwk), _dpop(token, attacker))
            is DPoPErrorKind.JKT_MISMATCH
        )

    @pytest.mark.parametrize("jkt", ["", 5, None, "é" * 43])
    def test_malformed_cnf_jkt_rejected(self, validate, signing_key, public_jwk, jkt):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": jkt})

        assert (
            _kind(validate, token, _config(public_jwk), _dpop(token, key))
            is DPoPErrorKind.JKT_MISMATCH
        )

    def test_overflowing_proof_iat_rejected(self, validate, signing_key, public_jwk):
        # An integer iat too large for a float must be a typed rejection, not
        # an OverflowError escaping validate_token.
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        proof = pyjwt.encode(
            {"jti": "big-iat", "htm": METHOD, "htu": URL, "iat": 10**400},
            key.private_key_pem,
            algorithm=key.algorithm,
            headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
        )
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.DPOP, method=METHOD, url=URL, dpop_proof=proof
        )

        assert (
            _kind(validate, token, _config(public_jwk), presentation)
            is DPoPErrorKind.MISSING_CLAIM
        )

    def test_bound_token_as_bearer_rejected(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        bearer = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=URL
        )

        assert (
            _kind(validate, token, _config(public_jwk), bearer)
            is DPoPErrorKind.WRONG_SCHEME
        )

    def test_bound_token_without_proof_rejected(
        self, validate, signing_key, public_jwk
    ):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.DPOP, method=METHOD, url=URL
        )

        assert (
            _kind(validate, token, _config(public_jwk), presentation)
            is DPoPErrorKind.PROOF_REQUIRED
        )

    def test_proof_for_other_token_rejected(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.DPOP,
            method=METHOD,
            url=URL,
            dpop_proof=create_dpop_proof(key, METHOD, URL, access_token="other"),
        )

        assert (
            _kind(validate, token, _config(public_jwk), presentation)
            is DPoPErrorKind.ATH_MISMATCH
        )

    def test_replayed_proof_rejected(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        config = _config(public_jwk)
        presentation = _dpop(token, key)
        validate(token, config, presentation=presentation)

        assert (
            _kind(validate, token, config, presentation) is DPoPErrorKind.REPLAYED_JTI
        )

    def test_configured_replay_cache_used(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        cache = InMemoryDPoPReplayCache()
        config = replace(
            _config(public_jwk), dpop=DPoPVerificationOptions(replay_cache=cache)
        )
        validate(token, config, presentation=_dpop(token, key))

        assert len(cache) == 1

    @pytest.mark.parametrize("missing", ["method", "url"])
    def test_proof_without_request_is_value_error(
        self, validate, signing_key, public_jwk, missing
    ):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        proof = create_dpop_proof(key, METHOD, URL, access_token=token)
        request = {"method": METHOD, "url": URL} | {missing: None}
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.DPOP, dpop_proof=proof, **request
        )

        with pytest.raises(
            ValueError,
            match=_exactly(
                "presentation.method and presentation.url are needed to verify a DPoP proof"
            ),
        ):
            validate(token, _config(public_jwk), presentation=presentation)

    def test_expected_nonce_enforced(self, validate, signing_key, public_jwk):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.DPOP,
            method=METHOD,
            url=URL,
            dpop_proof=create_dpop_proof(key, METHOD, URL, access_token=token),
            expected_nonce="server-nonce",
        )

        assert (
            _kind(validate, token, _config(public_jwk), presentation)
            is DPoPErrorKind.NONCE_MISMATCH
        )


@pytest.mark.unit
class TestRequiredBinding:
    def test_required_dpop_unbound_without_proof_rejected(
        self, validate, signing_key, public_jwk
    ):
        token = _access_token(signing_key)
        presentation = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=URL
        )

        assert (
            _kind(validate, token, _config(public_jwk, TokenBinding.DPOP), presentation)
            is DPoPErrorKind.NOT_BOUND
        )

    def test_required_dpop_unbound_with_proof_rejected(
        self, validate, signing_key, public_jwk
    ):
        key = generate_dpop_key()
        token = _access_token(signing_key)

        assert (
            _kind(
                validate,
                token,
                _config(public_jwk, TokenBinding.DPOP),
                _dpop(token, key),
            )
            is DPoPErrorKind.NOT_BOUND
        )

    def test_unbound_token_under_dpop_scheme_rejected(
        self, validate, signing_key, public_jwk
    ):
        key = generate_dpop_key()
        token = _access_token(signing_key)

        assert (
            _kind(validate, token, _config(public_jwk), _dpop(token, key))
            is DPoPErrorKind.NOT_BOUND
        )

    @pytest.mark.parametrize("binding", [TokenBinding.DPOP, TokenBinding.MTLS])
    def test_required_binding_without_presentation_is_config_error(
        self, validate, signing_key, public_jwk, binding
    ):
        token = _access_token(signing_key)

        with pytest.raises(ConfigurationException) as exc:
            validate(token, _config(public_jwk, binding))

        assert str(exc.value) == (
            f"required_binding={binding.value} needs the request's presentation= "
            "(scheme, method, url, DPoP proof or client certificate)"
        )

    def test_required_binding_must_be_typed(self, validate, signing_key, public_jwk):
        config = replace(
            _config(public_jwk), required_binding=cast("TokenBinding", "dpop")
        )

        with pytest.raises(ConfigurationException) as exc:
            validate(_access_token(signing_key), config)

        assert str(exc.value) == "required_binding must be a TokenBinding"

    def test_none_unbound_bearer_accepted(self, validate, signing_key, public_jwk):
        token = _access_token(signing_key)
        bearer = TokenPresentation(
            scheme=AuthorizationScheme.BEARER, method=METHOD, url=URL
        )

        assert (
            validate(token, _config(public_jwk), presentation=bearer)["sub"] == "user"
        )

    def test_none_without_presentation_unchanged(
        self, validate, signing_key, public_jwk
    ):
        key = generate_dpop_key()
        token = _access_token(signing_key, {"jkt": key.jwk_thumbprint})

        assert validate(token, _config(public_jwk))["cnf"] == {
            "jkt": key.jwk_thumbprint
        }

    def test_default_is_none(self):
        assert TokenValidationConfig(perform_disco=True).required_binding is (
            TokenBinding.NONE
        )


@pytest.mark.unit
class TestMtlsBinding:
    def _presentation(self, cert) -> TokenPresentation:
        return TokenPresentation(
            scheme=AuthorizationScheme.BEARER,
            method=METHOD,
            url=URL,
            client_certificate=cert,
        )

    def test_matching_certificate_accepted(
        self, validate, signing_key, public_jwk, client_cert_pem
    ):
        thumbprint = compute_certificate_thumbprint(client_cert_pem)
        token = _access_token(signing_key, {"x5t#S256": thumbprint})
        config = _config(public_jwk, TokenBinding.MTLS)

        claims = validate(
            token, config, presentation=self._presentation(client_cert_pem)
        )

        assert claims["cnf"] == {"x5t#S256": thumbprint}

    def test_certificate_mismatch_rejected(
        self, validate, signing_key, public_jwk, client_cert_pem
    ):
        token = _access_token(signing_key, {"x5t#S256": "A" * 43})

        with pytest.raises(CertificateBindingError):
            validate(
                token,
                _config(public_jwk),
                presentation=self._presentation(client_cert_pem),
            )

    def test_required_mtls_without_certificate_rejected(
        self, validate, signing_key, public_jwk, client_cert_pem
    ):
        thumbprint = compute_certificate_thumbprint(client_cert_pem)
        token = _access_token(signing_key, {"x5t#S256": thumbprint})

        with pytest.raises(CertificateBindingError) as exc:
            validate(
                token,
                _config(public_jwk, TokenBinding.MTLS),
                presentation=self._presentation(None),
            )

        assert str(exc.value) == (
            "required_binding=mtls but no client certificate was presented "
            "(RFC 8705 §3)"
        )

    def test_certificate_bound_token_without_certificate_rejected(
        self, validate, signing_key, public_jwk, client_cert_pem
    ):
        # RFC 8705 §3: a certificate-bound token is only valid over mTLS with
        # the bound certificate, as a DPoP-bound token needs its proof.
        thumbprint = compute_certificate_thumbprint(client_cert_pem)
        token = _access_token(signing_key, {"x5t#S256": thumbprint})

        with pytest.raises(CertificateBindingError) as exc:
            validate(token, _config(public_jwk), presentation=self._presentation(None))

        assert str(exc.value) == (
            "Certificate-bound access token was presented without a client "
            "certificate (RFC 8705 §3)"
        )

    def test_unbound_token_without_certificate_accepted(
        self, validate, signing_key, public_jwk
    ):
        token = _access_token(signing_key)

        claims = validate(
            token, _config(public_jwk), presentation=self._presentation(None)
        )

        assert "cnf" not in claims

    def test_certificate_bound_token_without_presentation_unchanged(
        self, validate, signing_key, public_jwk
    ):
        token = _access_token(signing_key, {"x5t#S256": "A" * 43})

        claims = validate(token, _config(public_jwk))

        assert claims["cnf"] == {"x5t#S256": "A" * 43}

    def test_required_mtls_unbound_rejected(
        self, validate, signing_key, public_jwk, client_cert_pem
    ):
        token = _access_token(signing_key)

        with pytest.raises(CertificateBindingError):
            validate(
                token,
                _config(public_jwk, TokenBinding.MTLS),
                presentation=self._presentation(client_cert_pem),
            )
