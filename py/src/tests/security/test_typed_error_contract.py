"""Fail-closed control test: typed errors for discovery, JWKS and DPoP inputs.

A discovery or JWKS failure must surface as its own type, so an outage
(``NetworkException``) is never confused with an invalid document
(``ValidationException``). DPoP key and argument checks must refuse bad input
with a typed error naming the rule. Each case pins the type, the kind or
argument, and the exact message.
"""

import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
import httpx
import pytest

from py_identity_model.core import discovery_logic
from py_identity_model.core.discovery_logic import process_discovery_response
from py_identity_model.core.dpop import (
    DPoPAlgorithm,
    DPoPKey,
    build_dpop_headers,
    compute_ath,
    compute_jwk_thumbprint,
    create_dpop_proof,
)
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    DiscoveryErrorKind,
    JsonWebKey,
    JwksErrorKind,
    JwksResponse,
)
from py_identity_model.core.token_validation_logic import (
    discovery_failure,
    jwks_failure,
    keep_signature_verdict_on_failed_refresh,
    validate_disco_response,
    validate_jwks_response,
    validate_jwks_uri,
)
from py_identity_model.exceptions import (
    DiscoveryException,
    DiscoveryIssuerMismatchError,
    DiscoveryMissingFieldsError,
    DPoPKeyError,
    DPoPKeyErrorKind,
    InvalidArgumentError,
    InvalidArgumentKind,
    JwksException,
    JwksValidationError,
    SignatureVerificationException,
)


ISSUER = "https://issuer.example"
DISCO_ADDR = f"{ISSUER}/.well-known/openid-configuration"
URI = "https://rs.example/resource"
SUPPORTED = sorted(a.value for a in DPoPAlgorithm)


def _invalid_argument(call) -> tuple:
    with pytest.raises(InvalidArgumentError) as excinfo:
        call()
    exc = excinfo.value
    return (type(exc), exc.argument, exc.kind, str(exc))


def _dpop_key_error(call) -> tuple:
    with pytest.raises(DPoPKeyError) as excinfo:
        call()
    exc = excinfo.value
    return (type(exc), exc.kind, str(exc))


class TestDPoPKeyErrors:
    def test_unsupported_algorithm(self):
        assert _dpop_key_error(lambda: DPoPKey("HS256")) == (
            DPoPKeyError,
            DPoPKeyErrorKind.UNSUPPORTED_ALGORITHM,
            f"Unsupported DPoP algorithm: HS256. Supported: {SUPPORTED}",
        )

    def test_key_that_cannot_sign_with_the_algorithm(self):
        pem = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        data = pem.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        assert _dpop_key_error(lambda: DPoPKey.from_pem(data, "ES256")) == (
            DPoPKeyError,
            DPoPKeyErrorKind.KEY_ALGORITHM_MISMATCH,
            "Key is not a private key ES256 can sign with",
        )

    def test_unloadable_pem(self):
        with pytest.raises(DPoPKeyError) as excinfo:
            DPoPKey.from_pem(b"not a pem", "ES256")
        exc = excinfo.value
        assert (exc.kind, str(exc)) == (
            DPoPKeyErrorKind.INVALID_KEY,
            f"Cannot load the DPoP private key: {exc.__cause__}",
        )

    def test_jwk_not_a_dict(self):
        assert _dpop_key_error(lambda: DPoPKey.from_jwk([], "ES256")) == (  # type: ignore[arg-type]
            DPoPKeyError,
            DPoPKeyErrorKind.INVALID_KEY,
            "A DPoP JWK must be a dict",
        )

    def test_jwk_without_algorithm(self):
        assert _dpop_key_error(lambda: DPoPKey.from_jwk({"kty": "EC"})) == (
            DPoPKeyError,
            DPoPKeyErrorKind.ALGORITHM_REQUIRED,
            "A DPoP JWK needs an algorithm: pass one or set 'alg'",
        )

    def test_jwk_alg_member_is_used(self):
        # The JWK's own "alg" picks the algorithm when none is passed.
        assert _dpop_key_error(
            lambda: DPoPKey.from_jwk({"kty": "oct", "alg": "ES256"})
        ) == (
            DPoPKeyError,
            DPoPKeyErrorKind.UNSUPPORTED_KEY_TYPE,
            "Unsupported JWK kty for DPoP: 'oct'",
        )

    def test_unloadable_jwk(self):
        with pytest.raises(DPoPKeyError) as excinfo:
            DPoPKey.from_jwk({"kty": "EC", "crv": "P-256"}, "ES256")
        exc = excinfo.value
        assert (exc.kind, str(exc)) == (
            DPoPKeyErrorKind.INVALID_KEY,
            f"Cannot load the DPoP JWK: {exc.__cause__}",
        )

    def test_thumbprint_unsupported_key_type(self):
        assert _dpop_key_error(lambda: compute_jwk_thumbprint({"kty": "oct"})) == (
            DPoPKeyError,
            DPoPKeyErrorKind.UNSUPPORTED_KEY_TYPE,
            "Unsupported JWK kty for thumbprint: 'oct'",
        )

    def test_thumbprint_missing_members(self):
        assert _dpop_key_error(lambda: compute_jwk_thumbprint({"kty": "EC"})) == (
            DPoPKeyError,
            DPoPKeyErrorKind.MISSING_THUMBPRINT_MEMBERS,
            "JWK thumbprint needs string members ('crv', 'kty', 'x', 'y')",
        )


class TestDPoPArgumentErrors:
    @pytest.mark.parametrize("token", ["", "   "])
    def test_empty_access_token(self, token):
        assert _invalid_argument(lambda: compute_ath(token)) == (
            InvalidArgumentError,
            "access_token",
            InvalidArgumentKind.MISSING,
            "access_token must not be empty",
        )

    def test_non_ascii_access_token(self):
        assert _invalid_argument(lambda: compute_ath("tök")) == (
            InvalidArgumentError,
            "access_token",
            InvalidArgumentKind.INVALID_VALUE,
            "access_token must contain only ASCII characters",
        )

    @pytest.mark.parametrize("method", ["", "   "])
    def test_empty_method(self, method):
        key = DPoPKey("ES256")
        assert _invalid_argument(lambda: create_dpop_proof(key, method, URI)) == (
            InvalidArgumentError,
            "method",
            InvalidArgumentKind.MISSING,
            "method must not be empty",
        )

    @pytest.mark.parametrize("uri", ["", "   "])
    def test_empty_uri(self, uri):
        key = DPoPKey("ES256")
        assert _invalid_argument(lambda: create_dpop_proof(key, "GET", uri)) == (
            InvalidArgumentError,
            "uri",
            InvalidArgumentKind.MISSING,
            "uri must not be empty",
        )

    @pytest.mark.parametrize("uri", ["/relative", "https://"])
    def test_relative_uri(self, uri):
        key = DPoPKey("ES256")
        assert _invalid_argument(lambda: create_dpop_proof(key, "GET", uri)) == (
            InvalidArgumentError,
            "uri",
            InvalidArgumentKind.INVALID_VALUE,
            "uri must be an absolute HTTP URI",
        )

    @pytest.mark.parametrize("proof", ["", "   "])
    def test_empty_proof(self, proof):
        assert _invalid_argument(lambda: build_dpop_headers(proof)) == (
            InvalidArgumentError,
            "proof",
            InvalidArgumentKind.MISSING,
            "proof must not be empty",
        )

    def test_headers_for_a_valid_proof(self):
        assert build_dpop_headers("p") == {"DPoP": "p"}
        assert build_dpop_headers("p", "at") == {
            "DPoP": "p",
            "Authorization": "DPoP at",
        }


def _failed_disco(**fields) -> DiscoveryDocumentResponse:
    return DiscoveryDocumentResponse(is_successful=False, **fields)


class TestDiscoveryFailure:
    def test_default_message(self):
        exc = discovery_failure(_failed_disco())
        assert isinstance(exc, DiscoveryException)
        assert (type(exc), str(exc), exc.status_code) == (
            DiscoveryException,
            "Discovery document request failed",
            None,
        )

    def test_issuer_mismatch_without_issuers(self):
        exc = discovery_failure(
            _failed_disco(error="boom", error_kind=DiscoveryErrorKind.ISSUER_MISMATCH)
        )
        assert isinstance(exc, DiscoveryIssuerMismatchError)
        assert (exc.requested, exc.returned) == ("", "")

    def test_missing_fields_message(self):
        exc = discovery_failure(
            _failed_disco(
                error="boom",
                error_kind=DiscoveryErrorKind.MISSING_FIELDS,
                missing_fields=("issuer",),
            )
        )
        assert isinstance(exc, DiscoveryMissingFieldsError)
        assert (type(exc), str(exc), exc.fields) == (
            DiscoveryMissingFieldsError,
            "boom",
            ("issuer",),
        )

    def test_failed_response_raises_and_logs(self, caplog):
        with (
            caplog.at_level(logging.ERROR, logger="py_identity_model"),
            pytest.raises(DiscoveryException),
        ):
            validate_disco_response(_failed_disco(error="boom"))
        assert [r.getMessage() for r in caplog.records] == ["Discovery failed: boom"]

    def test_successful_response_passes(self):
        validate_disco_response(DiscoveryDocumentResponse(is_successful=True))

    @pytest.mark.parametrize("jwks_uri", [None, ""])
    def test_missing_jwks_uri(self, jwks_uri):
        response = DiscoveryDocumentResponse(is_successful=True, jwks_uri=jwks_uri)
        with pytest.raises(DiscoveryMissingFieldsError) as excinfo:
            validate_jwks_uri(response)
        assert (str(excinfo.value), excinfo.value.fields) == (
            "Discovery document missing jwks_uri",
            ("jwks_uri",),
        )

    def test_jwks_uri_returned(self):
        response = DiscoveryDocumentResponse(
            is_successful=True, jwks_uri=f"{ISSUER}/jwks"
        )
        assert validate_jwks_uri(response) == f"{ISSUER}/jwks"

    def test_wrongly_typed_document_is_invalid_document(self):
        document = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": 5,
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        response = httpx.Response(
            200,
            json=document,
            request=httpx.Request("GET", DISCO_ADDR),
        )
        with pytest.raises(TypeError) as crash:
            iter(5)  # type: ignore[call-overload]
        cause = str(crash.value)
        result = process_discovery_response(response, requested_address=DISCO_ADDR)
        assert (result.is_successful, result.error_kind, result.error) == (
            False,
            DiscoveryErrorKind.INVALID_DOCUMENT,
            f"Invalid discovery document: {cause}",
        )

    @pytest.mark.parametrize(
        ("crash", "kind", "error"),
        [
            (
                TypeError("t"),
                DiscoveryErrorKind.INVALID_DOCUMENT,
                "Invalid discovery document: t",
            ),
            (
                AttributeError("a"),
                DiscoveryErrorKind.INVALID_DOCUMENT,
                "Invalid discovery document: a",
            ),
            (
                RuntimeError("r"),
                DiscoveryErrorKind.UNEXPECTED_ERROR,
                "Unexpected error during discovery document request: r",
            ),
        ],
        ids=["type-error", "attribute-error", "library-bug"],
    )
    def test_only_type_crashes_are_invalid_documents(
        self, monkeypatch, crash, kind, error
    ):
        def _crash(*_args, **_kwargs):
            raise crash

        monkeypatch.setattr(discovery_logic, "process_successful_response", _crash)
        response = httpx.Response(
            200, json={}, request=httpx.Request("GET", DISCO_ADDR)
        )
        result = process_discovery_response(response, requested_address=DISCO_ADDR)
        assert (result.error_kind, result.error) == (kind, error)


class TestJwksFailure:
    def test_default_message(self):
        exc = jwks_failure(JwksResponse(is_successful=False))
        assert isinstance(exc, JwksException)
        assert (type(exc), str(exc), exc.status_code) == (
            JwksException,
            "JWKS request failed",
            None,
        )

    def test_invalid_document(self):
        exc = jwks_failure(
            JwksResponse(
                is_successful=False,
                error="boom",
                error_kind=JwksErrorKind.INVALID_DOCUMENT,
            )
        )
        assert (type(exc), str(exc)) == (JwksValidationError, "boom")

    def test_failed_response_raises_and_logs(self, caplog):
        with (
            caplog.at_level(logging.ERROR, logger="py_identity_model"),
            pytest.raises(JwksException),
        ):
            validate_jwks_response(JwksResponse(is_successful=False, error="boom"))
        assert [r.getMessage() for r in caplog.records] == ["JWKS fetch failed: boom"]

    def test_empty_key_set(self, caplog):
        with (
            caplog.at_level(logging.ERROR, logger="py_identity_model"),
            pytest.raises(JwksValidationError) as excinfo,
        ):
            validate_jwks_response(JwksResponse(is_successful=True, keys=[]))
        assert str(excinfo.value) == "No keys available in JWKS response"
        assert [r.getMessage() for r in caplog.records] == [
            "No keys available in JWKS response"
        ]

    def test_key_set_passes(self):
        key = JsonWebKey(kty="RSA", kid="k", n="n", e="AQAB")
        validate_jwks_response(JwksResponse(is_successful=True, keys=[key]))


class TestSignatureRetryRefresh:
    """A failed refresh after a signature failure keeps the signature verdict."""

    def test_failed_refresh_keeps_signature_failure(self, caplog):
        failed = JwksResponse(
            is_successful=False,
            error="boom",
            error_kind=JwksErrorKind.UNEXPECTED_STATUS,
            status_code=503,
        )
        with (
            caplog.at_level(logging.WARNING, logger="py_identity_model"),
            pytest.raises(SignatureVerificationException) as excinfo,
        ):
            keep_signature_verdict_on_failed_refresh(failed)
        cause = excinfo.value.__cause__
        assert isinstance(cause, JwksException)
        assert (
            str(excinfo.value),
            excinfo.value.token_part,
            type(cause),
            str(cause),
            cause.status_code,
        ) == (
            "Signature verification failed; JWKS refresh failed",
            "signature",
            JwksException,
            "boom",
            503,
        )
        assert [r.getMessage() for r in caplog.records] == [
            "JWKS refresh failed after a signature failure: boom"
        ]

    def test_successful_refresh_passes(self, caplog):
        key = JsonWebKey(kty="RSA", kid="k", n="n", e="AQAB")
        with caplog.at_level(logging.WARNING, logger="py_identity_model"):
            keep_signature_verdict_on_failed_refresh(
                JwksResponse(is_successful=True, keys=[key])
            )
        assert caplog.records == []
