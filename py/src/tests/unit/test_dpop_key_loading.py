"""Loading a stored DPoP key (#1063): ``DPoPKey.from_pem`` and ``from_jwk``.

Tokens stay bound to the key's thumbprint (RFC 9449 §6.1), so a client that
refreshes after a restart has to sign with the same key.
"""

import json
import re
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
import jwt as pyjwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
import pytest

from py_identity_model import DPoPAlgorithm, DPoPKey, generate_dpop_key
from py_identity_model.core import dpop as dpop_module
from py_identity_model.core.dpop import create_dpop_proof


WEAK_RSA_BITS = 1024
MIN_RSA_BITS = 2048
TOKEN_URL = "https://auth.example.com/token"


def _private_jwk(key: DPoPKey) -> dict:
    private = load_pem_private_key(key.private_key_pem, password=None)
    if isinstance(private, ec.EllipticCurvePrivateKey):
        return json.loads(ECAlgorithm.to_jwk(private))
    if isinstance(private, ed25519.Ed25519PrivateKey):
        return json.loads(OKPAlgorithm.to_jwk(private))
    assert isinstance(private, rsa.RSAPrivateKey)
    return json.loads(RSAAlgorithm.to_jwk(private))


def _proof_verifies(key: DPoPKey) -> bool:
    proof = create_dpop_proof(key, "POST", TOKEN_URL)
    jwk = pyjwt.get_unverified_header(proof)["jwk"]
    signing_key = pyjwt.PyJWK(jwk).key
    pyjwt.decode(proof, signing_key, algorithms=[key.algorithm.value])
    return True


@pytest.mark.unit
class TestAlgorithmEnum:
    def test_generated_key_reports_the_enum(self):
        key = generate_dpop_key("PS256")
        assert key.algorithm is DPoPAlgorithm.PS256
        assert key.algorithm == "PS256"

    def test_default_is_es256(self):
        assert DPoPKey().algorithm is DPoPAlgorithm.ES256

    def test_unknown_algorithm_refused(self):
        with pytest.raises(ValueError, match="Unsupported DPoP algorithm: HS256"):
            DPoPKey("HS256")


@pytest.mark.unit
class TestFromPem:
    @pytest.mark.parametrize("algorithm", list(DPoPAlgorithm))
    def test_round_trip_keeps_the_thumbprint(self, algorithm):
        original = generate_dpop_key(algorithm)
        loaded = DPoPKey.from_pem(original.private_key_pem, algorithm)
        assert loaded.algorithm is algorithm
        assert loaded.jwk_thumbprint == original.jwk_thumbprint
        assert _proof_verifies(loaded)

    def test_accepts_str_pem(self):
        original = generate_dpop_key("ES256")
        loaded = DPoPKey.from_pem(original.private_key_pem.decode(), "ES256")
        assert loaded.jwk_thumbprint == original.jwk_thumbprint

    def test_encrypted_pem_with_password(self):
        private = ec.generate_private_key(ec.SECP256R1())
        pem = private.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"pw")
        )
        loaded = DPoPKey.from_pem(pem, DPoPAlgorithm.ES256, password=b"pw")
        assert loaded.algorithm is DPoPAlgorithm.ES256

    def test_wrong_password_refused(self):
        private = ec.generate_private_key(ec.SECP256R1())
        pem = private.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"pw")
        )
        with pytest.raises(ValueError, match="Cannot load the DPoP private key"):
            DPoPKey.from_pem(pem, DPoPAlgorithm.ES256, password=b"other")

    def test_garbage_refused(self):
        with pytest.raises(ValueError, match="Cannot load the DPoP private key"):
            DPoPKey.from_pem(b"not a pem", DPoPAlgorithm.ES256)

    @pytest.mark.parametrize(
        ("algorithm", "key_algorithm"),
        [
            ("ES256", "ES384"),
            ("ES384", "ES512"),
            ("ES512", "ES256"),
            ("EdDSA", "ES256"),
            ("PS256", "EdDSA"),
            ("RS256", "ES256"),
        ],
    )
    def test_key_that_does_not_fit_refused(self, algorithm, key_algorithm):
        pem = generate_dpop_key(key_algorithm).private_key_pem
        with pytest.raises(
            ValueError, match=f"Key is not a private key {algorithm} can sign with"
        ):
            DPoPKey.from_pem(pem, algorithm)

    @pytest.mark.parametrize("bits", [WEAK_RSA_BITS, MIN_RSA_BITS - 1])
    def test_weak_rsa_refused(self, bits, monkeypatch):
        # Stand in for a loaded RSA key of *bits*, so the test never creates a
        # weak key: only the size floor in the loader is under test.
        weak = mock.create_autospec(rsa.RSAPrivateKey, instance=True)
        weak.key_size = bits
        monkeypatch.setattr(dpop_module, "load_pem_private_key", lambda *_, **__: weak)
        with pytest.raises(ValueError, match="Key is not a private key PS256"):
            DPoPKey.from_pem(b"pem", "PS256")

    def test_unknown_algorithm_refused(self):
        pem = generate_dpop_key("ES256").private_key_pem
        with pytest.raises(ValueError, match="Unsupported DPoP algorithm: none"):
            DPoPKey.from_pem(pem, "none")


@pytest.mark.unit
class TestFromJwk:
    @pytest.mark.parametrize("algorithm", list(DPoPAlgorithm))
    def test_round_trip_keeps_the_thumbprint(self, algorithm):
        original = generate_dpop_key(algorithm)
        loaded = DPoPKey.from_jwk(_private_jwk(original), algorithm)
        assert loaded.algorithm is algorithm
        assert loaded.jwk_thumbprint == original.jwk_thumbprint
        assert _proof_verifies(loaded)

    def test_algorithm_from_the_jwk_alg_member(self):
        original = generate_dpop_key("ES384")
        loaded = DPoPKey.from_jwk({**_private_jwk(original), "alg": "ES384"})
        assert loaded.algorithm is DPoPAlgorithm.ES384

    def test_argument_overrides_alg_member(self):
        original = generate_dpop_key("ES256")
        loaded = DPoPKey.from_jwk({**_private_jwk(original), "alg": "ES384"}, "ES256")
        assert loaded.algorithm is DPoPAlgorithm.ES256

    def test_no_algorithm_refused(self):
        jwk = _private_jwk(generate_dpop_key("ES256"))
        message = "A DPoP JWK needs an algorithm: pass one or set 'alg'"
        with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
            DPoPKey.from_jwk(jwk)

    def test_public_jwk_refused(self):
        key = generate_dpop_key("ES256")
        with pytest.raises(ValueError, match="Key is not a private key ES256"):
            DPoPKey.from_jwk(key.public_jwk, "ES256")

    def test_unsupported_kty_refused(self):
        with pytest.raises(ValueError, match="Unsupported JWK kty for DPoP: 'oct'"):
            DPoPKey.from_jwk({"kty": "oct", "k": "c2VjcmV0"}, "ES256")

    def test_malformed_jwk_refused(self):
        with pytest.raises(ValueError, match="Cannot load the DPoP JWK"):
            DPoPKey.from_jwk({"kty": "EC", "crv": "P-256"}, "ES256")

    def test_curve_mismatch_refused(self):
        jwk = _private_jwk(generate_dpop_key("ES384"))
        with pytest.raises(ValueError, match="Key is not a private key ES256"):
            DPoPKey.from_jwk(jwk, "ES256")


@pytest.mark.unit
def test_public_key_pem_is_not_a_private_key():
    private = load_pem_private_key(
        generate_dpop_key("ES256").private_key_pem, password=None
    )
    public_pem = private.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError, match="Cannot load the DPoP private key"):
        DPoPKey.from_pem(public_pem, "ES256")
