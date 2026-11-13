"""Signing key-strength floor (RFC 7518 §3.3, §3.5).

The library refuses to sign a request object or client assertion with an RSA
key under 2048 bits, the floor verification keys meet too.
"""

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from jwt.algorithms import ECAlgorithm
import pytest

from py_identity_model.core.key_strength import (
    MIN_RSA_KEY_BITS,
    enforce_signing_key_strength,
    load_signing_key,
)
from py_identity_model.exceptions import ConfigurationException, WeakSigningKeyError


WEAK_RSA_BITS = MIN_RSA_KEY_BITS - 1


def _pem(key) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.mark.unit
class TestEnforceSigningKeyStrength:
    def test_rsa_one_bit_under_floor_refused(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=WEAK_RSA_BITS)
        with pytest.raises(WeakSigningKeyError) as exc_info:
            enforce_signing_key_strength(_pem(key), "PS256")
        error = exc_info.value
        assert isinstance(error, ConfigurationException)
        assert (error.message, error.details) == (
            "RSA signing key is 2047 bits; at least 2048 required",
            {"kty": "RSA", "bits": WEAK_RSA_BITS, "min_bits": 2048},
        )

    def test_rsa_key_object_refused(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=WEAK_RSA_BITS)
        with pytest.raises(WeakSigningKeyError) as exc_info:
            enforce_signing_key_strength(key, "RS256")
        assert exc_info.value.bits == WEAK_RSA_BITS

    @pytest.mark.parametrize(
        ("key", "algorithm"),
        [
            (rsa.generate_private_key(public_exponent=65537, key_size=2048), "PS256"),
            (ec.generate_private_key(ec.SECP256R1()), "ES256"),
            (ed25519.Ed25519PrivateKey.generate(), "EdDSA"),
        ],
        ids=["rsa-2048", "ec-p256", "ed25519"],
    )
    def test_allowed_keys_pass(self, key, algorithm):
        assert enforce_signing_key_strength(_pem(key), algorithm) is None

    def test_unpreparable_key_left_to_signing(self):
        assert enforce_signing_key_strength(b"not a key", "PS256") is None


@pytest.mark.unit
class TestLoadSigningKey:
    def test_unknown_algorithm(self):
        key = ec.generate_private_key(ec.SECP256R1())
        assert load_signing_key(_pem(key), "XX999") is None

    def test_unsupported_key_left_to_signing(self, monkeypatch):
        def unsupported(_self, _key):
            raise UnsupportedAlgorithm("curve not supported")

        monkeypatch.setattr(ECAlgorithm, "prepare_key", unsupported)
        key = ec.generate_private_key(ec.SECP256R1())
        assert load_signing_key(_pem(key), "ES256") is None

    def test_prepares_like_pyjwt(self):
        key = ed25519.Ed25519PrivateKey.generate()
        loaded = load_signing_key(_pem(key), "EdDSA")
        assert isinstance(loaded, ed25519.Ed25519PrivateKey)
        assert loaded.public_key() == key.public_key()
