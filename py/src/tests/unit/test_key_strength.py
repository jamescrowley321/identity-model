"""Verification key-strength floor (#952).

RSA verification keys need a modulus of at least 2048 bits (RFC 7518 §3.3,
§3.5) and EC keys a coordinate of at least 224 bits (FAPI 2.0 Security
Profile §5.4.1). The floor is checked on the key selected to verify a token;
a weak key is a typed error, not a skipped key or a kid miss.
"""

import base64
import json
import warnings

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt as pyjwt
from jwt.warnings import InsecureKeyLengthWarning
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.core.key_strength import (
    MIN_EC_KEY_BITS,
    MIN_RSA_KEY_BITS,
    enforce_key_strength,
)
from py_identity_model.core.models import JsonWebKey, TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException, WeakKeyException
from py_identity_model.sync import token_validation as sync_tv

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import DISCO_RESPONSE_WITH_JWKS


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
CLAIMS = {"sub": "user1", "iss": ISSUER}


def _b64u(value: int, length: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _rsa(bits: int, kid: str) -> tuple[dict, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "n": _b64u(numbers.n, (bits + 7) // 8),
        "e": _b64u(numbers.e, 3),
    }
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return jwk, pem


def _ec_jwk(curve: ec.EllipticCurve, crv: str, kid: str) -> dict:
    numbers = ec.generate_private_key(curve).public_key().public_numbers()
    size = (curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "crv": crv,
        "x": _b64u(numbers.x, size),
        "y": _b64u(numbers.y, size),
    }


@pytest.fixture(scope="module")
def rsa_1024() -> tuple[dict, str]:
    """A 1024-bit RSA JWK and an RS256 token it signed."""
    jwk, pem = _rsa(1024, "weak-rsa")
    # PyJWT warns when *signing* with a short key; only verification is tested.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureKeyLengthWarning)
        token = pyjwt.encode(
            CLAIMS, pem, algorithm="RS256", headers={"kid": "weak-rsa"}
        )
    return jwk, token


@pytest.fixture(scope="module")
def rsa_2048() -> tuple[dict, bytes]:
    return _rsa(2048, "rsa-2048")


class TestEnforceKeyStrength:
    def test_floors_match_the_specs(self):
        assert (MIN_RSA_KEY_BITS, MIN_EC_KEY_BITS) == (2048, 224)

    def test_rsa_1024_is_rejected_with_details(self, rsa_1024):
        jwk, _ = rsa_1024

        with pytest.raises(WeakKeyException) as exc_info:
            enforce_key_strength(jwk)

        assert exc_info.value.token_part == "header"
        assert exc_info.value.details == {
            "kid": "weak-rsa",
            "kty": "RSA",
            "bits": 1024,
            "min_bits": 2048,
        }

    def test_rsa_2048_passes(self, rsa_2048):
        jwk, _ = rsa_2048
        assert enforce_key_strength(jwk) is None

    def test_rsa_strength_is_the_modulus_bit_length(self, rsa_2048):
        # A 2048-bit modulus with a leading zero octet is still 2048 bits, and
        # a 2047-bit modulus in 256 octets is weak: octet counts don't decide.
        jwk, _ = rsa_2048
        n = int.from_bytes(
            base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big"
        )
        padded = {**jwk, "n": _b64u(n, 257)}
        assert enforce_key_strength(padded) is None

        short = {**jwk, "n": _b64u(n >> 1, 256)}
        with pytest.raises(WeakKeyException) as exc_info:
            enforce_key_strength(short)
        assert exc_info.value.details["bits"] == MIN_RSA_KEY_BITS - 1

    def test_ec_p192_is_rejected(self):
        jwk = _ec_jwk(ec.SECP192R1(), "P-192", "weak-ec")

        with pytest.raises(WeakKeyException) as exc_info:
            enforce_key_strength(jwk)

        assert exc_info.value.details == {
            "kid": "weak-ec",
            "kty": "EC",
            "bits": 192,
            "min_bits": 224,
        }

    @pytest.mark.parametrize(
        ("curve", "crv"),
        [
            (ec.SECP224R1(), "P-224"),
            (ec.SECP256R1(), "P-256"),
            (ec.SECP384R1(), "P-384"),
            (ec.SECP521R1(), "P-521"),
        ],
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ec_curves_at_or_above_224_bits_pass(self, curve, crv):
        assert enforce_key_strength(_ec_jwk(curve, crv, crv)) is None

    @pytest.mark.parametrize(
        "jwk",
        [
            {"kty": "OKP", "crv": "Ed25519", "x": "AA"},
            {"kty": "oct", "k": "AA"},
            {"kty": "RSA"},
            {"kty": "RSA", "n": "!!not base64!!", "e": "AQAB"},
            {"kty": "EC", "crv": "P-256", "x": 5, "y": "AA"},
        ],
        ids=["okp", "oct", "rsa-without-n", "rsa-undecodable-n", "ec-non-string-x"],
    )
    def test_keys_without_a_floor_or_measurable_size_are_left_alone(self, jwk):
        # OKP keys are fixed-size and oct keys aren't asymmetric; material that
        # doesn't decode is left for key conversion to reject.
        assert enforce_key_strength(jwk) is None

    def test_kid_is_none_when_the_key_has_none(self, rsa_1024):
        jwk, _ = rsa_1024
        anonymous = {k: v for k, v in jwk.items() if k != "kid"}

        with pytest.raises(WeakKeyException) as exc_info:
            enforce_key_strength(anonymous)

        assert exc_info.value.details["kid"] is None


class TestDecodeRejectsWeakKey:
    def test_weak_rsa_key_is_rejected_before_verification(self, rsa_1024):
        jwk, token = rsa_1024

        with pytest.raises(WeakKeyException):
            decode_and_validate_jwt(token, jwk, ["RS256"], None, None, None)

    def test_typed_json_web_key_is_checked_too(self, rsa_1024):
        jwk, token = rsa_1024

        with pytest.raises(WeakKeyException):
            decode_and_validate_jwt(
                token,
                JsonWebKey.from_json(json.dumps(jwk)),
                ["RS256"],
                None,
                None,
                None,
            )

    def test_weak_key_exception_is_a_token_validation_exception(self):
        assert issubclass(WeakKeyException, TokenValidationException)

    def test_strong_rsa_key_still_verifies(self, rsa_2048):
        jwk, pem = rsa_2048
        token = pyjwt.encode(
            CLAIMS, pem, algorithm="RS256", headers={"kid": "rsa-2048"}
        )

        assert decode_and_validate_jwt(token, jwk, ["RS256"], None, None, None) == (
            CLAIMS
        )


def _manual_config(jwk: dict) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=False, key=jwk, algorithms=["RS256"], issuer=ISSUER
    )


def _disco_config() -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, issuer=ISSUER)


@pytest.fixture
async def _clear_caches():
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()
    yield
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()


def _mock_op(jwk: dict) -> respx.Route:
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    return respx.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [jwk]})
    )


@pytest.mark.usefixtures("_clear_caches")
class TestValidateTokenRejectsWeakKey:
    def test_manual_mode(self, rsa_1024):
        jwk, token = rsa_1024

        with pytest.raises(WeakKeyException):
            sync_tv.validate_token(token, _manual_config(jwk))

    @respx.mock
    def test_discovery_mode_fails_without_a_jwks_refresh(self, rsa_1024):
        # A weak key is not a kid miss: the JWKS is fetched once, not refreshed.
        jwk, token = rsa_1024
        jwks_route = _mock_op(jwk)

        with pytest.raises(WeakKeyException):
            sync_tv.validate_token(token, _disco_config(), DISCO_URL)

        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_discovery_mode_fails_without_a_jwks_refresh(self, rsa_1024):
        jwk, token = rsa_1024
        jwks_route = _mock_op(jwk)

        with pytest.raises(WeakKeyException):
            await aio_tv.validate_token(token, _disco_config(), DISCO_URL)

        assert jwks_route.call_count == 1
