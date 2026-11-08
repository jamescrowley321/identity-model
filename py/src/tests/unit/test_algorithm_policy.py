"""One JWS algorithm allowlist per purpose, and one meaning for ``algorithms=None``.

Verify: ``DEFAULT_ALLOWED_ALGORITHMS``. Sign: ``SUPPORTED_SIGNING_ALGORITHMS``.
FAPI 2.0: ``FAPI2_ALLOWED_SIGNING_ALGORITHMS``, only when passed explicitly.
"""

from __future__ import annotations

import time
import uuid

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import jwt as pyjwt
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
import pytest

from py_identity_model import (
    DEFAULT_ALLOWED_ALGORITHMS,
    FAPI2_ALLOWED_SIGNING_ALGORITHMS,
    IntrospectionErrorKind,
    JwksResponse,
    SignedIntrospectionOptions,
    TokenValidationConfig,
    TokenValidationException,
)
from py_identity_model.aio import validate_token as avalidate_token
from py_identity_model.core import jwt_signing
from py_identity_model.core.dpop_verify import (
    DPoPErrorKind,
    DPoPProofRequest,
    DPoPValidationError,
    DPoPVerificationOptions,
    InMemoryDPoPReplayCache,
    verify_dpop_proof,
)
from py_identity_model.core.introspection_jwt import _algorithm, _Refused
from py_identity_model.core.jarm import select_jarm_algorithm
from py_identity_model.exceptions import JarmValidationException
from py_identity_model.sync import validate_token


VERIFY_SET = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
SIGNING_SET = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
URL = "https://rs.example.com/api"
INTROSPECTION_TYP = "token-introspection+jwt"


def _private_key(alg: str):
    if alg.startswith(("RS", "PS")):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if alg == "EdDSA":
        return ed25519.Ed25519PrivateKey.generate()
    curve = {
        "ES256": ec.SECP256R1(),
        "ES384": ec.SECP384R1(),
        "ES512": ec.SECP521R1(),
        "ES256K": ec.SECP256K1(),
    }[alg]
    return ec.generate_private_key(curve)


def _public_jwk(private_key) -> dict:
    public = private_key.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        return RSAAlgorithm.to_jwk(public, as_dict=True)
    if isinstance(public, ed25519.Ed25519PublicKey):
        return OKPAlgorithm.to_jwk(public, as_dict=True)
    return ECAlgorithm.to_jwk(public, as_dict=True)


@pytest.fixture(scope="module")
def keys() -> dict:
    return {alg: _private_key(alg) for alg in [*sorted(VERIFY_SET), "ES256K"]}


def _token(private_key, alg: str) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"sub": "user-1", "iat": now, "exp": now + 300}, private_key, algorithm=alg
    )


def _manual_config(jwk: dict, **kwargs) -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=False, key=jwk, **kwargs)


def _dpop_proof(private_key, alg: str) -> str:
    return pyjwt.encode(
        {"jti": str(uuid.uuid4()), "htm": "GET", "htu": URL, "iat": int(time.time())},
        private_key,
        algorithm=alg,
        headers={"typ": "dpop+jwt", "jwk": _public_jwk(private_key)},
    )


def _verify_dpop(proof: str, algorithms: frozenset[str] | None = None):
    options = DPoPVerificationOptions(
        algorithms=algorithms, replay_cache=InMemoryDPoPReplayCache()
    )
    return verify_dpop_proof(proof, DPoPProofRequest(method="GET", url=URL), options)


def _introspection_options(algorithms: frozenset[str] | None = None):
    return SignedIntrospectionOptions(
        issuer="https://as.example.com",
        jwks=JwksResponse(is_successful=True, keys=[]),
        algorithms=algorithms,
    )


@pytest.mark.unit
class TestPolicySets:
    def test_verify_set_contents(self):
        assert DEFAULT_ALLOWED_ALGORITHMS == VERIFY_SET

    def test_signing_set_contents(self):
        assert jwt_signing.SUPPORTED_SIGNING_ALGORITHMS == SIGNING_SET

    def test_fapi_set_contents(self):
        assert frozenset({"PS256", "ES256", "EdDSA"}) == (
            FAPI2_ALLOWED_SIGNING_ALGORITHMS
        )

    def test_verify_set_is_not_an_alias_of_the_signing_set(self):
        assert DEFAULT_ALLOWED_ALGORITHMS is not (
            jwt_signing.SUPPORTED_SIGNING_ALGORITHMS
        )

    def test_verify_set_has_no_hmac_or_none(self):
        assert {
            alg
            for alg in DEFAULT_ALLOWED_ALGORITHMS
            if alg.upper().startswith("HS") or alg.lower() == "none"
        } == set()


@pytest.mark.unit
class TestManualModeNoneIsVerifyDefault:
    @pytest.mark.parametrize("alg", sorted(VERIFY_SET))
    def test_sync_accepts_every_verify_alg(self, keys, alg):
        jwk = _public_jwk(keys[alg])

        claims = validate_token(_token(keys[alg], alg), _manual_config(jwk))

        assert claims["sub"] == "user-1"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("alg", sorted(VERIFY_SET))
    async def test_async_accepts_every_verify_alg(self, keys, alg):
        jwk = _public_jwk(keys[alg])

        claims = await avalidate_token(_token(keys[alg], alg), _manual_config(jwk))

        assert claims["sub"] == "user-1"

    def test_hmac_refused(self):
        secret = "s" * 64
        token = pyjwt.encode({"sub": "user-1"}, secret, algorithm="HS256")
        jwk = {"kty": "oct", "k": pyjwt.utils.base64url_encode(secret.encode())}

        with pytest.raises(TokenValidationException) as exc_info:
            validate_token(token, _manual_config(jwk.copy()))

        assert exc_info.value.details == {
            "alg": "HS256",
            "allowed": sorted(VERIFY_SET),
        }

    def test_explicit_list_still_restricts(self, keys):
        jwk = _public_jwk(keys["RS256"])

        with pytest.raises(TokenValidationException):
            validate_token(
                _token(keys["RS256"], "RS256"),
                _manual_config(jwk, algorithms=["PS256"]),
            )


@pytest.mark.unit
class TestDPoPNoneIsVerifyDefault:
    def test_accepted_algorithms_are_the_verify_set(self):
        assert DPoPVerificationOptions().accepted_algorithms == tuple(
            sorted(VERIFY_SET)
        )

    @pytest.mark.parametrize("alg", sorted(VERIFY_SET))
    def test_proof_with_every_verify_alg_accepted(self, keys, alg):
        proof = _verify_dpop(_dpop_proof(keys[alg], alg))

        assert proof.htu == URL

    def test_fapi_set_refuses_rs256(self, keys):
        with pytest.raises(DPoPValidationError) as exc_info:
            _verify_dpop(
                _dpop_proof(keys["RS256"], "RS256"), FAPI2_ALLOWED_SIGNING_ALGORITHMS
            )

        assert exc_info.value.kind is DPoPErrorKind.UNSUPPORTED_ALGORITHM


@pytest.mark.unit
class TestIntrospectionNoneIsVerifyDefault:
    @pytest.mark.parametrize("alg", sorted(VERIFY_SET))
    def test_every_verify_alg_allowed(self, alg):
        header = {"typ": INTROSPECTION_TYP, "alg": alg}

        assert _algorithm(header, _introspection_options()) == alg

    def test_fapi_set_refuses_rs256(self):
        options = _introspection_options(FAPI2_ALLOWED_SIGNING_ALGORITHMS)

        with pytest.raises(_Refused) as exc_info:
            _algorithm({"typ": INTROSPECTION_TYP, "alg": "RS256"}, options)

        assert exc_info.value.kind is IntrospectionErrorKind.UNSUPPORTED_ALGORITHM


@pytest.mark.unit
class TestVerifyIndependentOfSigning:
    """Extending the signing set must not widen any verification default."""

    @pytest.fixture
    def wider_signing(self, monkeypatch):
        monkeypatch.setattr(
            jwt_signing,
            "SUPPORTED_SIGNING_ALGORITHMS",
            jwt_signing.SUPPORTED_SIGNING_ALGORITHMS | {"ES256K"},
        )

    @pytest.mark.usefixtures("wider_signing")
    def test_verify_set_unchanged(self):
        assert DEFAULT_ALLOWED_ALGORITHMS == VERIFY_SET

    @pytest.mark.usefixtures("wider_signing")
    def test_token_validation_refuses_new_signing_alg(self, keys):
        jwk = _public_jwk(keys["ES256K"])

        with pytest.raises(TokenValidationException) as exc_info:
            validate_token(_token(keys["ES256K"], "ES256K"), _manual_config(jwk))

        assert exc_info.value.details == {
            "alg": "ES256K",
            "allowed": sorted(VERIFY_SET),
        }

    @pytest.mark.usefixtures("wider_signing")
    def test_dpop_options_refuse_new_signing_alg(self):
        with pytest.raises(ValueError, match="ES256K"):
            DPoPVerificationOptions(algorithms=frozenset({"ES256K"}))

    @pytest.mark.usefixtures("wider_signing")
    def test_jarm_default_refuses_new_signing_alg(self):
        with pytest.raises(JarmValidationException, match="not in the allowed set"):
            select_jarm_algorithm("ES256K", None)


@pytest.mark.unit
class TestKeyAlgorithmMismatchIsTyped:
    @pytest.mark.parametrize("algorithms", [None, ["ES256"]])
    def test_rsa_key_with_es256_token(self, keys, algorithms):
        jwk = _public_jwk(keys["RS256"])

        with pytest.raises(TokenValidationException) as exc_info:
            validate_token(
                _token(keys["ES256"], "ES256"),
                _manual_config(jwk, algorithms=algorithms),
            )

        assert exc_info.value.message == "Key does not fit the token algorithm"
