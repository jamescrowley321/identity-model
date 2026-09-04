"""
Security tests for verification-key normalization at the PyJWT boundary
(``py_identity_model.core.jwt_helpers._normalize_verification_key``).

Two defects motivated this normalization:

1. **Typed key rejected.** ``get_jwks`` returns typed ``JsonWebKey`` objects, but
   ``TokenValidationConfig.key`` fed them straight into PyJWT, which called
   ``.get()`` on the dataclass → ``AttributeError``. The round-trip now works.

2. **Null private member misread as a private key.** PyJWT's
   ``Algorithm.from_jwk`` classifies a JWK public-vs-private by key *name presence*
   (``"d" in obj``), not value. A public JWK carrying ``"d": None`` (e.g. from a
   naive dataclass-to-dict conversion) was routed into private-key construction
   and raised ``TypeError: Expected a string value``. Stripping ``None`` members
   closes that trap while never removing a genuine private value.
"""

import json
import time

import pytest

from py_identity_model import JsonWebKey, TokenValidationConfig, validate_token
from py_identity_model.aio import validate_token as async_validate_token
from py_identity_model.core.jwt_helpers import _normalize_verification_key
from py_identity_model.exceptions import ConfigurationException

from ..unit.token_validation_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit


def _token_for(key_dict: dict, pem: bytes) -> str:
    return sign_jwt(
        pem,
        {
            "sub": "u1",
            "aud": "a",
            "iss": "i",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        headers={"kid": key_dict["kid"]},
    )


def _config(key) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=False,
        key=key,
        algorithms=["RS256"],
        audience="a",
        issuer="i",
    )


class TestNormalizeVerificationKey:
    """Unit-level contract of ``_normalize_verification_key``."""

    def test_typed_jsonwebkey_returns_as_dict(self):
        key_dict, _ = generate_rsa_keypair()
        typed = JsonWebKey.from_json(json.dumps(key_dict))
        assert _normalize_verification_key(typed) == typed.as_dict()

    def test_dict_strips_only_none_members(self):
        """None-valued members are dropped; every real value is preserved.

        Kills mutants that skip the filter entirely or invert the membership.
        """
        key_dict, _ = generate_rsa_keypair()
        polluted = {**key_dict, "d": None, "p": None, "q": None}
        assert _normalize_verification_key(polluted) == key_dict

    def test_falsy_but_non_none_values_are_kept(self):
        """Only ``None`` is stripped — empty string and ``0`` survive.

        Kills the ``v is not None`` -> ``v`` (truthiness) mutant, which would
        also drop legitimate falsy JWK members.
        """
        src = {"kty": "RSA", "n": "AA", "e": "AQAB", "kid": "", "x5c": 0}
        assert _normalize_verification_key(src) == src

    def test_dict_without_none_is_unchanged(self):
        key_dict, _ = generate_rsa_keypair()
        assert _normalize_verification_key(key_dict) == key_dict

    def test_genuine_private_values_preserved(self):
        """A real private key's members hold real values, so nothing is stripped.

        Guards against a regression where the None-filter is widened to also
        remove present private material.
        """
        priv = {
            "kty": "RSA",
            "n": "AA",
            "e": "AQAB",
            "d": "ZZ",
            "p": "PP",
            "q": "QQ",
            "dp": "DP",
            "dq": "DQ",
            "qi": "QI",
        }
        assert _normalize_verification_key(priv) == priv

    @pytest.mark.parametrize("bad", ["not-a-key", 123, None, [1, 2, 3], b"bytes"])
    def test_wrong_type_raises_configuration_exception(self, bad):
        with pytest.raises(ConfigurationException) as exc:
            _normalize_verification_key(bad)
        msg = str(exc.value)
        assert "JsonWebKey or a JWK dict" in msg
        # The concrete offending type is named in the error — asserts against the
        # `type(key)` -> `type(None)` mutant (every non-None input distinguishes
        # "got <type>" from "got NoneType").
        assert f"got {type(bad).__name__}" in msg


class TestValidateTokenAcceptsTypedAndNullDictKeys:
    """End-to-end: the manual-validation path accepts what ``get_jwks`` emits."""

    def test_typed_key_sync(self):
        key_dict, pem = generate_rsa_keypair()
        token = _token_for(key_dict, pem)
        typed = JsonWebKey.from_json(json.dumps(key_dict))
        assert validate_token(token, _config(typed))["sub"] == "u1"

    @pytest.mark.asyncio
    async def test_typed_key_async(self):
        key_dict, pem = generate_rsa_keypair()
        token = _token_for(key_dict, pem)
        typed = JsonWebKey.from_json(json.dumps(key_dict))
        decoded = await async_validate_token(token, _config(typed))
        assert decoded["sub"] == "u1"

    def test_public_dict_with_null_private_member_sync(self):
        """A public JWK carrying ``d: None`` must verify, not crash.

        Pins the fix for PyJWT's name-presence private-key detection.
        """
        key_dict, pem = generate_rsa_keypair()
        token = _token_for(key_dict, pem)
        polluted = {**key_dict, "d": None, "p": None, "q": None}
        assert validate_token(token, _config(polluted))["sub"] == "u1"

    @pytest.mark.asyncio
    async def test_public_dict_with_null_private_member_async(self):
        key_dict, pem = generate_rsa_keypair()
        token = _token_for(key_dict, pem)
        polluted = {**key_dict, "d": None, "p": None, "q": None}
        decoded = await async_validate_token(token, _config(polluted))
        assert decoded["sub"] == "u1"

    def test_plain_public_dict_still_works(self):
        """Backward compatibility: the original dict input path is unchanged."""
        key_dict, pem = generate_rsa_keypair()
        token = _token_for(key_dict, pem)
        assert validate_token(token, _config(key_dict))["sub"] == "u1"
