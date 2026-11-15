"""A key's declared ``alg`` binds verification when no algorithm list is given.

RFC 7517 §4.4: a key that declares ``alg`` is used with that algorithm only.
RFC 7517 §4.2: a key whose ``use`` is absent or empty may verify a signature.
"""

from __future__ import annotations

import json
import time

import pytest

from py_identity_model import JsonWebKey, TokenValidationConfig
from py_identity_model.core.parsers import is_signing_key
from py_identity_model.core.token_validation_logic import decode_with_config
from py_identity_model.exceptions import KeyAlgorithmMismatchException

from ..token_validation_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit

JWT_ALG = "RS256"
OTHER_ALG = "RS384"


def _token(pem: bytes, kid: str) -> str:
    now = int(time.time())
    return sign_jwt(
        pem,
        {"sub": "u1", "aud": "a", "iss": "i", "iat": now, "exp": now + 3600},
        headers={"kid": kid},
    )


def _typed(key: dict) -> JsonWebKey:
    return JsonWebKey.from_json(json.dumps(key))


def _config(key: dict | JsonWebKey) -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=False, key=key, algorithms=None, audience="a", issuer="i"
    )


def _assert_mismatch(exc: KeyAlgorithmMismatchException, kid: str) -> None:
    assert str(exc) == (
        f"Key algorithm '{OTHER_ALG}' does not match JWT algorithm '{JWT_ALG}'"
    )
    assert exc.token_part == "header"
    assert exc.details == {"kid": kid, "key_alg": OTHER_ALG, "jwt_alg": JWT_ALG}


@pytest.mark.parametrize("typed", [False, True])
def test_decode_with_config_rejects_key_declaring_another_alg(typed):
    key, pem = generate_rsa_keypair()
    declared = {**key, "alg": OTHER_ALG}
    mismatched = _typed(declared) if typed else declared
    with pytest.raises(KeyAlgorithmMismatchException) as exc_info:
        decode_with_config(_token(pem, key["kid"]), _config(mismatched))
    _assert_mismatch(exc_info.value, key["kid"])


@pytest.mark.parametrize("declares_alg", [True, False])
def test_decode_with_config_accepts_matching_or_undeclared_key_alg(declares_alg):
    key, pem = generate_rsa_keypair()
    token = _token(pem, key["kid"])
    if not declares_alg:
        key = {k: v for k, v in key.items() if k != "alg"}
    assert decode_with_config(token, _config(key))["sub"] == "u1"


@pytest.mark.parametrize("use", [None, "", "sig"])
def test_absent_empty_or_sig_use_is_a_signing_key(use):
    key, _ = generate_rsa_keypair()
    assert is_signing_key(_typed({**key, "use": use})) is True


@pytest.mark.parametrize("use", ["enc", "XXXX", "SIG", "https://example.com/use"])
def test_any_other_use_is_not_a_signing_key(use):
    key, _ = generate_rsa_keypair()
    assert is_signing_key(_typed({**key, "use": use})) is False
