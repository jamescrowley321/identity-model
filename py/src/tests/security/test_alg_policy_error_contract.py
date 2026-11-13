"""Full error contract for the algorithm-policy rejections (#1058).

Each rejection is pinned by type, message, ``token_part``, ``details`` and the
chained cause, so a caller branching on any of them cannot be silently broken.
"""

from __future__ import annotations

import logging

import jwt as pyjwt
import pytest

from py_identity_model.core.jarm import select_jarm_algorithm
from py_identity_model.core.jwt_helpers import decode_and_validate_jwt
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import resolve_algorithms
from py_identity_model.core.validators import validate_token_config
from py_identity_model.exceptions import (
    ConfigurationException,
    JarmValidationException,
    TokenValidationException,
)


def test_key_that_does_not_fit_alg_full_contract(caplog):
    with (
        caplog.at_level(logging.ERROR, logger="py_identity_model"),
        pytest.raises(TokenValidationException) as exc_info,
    ):
        decode_and_validate_jwt(
            # Header {"alg": "RS256"}: readable, so the failure is the key.
            "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
            {"kty": "RSA"},
            ["RS256"],
            audience=None,
            issuer=None,
            options=None,
        )

    exc = exc_info.value
    cause = exc.__cause__
    assert type(exc) is TokenValidationException
    assert isinstance(cause, pyjwt.InvalidKeyError)
    assert exc.message == "Key cannot verify the token"
    assert exc.token_part == "header"
    assert exc.details == {"error": str(cause)}
    assert str(cause)
    assert [r.getMessage() for r in caplog.records] == [
        f"Key cannot verify the token: {cause!s}"
    ]


def test_unreadable_header_with_default_algs_full_contract():
    with pytest.raises(TokenValidationException) as exc_info:
        resolve_algorithms("not-a-jwt", None)

    exc = exc_info.value
    cause = exc.__cause__
    assert type(exc) is TokenValidationException
    assert isinstance(cause, pyjwt.PyJWTError)
    assert str(cause)
    assert exc.message == f"Invalid token: {cause!s}"
    assert exc.token_part == "header"
    assert exc.details == {"error": str(cause)}


def test_jarm_empty_allowlist_message():
    with pytest.raises(JarmValidationException) as exc_info:
        select_jarm_algorithm("RS256", [])
    assert exc_info.value.message == "No allowed JARM signing algorithms configured"


def test_missing_key_without_disco_message():
    with pytest.raises(ConfigurationException) as exc_info:
        validate_token_config(
            TokenValidationConfig(perform_disco=False, algorithms=["RS256"])
        )
    assert (
        exc_info.value.message
        == "TokenValidationConfig.key is required if perform_disco is False"
    )
