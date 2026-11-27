"""Fail-closed control test: every token rejection carries a typed kind.

A caller branching on ``TokenValidationException.validation_kind`` must get
the kind for the rule that rejected the token, never a silent fallback. Each
case pins the exception type, kind, message and ``token_part`` by equality.
"""

import base64
import json

from jwt.exceptions import InvalidTokenError, MissingRequiredClaimError
import pytest

from py_identity_model.core.jwt_helpers import (
    _invalid_token_kind,
    decode_and_validate_jwt,
)
from py_identity_model.core.parsers import find_key_by_kid
from py_identity_model.core.token_validation_logic import resolve_algorithms
from py_identity_model.exceptions import (
    TokenValidationErrorKind,
    TokenValidationException,
)

from ._security_helpers import generate_rsa_keypair, sign_jwt


pytestmark = pytest.mark.unit


def _contract(exc: TokenValidationException) -> dict:
    return {
        "type": type(exc),
        "validation_kind": exc.validation_kind,
        "message": exc.message,
        "token_part": exc.token_part,
    }


def _header_only_jwt(alg: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode())
    return f"{header.rstrip(b'=').decode()}.e30.c2ln"


def _decode(claims: dict, algorithms: list[str]) -> None:
    key_dict, pem = generate_rsa_keypair()
    decode_and_validate_jwt(
        sign_jwt(pem, claims),
        key_dict,
        algorithms,
        audience=None,
        issuer=None,
        options=None,
    )


def test_non_string_sub_is_a_subject_rejection():
    with pytest.raises(TokenValidationException) as exc_info:
        _decode({"sub": 123}, ["RS256"])

    exc = exc_info.value
    assert _contract(exc) == {
        "type": TokenValidationException,
        "validation_kind": TokenValidationErrorKind.SUBJECT,
        "message": f"Invalid token: {exc.__cause__!s}",
        "token_part": None,
    }


def test_header_alg_outside_algorithms_is_an_algorithm_rejection():
    with pytest.raises(TokenValidationException) as exc_info:
        _decode({"sub": "user"}, ["ES256"])

    exc = exc_info.value
    assert _contract(exc) == {
        "type": TokenValidationException,
        "validation_kind": TokenValidationErrorKind.ALGORITHM,
        "message": f"Invalid token: {exc.__cause__!s}",
        "token_part": None,
    }


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(InvalidTokenError("unmapped"), id="unmapped-error"),
        pytest.param(MissingRequiredClaimError("nbf"), id="unmapped-required-claim"),
    ],
)
def test_unmapped_pyjwt_error_is_unclassified_never_none(error):
    assert _invalid_token_kind(error) is TokenValidationErrorKind.UNCLASSIFIED


def test_empty_key_set_is_a_key_selection_rejection():
    with pytest.raises(TokenValidationException) as exc_info:
        find_key_by_kid("kid-1", [], "RS256")

    assert _contract(exc_info.value) == {
        "type": TokenValidationException,
        "validation_kind": TokenValidationErrorKind.KEY_SELECTION,
        "message": "No keys available in JWKS response",
        "token_part": None,
    }


def test_key_that_does_not_fit_alg_is_a_key_selection_rejection():
    with pytest.raises(TokenValidationException) as exc_info:
        decode_and_validate_jwt(
            _header_only_jwt("RS256"),
            {"kty": "RSA"},
            ["RS256"],
            audience=None,
            issuer=None,
            options=None,
        )

    assert _contract(exc_info.value) == {
        "type": TokenValidationException,
        "validation_kind": TokenValidationErrorKind.KEY_SELECTION,
        "message": "Key cannot verify the token",
        "token_part": "header",
    }


def test_default_allowed_header_alg_is_accepted():
    assert resolve_algorithms(_header_only_jwt("RS256"), None) == ["RS256"]


@pytest.mark.parametrize(
    ("alg", "kind"),
    [
        pytest.param("HS256", TokenValidationErrorKind.ALGORITHM, id="hs256"),
        pytest.param("none", TokenValidationErrorKind.ALGORITHM_NONE, id="none"),
        pytest.param("None", TokenValidationErrorKind.ALGORITHM_NONE, id="mixed-case"),
    ],
)
def test_header_alg_outside_defaults_is_rejected_with_its_kind(alg, kind):
    with pytest.raises(TokenValidationException) as exc_info:
        resolve_algorithms(_header_only_jwt(alg), None)

    assert _contract(exc_info.value) == {
        "type": TokenValidationException,
        "validation_kind": kind,
        "message": f"Algorithm '{alg}' is not in the allowed algorithms",
        "token_part": "header",
    }
