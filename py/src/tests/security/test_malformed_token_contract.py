"""Fail-closed control test: a token that is not a compact JWS is typed (#1179).

Every malformed shape raises ``MalformedTokenException``, never a PyJWT or
JSON decoder error, from ``check_compact_jws`` and from the header extractors
that discovery mode calls before the token is decoded. Each case pins the
message, ``token_part``, ``details`` and the chained cause.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import cast

import jwt as pyjwt
import pytest

from py_identity_model.core.parsers import (
    check_compact_jws,
    extract_jwt_header_fields,
    extract_kid_from_jwt,
)
from py_identity_model.exceptions import MalformedTokenException


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# Segment lengths of 3 ("e30"), 10 and 4 characters cover each unpadded
# base64url remainder a valid segment can have.
HEADER = _b64(b'{"alg":"RS256","kid":"k1"}')
EMPTY_OBJECT = "e30"
PAYLOAD = _b64(b'{"a":1}')
SIGNATURE = "c2ln"
VALID = f"{HEADER}.{PAYLOAD}.{SIGNATURE}"
DEEP_JSON = b"[" * 100_000 + b"]" * 100_000
NOT_UTF8 = _b64(b"\xff\xfe")
KID_NOT_STRING = _b64(b'{"alg":"RS256","kid":1}')
URLSAFE_HEADER = _b64(b'{"alg":"RS256","kid":"a-_"}')

CASES = [
    # (id, token, reason, token_part, cause type or None)
    ("empty", "", "compact JWS must have 3 segments, got 1", None, None),
    (
        "two-segments",
        f"{HEADER}.{PAYLOAD}",
        "compact JWS must have 3 segments, got 2",
        None,
        None,
    ),
    (
        "four-segments",
        f"{VALID}.{SIGNATURE}",
        "compact JWS must have 3 segments, got 4",
        None,
        None,
    ),
    (
        "header-bad-char",
        f"e30*.{PAYLOAD}.{SIGNATURE}",
        "header is not valid base64url",
        "header",
        binascii.Error,
    ),
    (
        "header-bad-length",
        f"a.{PAYLOAD}.{SIGNATURE}",
        "header is not valid base64url",
        "header",
        binascii.Error,
    ),
    (
        "header-non-ascii",
        f"é30.{PAYLOAD}.{SIGNATURE}",
        "header is not valid base64url",
        "header",
        ValueError,
    ),
    (
        "header-padded",
        f"e30=.{PAYLOAD}.{SIGNATURE}",
        "header is not unpadded base64url",
        "header",
        None,
    ),
    (
        "payload-bad-char",
        f"{HEADER}.e30*.{SIGNATURE}",
        "payload is not valid base64url",
        "payload",
        binascii.Error,
    ),
    (
        "payload-plus",
        f"{HEADER}.ab+c.{SIGNATURE}",
        "payload is not unpadded base64url",
        "payload",
        None,
    ),
    (
        "signature-bad-char",
        f"{HEADER}.{PAYLOAD}.sig!",
        "signature is not valid base64url",
        "signature",
        binascii.Error,
    ),
    (
        "signature-slash",
        f"{HEADER}.{PAYLOAD}.ab/c",
        "signature is not unpadded base64url",
        "signature",
        None,
    ),
    (
        "header-not-json",
        f"{_b64(b'not json')}.{PAYLOAD}.{SIGNATURE}",
        "header is not valid JSON",
        "header",
        json.JSONDecodeError,
    ),
    (
        "header-not-utf8",
        f"{NOT_UTF8}.{PAYLOAD}.{SIGNATURE}",
        "header is not valid JSON",
        "header",
        UnicodeDecodeError,
    ),
    (
        "header-too-deep",
        f"{_b64(DEEP_JSON)}.{PAYLOAD}.{SIGNATURE}",
        "header is not valid JSON",
        "header",
        RecursionError,
    ),
    (
        "header-not-object",
        f"{_b64(b'[1]')}.{PAYLOAD}.{SIGNATURE}",
        "header is not a JSON object",
        "header",
        None,
    ),
    (
        "payload-not-json",
        f"{HEADER}.{_b64(b'not json')}.{SIGNATURE}",
        "payload is not valid JSON",
        "payload",
        json.JSONDecodeError,
    ),
    (
        "payload-not-object",
        f"{HEADER}.{_b64(b'[1]')}.{SIGNATURE}",
        "payload is not a JSON object",
        "payload",
        None,
    ),
]

_PARAMS = [pytest.param(*case[1:], id=case[0]) for case in CASES]

_EXTRACTORS = [
    pytest.param(check_compact_jws, id="check_compact_jws"),
    pytest.param(extract_jwt_header_fields, id="extract_jwt_header_fields"),
    pytest.param(extract_kid_from_jwt, id="extract_kid_from_jwt"),
]


@pytest.mark.parametrize("parse", _EXTRACTORS)
@pytest.mark.parametrize(("token", "reason", "token_part", "cause"), _PARAMS)
def test_malformed_token_full_contract(parse, token, reason, token_part, cause):
    with pytest.raises(MalformedTokenException) as exc_info:
        parse(token)

    exc = exc_info.value
    assert type(exc) is MalformedTokenException
    assert exc.message == f"Invalid token: {reason}"
    assert str(exc) == exc.message
    assert exc.token_part == token_part
    assert exc.details == {"error": reason}
    if cause is None:
        assert exc.__cause__ is None
    else:
        assert type(exc.__cause__) is cause


def test_non_string_token_full_contract():
    with pytest.raises(MalformedTokenException) as exc_info:
        check_compact_jws(cast("str", 1))

    exc = exc_info.value
    assert exc.message == "Invalid token: token is not a string"
    assert exc.token_part is None
    assert exc.details == {"error": "token is not a string"}


def test_header_rejected_by_pyjwt_full_contract():
    """A ``kid`` that is not a string is refused by PyJWT; the error is chained."""
    token = f"{KID_NOT_STRING}.{PAYLOAD}.{SIGNATURE}"
    check_compact_jws(token)

    with pytest.raises(MalformedTokenException) as exc_info:
        extract_jwt_header_fields(token)

    exc = exc_info.value
    cause = exc.__cause__
    assert type(cause) is pyjwt.InvalidTokenError
    assert exc.message == f"Invalid token: {cause!s}"
    assert exc.token_part == "header"
    assert exc.details == {"error": str(cause)}


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(VALID, id="lengths-0-2-and-0"),
        pytest.param(f"{EMPTY_OBJECT}.{EMPTY_OBJECT}.{SIGNATURE}", id="lengths-3"),
        pytest.param(f"{URLSAFE_HEADER}.{PAYLOAD}.-_8", id="urlsafe"),
    ],
)
def test_well_formed_token_passes(token):
    check_compact_jws(token)


def test_header_fields_of_well_formed_token():
    assert extract_jwt_header_fields(VALID) == ("k1", "RS256")
    assert extract_kid_from_jwt(VALID) == "k1"
