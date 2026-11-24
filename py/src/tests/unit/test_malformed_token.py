"""A token that is not a well-formed compact JWS raises MalformedTokenException.

Every malformed shape, in discovery mode and manual-key mode, sync and async,
raises the library's typed exception with the failing ``token_part``; the
decoder's own error is chained as ``__cause__`` and never raised itself (#1179).
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import time
from typing import TYPE_CHECKING, cast

import httpx
import jwt
from jwt.api_jws import PyJWS
import pytest

from py_identity_model import (
    MalformedTokenException,
    TokenValidationConfig,
    TokenValidationException,
)
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import validate_token as validate_async
from py_identity_model.aio.validation_cache import AsyncValidationCache
from py_identity_model.core.parsers import (
    check_compact_jws,
    extract_jwt_header_fields,
    extract_kid_from_jwt,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import validate_token as validate_sync
from py_identity_model.sync.validation_cache import ValidationCache

from ..harness import MockOP


if TYPE_CHECKING:
    from collections.abc import Callable


AUDIENCE = "api"
TOKEN_LIFETIME_SECONDS = 300

_OP = MockOP()
_KEY = _OP.primary_key


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims() -> dict:
    now = int(time.time())
    return {
        "iss": _OP.issuer,
        "aud": AUDIENCE,
        "sub": "user-1",
        "iat": now,
        "exp": now + TOKEN_LIFETIME_SECONDS,
    }


def _valid_token() -> str:
    return _OP.sign(_claims())


def _signed_raw_payload(payload: bytes) -> str:
    """A token validly signed over *payload*, which need not be JSON."""
    return PyJWS().encode(
        payload, _KEY.private_key, algorithm=_KEY.alg, headers={"kid": _KEY.kid}
    )


def _with_segment(index: int, segment: str) -> str:
    segments = _valid_token().split(".")
    segments[index] = segment
    return ".".join(segments)


_HEADER, _PAYLOAD, _SIGNATURE = range(3)


@dataclass(frozen=True)
class Shape:
    id: str
    token: Callable[[], str]
    token_part: str | None
    cause: type[BaseException] | None


SHAPES = [
    Shape("empty", lambda: "", None, None),
    Shape("one-segment", lambda: "not-a-jwt", None, None),
    Shape("two-segments", lambda: ".".join(_valid_token().split(".")[:2]), None, None),
    Shape("four-segments", lambda: f"{_valid_token()}.extra", None, None),
    Shape("issue-a.b.c", lambda: "a.b.c", "header", binascii.Error),
    Shape(
        "header-bad-base64",
        lambda: _with_segment(_HEADER, "e30*"),
        "header",
        binascii.Error,
    ),
    Shape(
        "payload-bad-base64",
        lambda: _with_segment(_PAYLOAD, "e30*"),
        "payload",
        binascii.Error,
    ),
    Shape(
        "signature-bad-base64",
        lambda: _with_segment(_SIGNATURE, "sig!"),
        "signature",
        binascii.Error,
    ),
    Shape("payload-padded", lambda: _with_segment(_PAYLOAD, "e30="), "payload", None),
    Shape(
        "signature-standard-base64",
        lambda: _with_segment(_SIGNATURE, "ab+/"),
        "signature",
        None,
    ),
    Shape(
        "header-not-json",
        lambda: _with_segment(_HEADER, _b64(b"not json")),
        "header",
        json.JSONDecodeError,
    ),
    Shape(
        "header-not-utf8",
        lambda: _with_segment(_HEADER, _b64(b"\xff\xfe")),
        "header",
        UnicodeDecodeError,
    ),
    Shape(
        "header-not-object",
        lambda: _with_segment(_HEADER, _b64(b'["RS256"]')),
        "header",
        None,
    ),
    Shape(
        "header-kid-not-string",
        lambda: _with_segment(
            _HEADER, _b64(json.dumps({"alg": _KEY.alg, "kid": 1}).encode())
        ),
        "header",
        jwt.InvalidTokenError,
    ),
    Shape(
        "payload-not-json-signed",
        lambda: _signed_raw_payload(b"not json"),
        "payload",
        json.JSONDecodeError,
    ),
    Shape(
        "payload-not-object-signed",
        lambda: _signed_raw_payload(b"[1]"),
        "payload",
        None,
    ),
]


def _assert_malformed(exc_info: pytest.ExceptionInfo, shape: Shape) -> None:
    err = exc_info.value
    assert type(err) is MalformedTokenException
    assert isinstance(err, TokenValidationException)
    assert not isinstance(err, jwt.PyJWTError)
    assert err.token_part == shape.token_part
    if shape.cause is None:
        assert err.__cause__ is None
    else:
        assert isinstance(err.__cause__, shape.cause)


def _handler(request: httpx.Request) -> httpx.Response:
    documents = {
        httpx.URL(_OP.discovery_url).path: _OP.discovery_document(),
        httpx.URL(_OP.jwks_uri).path: _OP.jwks(),
    }
    return httpx.Response(httpx.codes.OK, json=documents[request.url.path])


def _discovery_config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=True,
        audience=AUDIENCE,
        algorithms=[_KEY.alg],
        require_https=False,
    )


def _manual_config() -> TokenValidationConfig:
    return TokenValidationConfig(
        perform_disco=False,
        key=dict(_KEY.public_jwk),
        audience=AUDIENCE,
        issuer=_OP.issuer,
        algorithms=[_KEY.alg],
    )


def _validate_sync_discovery(token: str) -> dict:
    with HTTPClient(
        client=httpx.Client(transport=httpx.MockTransport(_handler))
    ) as client:
        return validate_sync(
            token,
            _discovery_config(),
            disco_doc_address=_OP.discovery_url,
            http_client=client,
            cache=ValidationCache(),
        )


async def _validate_async_discovery(token: str) -> dict:
    client = AsyncHTTPClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    )
    try:
        return await validate_async(
            token,
            _discovery_config(),
            disco_doc_address=_OP.discovery_url,
            http_client=client,
            cache=AsyncValidationCache(),
        )
    finally:
        await client.close()


_SHAPE_PARAMS = [pytest.param(shape, id=shape.id) for shape in SHAPES]


def test_valid_token_passes_every_mode() -> None:
    """Control: the token the shapes are cut from validates in each mode."""
    token = _valid_token()
    assert _validate_sync_discovery(token)["sub"] == "user-1"
    assert validate_sync(token, _manual_config())["sub"] == "user-1"
    check_compact_jws(token)


async def test_valid_token_passes_async_modes() -> None:
    token = _valid_token()
    assert (await _validate_async_discovery(token))["sub"] == "user-1"
    assert (await validate_async(token, _manual_config()))["sub"] == "user-1"


@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
def test_sync_discovery_mode(shape: Shape) -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        _validate_sync_discovery(shape.token())
    _assert_malformed(exc_info, shape)


@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
async def test_async_discovery_mode(shape: Shape) -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        await _validate_async_discovery(shape.token())
    _assert_malformed(exc_info, shape)


@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
def test_sync_manual_key_mode(shape: Shape) -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        validate_sync(shape.token(), _manual_config())
    _assert_malformed(exc_info, shape)


@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
async def test_async_manual_key_mode(shape: Shape) -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        await validate_async(shape.token(), _manual_config())
    _assert_malformed(exc_info, shape)


@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
def test_manual_key_mode_with_default_algorithms(shape: Shape) -> None:
    """``algorithms=None`` reads the header first to pin the algorithm."""
    config = TokenValidationConfig(
        perform_disco=False,
        key=dict(_KEY.public_jwk),
        audience=AUDIENCE,
        issuer=_OP.issuer,
    )
    with pytest.raises(MalformedTokenException) as exc_info:
        validate_sync(shape.token(), config)
    _assert_malformed(exc_info, shape)


@pytest.mark.parametrize(
    "extract",
    [extract_jwt_header_fields, extract_kid_from_jwt],
    ids=lambda f: f.__name__,
)
@pytest.mark.parametrize("shape", _SHAPE_PARAMS)
def test_header_extractors(extract: Callable[[str], object], shape: Shape) -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        extract(shape.token())
    _assert_malformed(exc_info, shape)


def test_non_string_token_is_malformed() -> None:
    with pytest.raises(MalformedTokenException) as exc_info:
        check_compact_jws(cast("str", b"a.b.c"))
    assert exc_info.value.token_part is None
