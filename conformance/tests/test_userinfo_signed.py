"""Tests for the conformance RP's UserInfo validation (``_fetch_userinfo``).

The Dynamic RP module ``oidcc-client-test-userinfo-signed`` returns a signed
``application/jwt`` UserInfo response. The RP must verify it against the OP's
JWKS (``iss``/``aud`` per OIDC Core §5.3.2) and then compare ``sub`` with the
ID Token's (§5.3.4), not reject it outright.

respx intercepts the JWKS and UserInfo calls.
"""

from __future__ import annotations

from collections.abc import Iterator
import json

import app as harness_app
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.responses import HTMLResponse
import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm
import pytest
import respx

from py_identity_model import DiscoveryDocumentResponse, HTTPClient, clear_jwks_cache
from py_identity_model.sync.token_validation import clear_discovery_cache


ISSUER = "https://op.example.com"
USERINFO = f"{ISSUER}/userinfo"
CLIENT_ID = "conformance-rp"
SUB = "user-subject-1234531"
KID = "op-key"
JWKS_URI = f"{ISSUER}/jwks"

_OP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks() -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(_OP_KEY.public_key()))
    jwk.pop("key_ops", None)
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


def _signed_userinfo(claims: dict, key: rsa.RSAPrivateKey = _OP_KEY) -> str:
    return pyjwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def _session() -> harness_app.AuthSession:
    return harness_app.AuthSession(
        issuer=ISSUER, state="s", nonce="n", client_id=CLIENT_ID
    )


def _disco() -> DiscoveryDocumentResponse:
    return DiscoveryDocumentResponse(
        is_successful=True,
        issuer=ISSUER,
        jwks_uri=JWKS_URI,
        userinfo_endpoint=USERINFO,
    )


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


def _mock_op(mock: respx.MockRouter, userinfo: httpx.Response) -> None:
    mock.get(JWKS_URI).mock(return_value=httpx.Response(200, json=_jwks()))
    mock.get(USERINFO).mock(return_value=userinfo)


def _jwt_response(token: str) -> httpx.Response:
    return httpx.Response(
        200, content=token, headers={"Content-Type": "application/jwt"}
    )


def _fetch(expected_sub: str | None = SUB) -> dict | HTMLResponse:
    with HTTPClient() as client:
        return harness_app._fetch_userinfo(
            _session(), _disco(), "access-token", expected_sub, client
        )


VALID_CLAIMS = {"iss": ISSUER, "aud": CLIENT_ID, "sub": SUB, "name": "Demo"}


@respx.mock
def test_valid_signed_userinfo_is_accepted() -> None:
    _mock_op(respx.mock, _jwt_response(_signed_userinfo(VALID_CLAIMS)))

    assert _fetch() == VALID_CLAIMS
    # The OIDF module finishes once UserInfo is served; no OP call may follow.
    assert str(respx.mock.calls.last.request.url) == USERINFO


@pytest.mark.parametrize(
    ("claims", "key"),
    [
        pytest.param({**VALID_CLAIMS, "sub": "someone-else"}, _OP_KEY, id="sub"),
        pytest.param({**VALID_CLAIMS, "aud": "other-client"}, _OP_KEY, id="aud"),
        pytest.param(
            {**VALID_CLAIMS, "iss": "https://evil.example"}, _OP_KEY, id="iss"
        ),
        pytest.param(VALID_CLAIMS, _OTHER_KEY, id="signature"),
    ],
)
@respx.mock
def test_invalid_signed_userinfo_is_rejected(
    claims: dict, key: rsa.RSAPrivateKey
) -> None:
    _mock_op(respx.mock, _jwt_response(_signed_userinfo(claims, key)))

    result = _fetch()

    assert isinstance(result, HTMLResponse)
    assert result.status_code == 400


@respx.mock
def test_malformed_signed_userinfo_is_rejected() -> None:
    _mock_op(respx.mock, _jwt_response("not-a-jwt"))

    result = _fetch()

    assert isinstance(result, HTMLResponse)
    assert result.status_code == 400


@respx.mock
def test_json_userinfo_sub_match_is_accepted() -> None:
    claims = {"sub": SUB, "name": "Demo"}
    _mock_op(respx.mock, httpx.Response(200, json=claims))

    assert _fetch() == claims


@respx.mock
def test_json_userinfo_sub_mismatch_is_rejected() -> None:
    _mock_op(respx.mock, httpx.Response(200, json={"sub": "someone-else"}))

    result = _fetch()

    assert isinstance(result, HTMLResponse)
    assert result.status_code == 400


@pytest.mark.parametrize("body", [[{"sub": SUB}], "sub"], ids=["array", "string"])
@respx.mock
def test_non_object_json_userinfo_is_rejected(body: object) -> None:
    _mock_op(respx.mock, httpx.Response(200, json=body))

    result = _fetch()

    assert isinstance(result, HTMLResponse)
    assert result.status_code == 400
