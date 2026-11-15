"""Unit tests for DPoP-bound UserInfo (resource server) requests.

Covers RFC 9449 threading through the UserInfo path (#475):
- a sender-constrained access token is presented as ``Authorization: DPoP <token>``
  with a resource-request ``DPoP`` proof,
- the resource proof carries the ``ath`` access-token hash (unlike the
  token-endpoint proof, which does not),
- the ``htm``/``htu`` bind the proof to the GET UserInfo request,
- the ``use_dpop_nonce`` challenge (RFC 9449 §8) is honored with a single retry,
- a plain (non-DPoP) request still uses ``Authorization: Bearer``,
- sync and aio implementations behave identically (NFR-9 parity).

respx cannot perform a real DPoP handshake, but it can assert the exact wire
headers and drive the nonce-retry state machine.
"""

from base64 import urlsafe_b64encode
import hashlib

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    UserInfoRequest,
    generate_dpop_key,
)
from py_identity_model.aio.userinfo import get_userinfo as get_userinfo_async
from py_identity_model.sync.userinfo import get_userinfo


USERINFO_URL = "https://api.example.com/userinfo"
ACCESS_TOKEN = "at-resource-123"
SUB = "user-1"
USERINFO_CLAIMS = {"sub": SUB, "name": "Jane Doe"}

# One original request + exactly one use_dpop_nonce retry (RFC 9449 §8).
EXPECTED_RETRY_CALLS = 2


def _expected_ath(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_proof(proof: str) -> dict:
    return pyjwt.decode(proof, options={"verify_signature": False})


@pytest.mark.unit
class TestUserInfoDpopSync:
    @respx.mock
    def test_dpop_bound_request_presents_dpop_scheme_and_ath(self):
        route = respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(200, json=USERINFO_CLAIMS)
        )
        key = generate_dpop_key()

        response = get_userinfo(
            UserInfoRequest(
                address=USERINFO_URL,
                token=ACCESS_TOKEN,
                expected_sub=SUB,
                dpop_key=key,
            )
        )

        assert response.is_successful is True
        sent = route.calls.last.request
        assert sent.headers["Authorization"] == f"DPoP {ACCESS_TOKEN}"
        proof = sent.headers["DPoP"]
        claims = _decode_proof(proof)
        # Resource-request proof MUST carry the access-token hash.
        assert claims["ath"] == _expected_ath(ACCESS_TOKEN)
        assert claims["htm"] == "GET"
        assert claims["htu"] == USERINFO_URL

    @respx.mock
    def test_plain_request_uses_bearer(self):
        route = respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(200, json=USERINFO_CLAIMS)
        )

        response = get_userinfo(
            UserInfoRequest(address=USERINFO_URL, token=ACCESS_TOKEN, expected_sub=SUB)
        )

        assert response.is_successful is True
        sent = route.calls.last.request
        assert sent.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
        assert "DPoP" not in sent.headers

    @respx.mock
    def test_use_dpop_nonce_retry_once(self):
        responses = [
            httpx.Response(
                401,
                json={"error": "use_dpop_nonce"},
                headers={
                    "DPoP-Nonce": "rs-nonce-1",
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                },
            ),
            httpx.Response(200, json=USERINFO_CLAIMS),
        ]
        route = respx.get(USERINFO_URL).mock(side_effect=responses)
        key = generate_dpop_key()

        response = get_userinfo(
            UserInfoRequest(
                address=USERINFO_URL,
                token=ACCESS_TOKEN,
                expected_sub=SUB,
                dpop_key=key,
            )
        )

        assert response.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        # The retried proof echoes the server nonce.
        retried_proof = route.calls[1].request.headers["DPoP"]
        assert _decode_proof(retried_proof)["nonce"] == "rs-nonce-1"

    @respx.mock
    def test_use_dpop_nonce_retry_bounded_to_one(self):
        # The server keeps demanding a nonce; the client must retry only once.
        route = respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(
                401,
                json={"error": "use_dpop_nonce"},
                headers={
                    "DPoP-Nonce": "rs-nonce-x",
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                },
            )
        )
        key = generate_dpop_key()

        response = get_userinfo(
            UserInfoRequest(
                address=USERINFO_URL,
                token=ACCESS_TOKEN,
                expected_sub=SUB,
                dpop_key=key,
            )
        )

        assert response.is_successful is False
        assert route.call_count == EXPECTED_RETRY_CALLS


@pytest.mark.unit
@pytest.mark.asyncio
class TestUserInfoDpopAsync:
    @respx.mock
    async def test_dpop_bound_request_presents_dpop_scheme_and_ath(self):
        route = respx.get(USERINFO_URL).mock(
            return_value=httpx.Response(200, json=USERINFO_CLAIMS)
        )
        key = generate_dpop_key()

        response = await get_userinfo_async(
            UserInfoRequest(
                address=USERINFO_URL,
                token=ACCESS_TOKEN,
                expected_sub=SUB,
                dpop_key=key,
            )
        )

        assert response.is_successful is True
        sent = route.calls.last.request
        assert sent.headers["Authorization"] == f"DPoP {ACCESS_TOKEN}"
        claims = _decode_proof(sent.headers["DPoP"])
        assert claims["ath"] == _expected_ath(ACCESS_TOKEN)
        assert claims["htm"] == "GET"

    @respx.mock
    async def test_use_dpop_nonce_retry_once(self):
        responses = [
            httpx.Response(
                401,
                json={"error": "use_dpop_nonce"},
                headers={
                    "DPoP-Nonce": "rs-nonce-a",
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                },
            ),
            httpx.Response(200, json=USERINFO_CLAIMS),
        ]
        route = respx.get(USERINFO_URL).mock(side_effect=responses)
        key = generate_dpop_key()

        response = await get_userinfo_async(
            UserInfoRequest(
                address=USERINFO_URL,
                token=ACCESS_TOKEN,
                expected_sub=SUB,
                dpop_key=key,
            )
        )

        assert response.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        retried_proof = route.calls[1].request.headers["DPoP"]
        assert _decode_proof(retried_proof)["nonce"] == "rs-nonce-a"
