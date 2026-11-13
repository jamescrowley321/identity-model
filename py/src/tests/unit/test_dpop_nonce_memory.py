"""A ``DPoP-Nonce`` from any response is used in the next proof (RFC 9449 §8.2, §9).

"The client MUST use the new nonce value supplied for the next token request
and for all subsequent token requests until the authorization server supplies
a new nonce." Resource servers supply nonces the same way (§9); each server's
nonce goes only to that server.
"""

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    UserInfoRequest,
    generate_dpop_key,
)
from py_identity_model.aio.token_client import refresh_token as refresh_token_async
from py_identity_model.sync.par import push_authorization_request
from py_identity_model.sync.token_client import refresh_token
from py_identity_model.sync.userinfo import get_userinfo


TOKEN_URL = "https://auth.example.com/token"
PAR_URL = "https://auth.example.com/par"
USERINFO_URL = "https://api.example.com/userinfo"
DPOP_TOKEN = {"access_token": "at-1", "token_type": "DPoP", "expires_in": 300}
PAR_RESPONSE = {"request_uri": "urn:example:par", "expires_in": 60}
SUB = "user-1"


def _nonces(route: respx.Route) -> list[str | None]:
    return [
        pyjwt.decode(
            call.request.headers["DPoP"], options={"verify_signature": False}
        ).get("nonce")
        for call in route.calls
    ]


def _refresh(key) -> RefreshTokenRequest:
    return RefreshTokenRequest(
        address=TOKEN_URL, client_id="app1", refresh_token="rt-1", dpop_key=key
    )


def _ok(nonce: str | None = None, body: dict | None = None, status: int = 200):
    headers = {"DPoP-Nonce": nonce} if nonce else {}
    return httpx.Response(status, json=body or DPOP_TOKEN, headers=headers)


@pytest.mark.unit
class TestTokenNonceFromSuccess:
    @respx.mock
    def test_nonce_on_200_is_used_next_and_until_replaced(self):
        key = generate_dpop_key()
        route = respx.post(TOKEN_URL).mock(
            side_effect=[_ok("n-1"), _ok(), _ok("n-2"), _ok()]
        )
        for _ in range(4):
            assert refresh_token(_refresh(key)).is_successful
        assert _nonces(route) == [None, "n-1", "n-1", "n-2"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_nonce_on_200_is_used_next(self):
        key = generate_dpop_key()
        route = respx.post(TOKEN_URL).mock(side_effect=[_ok("n-1"), _ok()])
        for _ in range(2):
            assert (await refresh_token_async(_refresh(key))).is_successful
        assert _nonces(route) == [None, "n-1"]

    @respx.mock
    def test_challenge_nonce_is_kept_for_later_requests(self):
        """DPOP-004 nonce-cached: no second challenge round trip."""
        key = generate_dpop_key()
        challenge = httpx.Response(
            400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "n-1"}
        )
        route = respx.post(TOKEN_URL).mock(side_effect=[challenge, _ok(), _ok()])
        for _ in range(2):
            assert refresh_token(_refresh(key)).is_successful
        assert _nonces(route) == [None, "n-1", "n-1"]


@pytest.mark.unit
class TestNonceScope:
    @respx.mock
    def test_par_shares_the_authorization_server_nonce(self):
        key = generate_dpop_key()
        respx.post(TOKEN_URL).mock(return_value=_ok("as-nonce"))
        par = respx.post(PAR_URL).mock(return_value=_ok(body=PAR_RESPONSE, status=201))
        assert refresh_token(_refresh(key)).is_successful
        response = push_authorization_request(
            PushedAuthorizationRequest(
                address=PAR_URL,
                client_id="app1",
                redirect_uri="https://app.example.com/cb",
                dpop_key=key,
            )
        )
        assert response.is_successful
        assert _nonces(par) == ["as-nonce"]

    @respx.mock
    def test_resource_server_nonce_is_kept_apart(self):
        key = generate_dpop_key()
        respx.post(TOKEN_URL).mock(return_value=_ok("as-nonce"))
        userinfo = respx.get(USERINFO_URL).mock(
            side_effect=[
                _ok("rs-nonce", body={"sub": SUB}),
                _ok(body={"sub": SUB}),
            ]
        )
        assert refresh_token(_refresh(key)).is_successful
        request = UserInfoRequest(
            address=USERINFO_URL, token="at-1", expected_sub=SUB, dpop_key=key
        )
        for _ in range(2):
            assert get_userinfo(request).is_successful
        assert _nonces(userinfo) == [None, "rs-nonce"]
        assert key.nonce_for(TOKEN_URL) == "as-nonce"
        assert key.nonce_for(USERINFO_URL) == "rs-nonce"

    def test_origin_ignores_path_and_case(self):
        key = generate_dpop_key()
        key.remember_nonce("https://Auth.Example.com/token", "n-1")
        assert key.nonce_for("https://auth.example.com/par?x=1") == "n-1"
        assert key.nonce_for("https://auth.example.com:8443/token") is None
        assert key.nonce_for("http://auth.example.com/token") is None
