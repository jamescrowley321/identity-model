"""A ``DPoP-Nonce`` from any response is used in the next proof (RFC 9449 §8.2, §9).

"The client MUST use the new nonce value supplied for the next token request
and for all subsequent token requests until the authorization server supplies
a new nonce." Resource servers supply nonces the same way (§9); each server's
nonce goes only to that server.
"""

from collections.abc import Awaitable, Callable
from typing import Any, NamedTuple

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    UserInfoRequest,
    generate_dpop_key,
)
from py_identity_model.aio.par import (
    push_authorization_request as push_authorization_request_async,
)
from py_identity_model.aio.token_client import refresh_token as refresh_token_async
from py_identity_model.aio.token_client import (
    request_authorization_code_token as request_authorization_code_token_async,
)
from py_identity_model.aio.userinfo import get_userinfo as get_userinfo_async
from py_identity_model.core.dpop import remember_dpop_nonce
from py_identity_model.sync.par import push_authorization_request
from py_identity_model.sync.token_client import (
    refresh_token,
    request_authorization_code_token,
)
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
        assert key.nonce_for(TOKEN_URL, resource_server=False) == "as-nonce"
        assert key.nonce_for(USERINFO_URL, resource_server=True) == "rs-nonce"

    def test_origin_ignores_path_and_case(self):
        key = generate_dpop_key()
        key.remember_nonce(
            "https://Auth.Example.com/token", "n-1", resource_server=False
        )
        assert (
            key.nonce_for("https://auth.example.com/par?x=1", resource_server=False)
            == "n-1"
        )
        assert (
            key.nonce_for("https://auth.example.com:8443/token", resource_server=False)
            is None
        )
        assert (
            key.nonce_for("http://auth.example.com/token", resource_server=False)
            is None
        )

    @respx.mock
    def test_shared_origin_keeps_resource_and_authorization_nonces_apart(self):
        """RFC 9449 §9: UserInfo on the token endpoint's origin keeps its own nonce."""
        key = generate_dpop_key()
        shared_userinfo = "https://auth.example.com/userinfo"
        token = respx.post(TOKEN_URL).mock(side_effect=[_ok("as-nonce"), _ok()])
        userinfo = respx.get(shared_userinfo).mock(
            side_effect=[_ok("rs-nonce", body={"sub": SUB}), _ok(body={"sub": SUB})]
        )
        request = UserInfoRequest(
            address=shared_userinfo, token="at-1", expected_sub=SUB, dpop_key=key
        )
        assert refresh_token(_refresh(key)).is_successful
        assert get_userinfo(request).is_successful
        assert refresh_token(_refresh(key)).is_successful
        assert get_userinfo(request).is_successful
        assert _nonces(token) == [None, "as-nonce"]
        assert _nonces(userinfo) == [None, "rs-nonce"]


@pytest.mark.asyncio
class TestAsyncAndAuthCodeCallSites:
    @respx.mock
    async def test_async_par_uses_remembered_nonce(self):
        key = generate_dpop_key()
        par = respx.post(PAR_URL).mock(
            side_effect=[
                _ok("n-1", body=PAR_RESPONSE, status=201),
                _ok(body=PAR_RESPONSE, status=201),
            ]
        )
        request = PushedAuthorizationRequest(
            address=PAR_URL,
            client_id="app1",
            redirect_uri="https://app.example.com/cb",
            dpop_key=key,
        )
        for _ in range(2):
            assert (await push_authorization_request_async(request)).is_successful
        assert _nonces(par) == [None, "n-1"]

    @respx.mock
    async def test_async_userinfo_uses_remembered_nonce(self):
        key = generate_dpop_key()
        userinfo = respx.get(USERINFO_URL).mock(
            side_effect=[_ok("n-1", body={"sub": SUB}), _ok(body={"sub": SUB})]
        )
        request = UserInfoRequest(
            address=USERINFO_URL, token="at-1", expected_sub=SUB, dpop_key=key
        )
        for _ in range(2):
            assert (await get_userinfo_async(request)).is_successful
        assert _nonces(userinfo) == [None, "n-1"]

    @respx.mock
    async def test_auth_code_sync_and_async_use_remembered_nonce(self):
        key = generate_dpop_key()
        route = respx.post(TOKEN_URL).mock(side_effect=[_ok("n-1"), _ok("n-2"), _ok()])
        request = AuthorizationCodeTokenRequest(
            address=TOKEN_URL,
            client_id="app1",
            code="code",
            redirect_uri="https://app.example.com/cb",
            code_verifier="verifier",
            dpop_key=key,
        )
        assert request_authorization_code_token(request).is_successful
        assert (await request_authorization_code_token_async(request)).is_successful
        assert request_authorization_code_token(request).is_successful
        assert _nonces(route) == [None, "n-1", "n-2"]


def _challenge(nonce: str, *, resource_server: bool) -> httpx.Response:
    if resource_server:
        return httpx.Response(
            401,
            headers={
                "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                "DPoP-Nonce": nonce,
            },
        )
    return httpx.Response(
        400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": nonce}
    )


def _auth_code(key) -> AuthorizationCodeTokenRequest:
    return AuthorizationCodeTokenRequest(
        address=TOKEN_URL,
        client_id="app1",
        code="code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="verifier",
        dpop_key=key,
    )


def _par(key) -> PushedAuthorizationRequest:
    return PushedAuthorizationRequest(
        address=PAR_URL,
        client_id="app1",
        redirect_uri="https://app.example.com/cb",
        dpop_key=key,
    )


def _userinfo(key) -> UserInfoRequest:
    return UserInfoRequest(
        address=USERINFO_URL, token="at-1", expected_sub=SUB, dpop_key=key
    )


class CallSite(NamedTuple):
    call: Callable[..., Any]
    acall: Callable[..., Awaitable[Any]]
    build: Callable[[Any], Any]
    method: str
    url: str
    body: dict
    status: int
    resource_server: bool


CALL_SITES = [
    pytest.param(
        CallSite(
            refresh_token,
            refresh_token_async,
            _refresh,
            "POST",
            TOKEN_URL,
            DPOP_TOKEN,
            200,
            False,
        ),
        id="refresh",
    ),
    pytest.param(
        CallSite(
            request_authorization_code_token,
            request_authorization_code_token_async,
            _auth_code,
            "POST",
            TOKEN_URL,
            DPOP_TOKEN,
            200,
            False,
        ),
        id="auth_code",
    ),
    pytest.param(
        CallSite(
            push_authorization_request,
            push_authorization_request_async,
            _par,
            "POST",
            PAR_URL,
            PAR_RESPONSE,
            201,
            False,
        ),
        id="par",
    ),
    pytest.param(
        CallSite(
            get_userinfo,
            get_userinfo_async,
            _userinfo,
            "GET",
            USERINFO_URL,
            {"sub": SUB},
            200,
            True,
        ),
        id="userinfo",
    ),
]


@pytest.mark.unit
class TestRetryResponseNonce:
    """A nonce on the response to the ``use_dpop_nonce`` retry is kept too."""

    @pytest.mark.parametrize("site", CALL_SITES)
    @respx.mock
    def test_sync(self, site: CallSite):
        key = generate_dpop_key()
        rs = site.resource_server
        route = respx.route(method=site.method, url=site.url).mock(
            side_effect=[
                _challenge("n-1", resource_server=rs),
                _ok("n-2", body=site.body, status=site.status),
                _ok(body=site.body, status=site.status),
            ]
        )
        assert site.call(site.build(key)).is_successful
        assert site.call(site.build(key)).is_successful
        assert _nonces(route) == [None, "n-1", "n-2"]
        assert key.nonce_for(site.url, resource_server=rs) == "n-2"
        assert key.nonce_for(site.url, resource_server=not rs) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("site", CALL_SITES)
    @respx.mock
    async def test_async(self, site: CallSite):
        key = generate_dpop_key()
        rs = site.resource_server
        route = respx.route(method=site.method, url=site.url).mock(
            side_effect=[
                _challenge("n-1", resource_server=rs),
                _ok("n-2", body=site.body, status=site.status),
                _ok("n-3", body=site.body, status=site.status),
                _ok(body=site.body, status=site.status),
            ]
        )
        for _ in range(3):
            assert (await site.acall(site.build(key))).is_successful
        assert _nonces(route) == [None, "n-1", "n-2", "n-3"]
        assert key.nonce_for(site.url, resource_server=rs) == "n-3"
        assert key.nonce_for(site.url, resource_server=not rs) is None


@pytest.mark.unit
class TestRememberDpopNonce:
    @pytest.mark.parametrize("rs", [True, False])
    def test_records_under_the_role(self, rs):
        key = generate_dpop_key()
        response = httpx.Response(200, headers={"DPoP-Nonce": "n-1"})
        remember_dpop_nonce(key, TOKEN_URL, response, resource_server=rs)
        assert key.nonce_for(TOKEN_URL, resource_server=rs) == "n-1"
        assert key.nonce_for(TOKEN_URL, resource_server=not rs) is None

    def test_no_header_records_nothing(self):
        key = generate_dpop_key()
        remember_dpop_nonce(key, TOKEN_URL, httpx.Response(200), resource_server=False)
        assert key.nonce_for(TOKEN_URL, resource_server=False) is None

    def test_scheme_and_host_case_are_ignored(self):
        key = generate_dpop_key()
        key.remember_nonce(
            "HTTPS://AUTH.EXAMPLE.COM/token", "n-1", resource_server=False
        )
        assert key.nonce_for(TOKEN_URL, resource_server=False) == "n-1"
