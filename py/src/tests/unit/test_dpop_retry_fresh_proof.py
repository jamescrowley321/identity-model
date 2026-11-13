"""Retry behaviour of DPoP-bound and single-use requests.

Each backoff retry carries a freshly minted DPoP proof (RFC 9449 §11.1, #1019):
a server may reject a proof whose ``jti`` it has already seen, so a ``5xx``
followed by a retry must not resend the first attempt's proof.

The authorization code and refresh token grants are never retried: the code is
single-use (RFC 6749 §4.1.2) and a rotating refresh token is too, so a resend
after a lost response would present a used credential.
"""

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    ClientCredentialsTokenRequest,
    HTTPConfig,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    RefreshTokenRequest,
    generate_dpop_key,
)
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.par import (
    push_authorization_request as push_authorization_request_async,
)
from py_identity_model.aio.token_client import refresh_token as refresh_token_async
from py_identity_model.aio.token_client import (
    request_authorization_code_token as request_authorization_code_token_async,
)
from py_identity_model.aio.token_client import (
    request_client_credentials_token as request_client_credentials_token_async,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.par import push_authorization_request
from py_identity_model.sync.token_client import (
    refresh_token,
    request_authorization_code_token,
    request_client_credentials_token,
)


TOKEN_URL = "https://auth.example.com/token"
PAR_URL = "https://auth.example.com/par"
DPOP_TOKEN = {"access_token": "at-1", "token_type": "DPoP", "expires_in": 300}
PAR_RESPONSE = {"request_uri": "urn:example:par", "expires_in": 60}
NO_SLEEP_ONE_RETRY = HTTPConfig(http_retry_base_delay=0, http_retry_max_attempts=1)
DPOP_KEY = generate_dpop_key("ES256")


def _refresh() -> RefreshTokenRequest:
    return RefreshTokenRequest(
        address=TOKEN_URL, client_id="app1", refresh_token="rt-1", dpop_key=DPOP_KEY
    )


def _auth_code() -> AuthorizationCodeTokenRequest:
    return AuthorizationCodeTokenRequest(
        address=TOKEN_URL,
        client_id="app1",
        code="code",
        redirect_uri="https://app.example.com/cb",
        code_verifier="verifier",
        dpop_key=DPOP_KEY,
    )


def _par() -> PushedAuthorizationRequest:
    return PushedAuthorizationRequest(
        address=PAR_URL,
        client_id="app1",
        redirect_uri="https://app.example.com/cb",
        dpop_key=DPOP_KEY,
    )


def _client_credentials() -> ClientCredentialsTokenRequest:
    return ClientCredentialsTokenRequest(
        address=TOKEN_URL,
        client_id="app1",
        private_key_jwt=PrivateKeyJwt(
            private_key=DPOP_KEY.private_key_pem, algorithm="ES256"
        ),
    )


def _assertion_jtis(route: respx.Route) -> list[str]:
    jtis = []
    for call in route.calls:
        form = parse_qs(call.request.content.decode())
        [assertion] = form["client_assertion"]
        claims = pyjwt.decode(assertion, options={"verify_signature": False})
        jtis.append(claims["jti"])
    return jtis


def _jtis(route: respx.Route) -> list[str]:
    return [
        pyjwt.decode(call.request.headers["DPoP"], options={"verify_signature": False})[
            "jti"
        ]
        for call in route.calls
    ]


SYNC_CALLS = [
    pytest.param(
        push_authorization_request, _par, PAR_URL, PAR_RESPONSE, 201, id="par"
    ),
]
ASYNC_CALLS = [
    pytest.param(
        push_authorization_request_async, _par, PAR_URL, PAR_RESPONSE, 201, id="par"
    ),
]


@pytest.mark.unit
class TestSyncRetryMintsFreshProof:
    @pytest.mark.parametrize(("call", "build", "url", "body", "status"), SYNC_CALLS)
    @respx.mock
    def test_5xx_retry_sends_a_new_jti(
        self, call: Callable[..., Any], build, url, body, status
    ):
        route = respx.post(url).mock(
            side_effect=[httpx.Response(503), httpx.Response(status, json=body)]
        )
        with HTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = call(build(), http_client=client)
        assert response.is_successful, response.error
        first, second = _jtis(route)
        assert first != second


@pytest.mark.asyncio
class TestAsyncRetryMintsFreshProof:
    @pytest.mark.parametrize(("call", "build", "url", "body", "status"), ASYNC_CALLS)
    @respx.mock
    async def test_5xx_retry_sends_a_new_jti(
        self, call: Callable[..., Awaitable[Any]], build, url, body, status
    ):
        route = respx.post(url).mock(
            side_effect=[httpx.Response(503), httpx.Response(status, json=body)]
        )
        async with AsyncHTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = await call(build(), http_client=client)
        assert response.is_successful, response.error
        first, second = _jtis(route)
        assert first != second


@pytest.mark.unit
class TestSyncRetryMintsFreshClientAssertion:
    @respx.mock
    def test_429_retry_sends_a_new_assertion_jti(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[httpx.Response(429), httpx.Response(200, json=DPOP_TOKEN)]
        )
        with HTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = request_client_credentials_token(
                _client_credentials(), http_client=client
            )
        assert response.is_successful, response.error
        first, second = _assertion_jtis(route)
        assert first != second


@pytest.mark.asyncio
class TestAsyncRetryMintsFreshClientAssertion:
    @respx.mock
    async def test_429_retry_sends_a_new_assertion_jti(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[httpx.Response(429), httpx.Response(200, json=DPOP_TOKEN)]
        )
        async with AsyncHTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = await request_client_credentials_token_async(
                _client_credentials(), http_client=client
            )
        assert response.is_successful, response.error
        first, second = _assertion_jtis(route)
        assert first != second


SINGLE_USE_SYNC_CALLS = [
    pytest.param(refresh_token, _refresh, id="refresh"),
    pytest.param(request_authorization_code_token, _auth_code, id="auth_code"),
]
SINGLE_USE_ASYNC_CALLS = [
    pytest.param(refresh_token_async, _refresh, id="refresh"),
    pytest.param(request_authorization_code_token_async, _auth_code, id="auth_code"),
]
NOT_SENT_TWICE = [
    pytest.param(httpx.Response(503), id="503"),
    pytest.param(httpx.Response(429), id="429"),
    pytest.param(httpx.ReadTimeout("response lost"), id="read_timeout"),
]


@pytest.mark.unit
class TestSyncSingleUseGrantIsNotRetried:
    @pytest.mark.parametrize(("call", "build"), SINGLE_USE_SYNC_CALLS)
    @pytest.mark.parametrize("first", NOT_SENT_TWICE)
    @respx.mock
    def test_sent_once(self, call: Callable[..., Any], build, first):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[first, httpx.Response(200, json=DPOP_TOKEN)]
        )
        with HTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = call(build(), http_client=client)
        assert response.is_successful is False
        assert route.call_count == 1


@pytest.mark.asyncio
class TestAsyncSingleUseGrantIsNotRetried:
    @pytest.mark.parametrize(("call", "build"), SINGLE_USE_ASYNC_CALLS)
    @pytest.mark.parametrize("first", NOT_SENT_TWICE)
    @respx.mock
    async def test_sent_once(self, call: Callable[..., Awaitable[Any]], build, first):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[first, httpx.Response(200, json=DPOP_TOKEN)]
        )
        async with AsyncHTTPClient(config=NO_SLEEP_ONE_RETRY) as client:
            response = await call(build(), http_client=client)
        assert response.is_successful is False
        assert route.call_count == 1
