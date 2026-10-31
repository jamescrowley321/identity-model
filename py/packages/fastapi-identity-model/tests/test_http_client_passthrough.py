"""Every library call the package makes uses the ``http_client`` the app passed.

The app builds an ``AsyncHTTPClient`` from its own ``Config`` and hands it to
the middleware, the WebSocket authenticator, the login router and the token
manager. Without one, the library default client is used (``None``).

Token validation also takes the ``cache`` the app passed (an
``AsyncValidationCache``); without one, the library default cache is used.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
import httpx
import pytest
from starlette.datastructures import URL, Headers
from starlette.middleware.sessions import SessionMiddleware

from fastapi_identity_model import (
    OIDCSettings,
    TokenManager,
    TokenValidationMiddleware,
    build_oidc_router,
    build_ws_authenticator,
    rp,
    ws,
)
import fastapi_identity_model.middleware as mw
import fastapi_identity_model.token_manager as tm_mod
from py_identity_model import Config
from py_identity_model.aio import AsyncHTTPClient, AsyncValidationCache


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"
SETTINGS = OIDCSettings(
    discovery_url=DISCOVERY_URL,
    client_id="cid",
    redirect_uri="http://testserver/auth/callback",
)
_ACCESS_CLAIMS = {"sub": "u1", "scope": "read"}


@pytest.fixture
async def http_client():
    async with AsyncHTTPClient(config=Config(http_timeout=7.0)) as client:
        yield client


@pytest.fixture
def cache() -> AsyncValidationCache:
    return AsyncValidationCache(config=Config(jwks_cache_ttl=900.0))


def _asgi_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


def _used_clients(*mocks: AsyncMock) -> list:
    return [call.kwargs["http_client"] for m in mocks for call in m.await_args_list]


def _used_caches(mock: AsyncMock) -> list:
    return [call.kwargs["cache"] for call in mock.await_args_list]


# --------------------------------------------------------------------------- #
# TokenValidationMiddleware                                                    #
# --------------------------------------------------------------------------- #


async def _call_through_middleware(monkeypatch, **kwargs) -> AsyncMock:
    validate = AsyncMock(return_value=dict(_ACCESS_CLAIMS))
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=DISCOVERY_URL,
        audience="cid",
        **kwargs,
    )

    @app.get("/me")
    async def me():
        return {}

    async with _asgi_client(app) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer t"})
    assert resp.status_code == 200
    return validate


async def test_middleware_validates_with_the_given_client(monkeypatch, http_client):
    validate = await _call_through_middleware(monkeypatch, http_client=http_client)
    assert _used_clients(validate) == [http_client]


async def test_middleware_defaults_to_the_library_client(monkeypatch):
    validate = await _call_through_middleware(monkeypatch)
    assert _used_clients(validate) == [None]
    assert _used_caches(validate) == [None]


async def test_middleware_validates_with_the_given_cache(monkeypatch, cache):
    validate = await _call_through_middleware(monkeypatch, cache=cache)
    assert _used_caches(validate) == [cache]


# --------------------------------------------------------------------------- #
# build_ws_authenticator                                                       #
# --------------------------------------------------------------------------- #


async def _call_ws_authenticator(monkeypatch, **kwargs) -> AsyncMock:
    validate = AsyncMock(return_value=dict(_ACCESS_CLAIMS))
    monkeypatch.setattr(ws, "validate_token", validate)
    auth = build_ws_authenticator(discovery_url=DISCOVERY_URL, audience="cid", **kwargs)
    sock = SimpleNamespace(
        headers=Headers({}),
        query_params={"access_token": "t"},
        url=URL("ws://testserver/ws"),
        scope={},
        state=SimpleNamespace(),
    )
    assert await auth(sock) == _ACCESS_CLAIMS
    return validate


async def test_ws_authenticator_validates_with_the_given_client(
    monkeypatch, http_client
):
    validate = await _call_ws_authenticator(monkeypatch, http_client=http_client)
    assert _used_clients(validate) == [http_client]


async def test_ws_authenticator_defaults_to_the_library_client(monkeypatch):
    validate = await _call_ws_authenticator(monkeypatch)
    assert _used_clients(validate) == [None]
    assert _used_caches(validate) == [None]


async def test_ws_authenticator_validates_with_the_given_cache(monkeypatch, cache):
    validate = await _call_ws_authenticator(monkeypatch, cache=cache)
    assert _used_caches(validate) == [cache]


# --------------------------------------------------------------------------- #
# build_oidc_router                                                            #
# --------------------------------------------------------------------------- #


def _patch_rp(monkeypatch) -> dict[str, AsyncMock]:
    mocks = {
        "get_discovery_document": AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                error=None,
                authorization_endpoint="https://op/authorize",
                token_endpoint="https://op/token",
                userinfo_endpoint="https://op/userinfo",
                issuer="https://op",
            )
        ),
        "request_authorization_code_token": AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                error=None,
                token={"id_token": "idt", "access_token": "at"},
            )
        ),
        "validate_token": AsyncMock(),
        "get_userinfo": AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True, claims={"sub": "u1"}, error_kind=None
            )
        ),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(rp, name, mock)
    return mocks


async def _log_in_through_router(monkeypatch, **kwargs) -> dict[str, AsyncMock]:
    mocks = _patch_rp(monkeypatch)
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(build_oidc_router(SETTINGS, **kwargs), prefix="/auth")

    async with _asgi_client(app) as client:
        login = await client.get("/auth/login")
        query = parse_qs(urlparse(login.headers["location"]).query)
        mocks["validate_token"].return_value = {
            "sub": "u1",
            "nonce": query["nonce"][0],
        }
        resp = await client.get(f"/auth/callback?code=c&state={query['state'][0]}")
    assert resp.status_code == 302
    return mocks


async def test_router_makes_every_call_with_the_given_client(monkeypatch, http_client):
    mocks = await _log_in_through_router(monkeypatch, http_client=http_client)
    # /login and /callback each discover; /callback also exchanges the code,
    # validates the ID token and fetches UserInfo.
    assert {name: _used_clients(m) for name, m in mocks.items()} == {
        "get_discovery_document": [http_client, http_client],
        "request_authorization_code_token": [http_client],
        "validate_token": [http_client],
        "get_userinfo": [http_client],
    }


async def test_router_defaults_to_the_library_client(monkeypatch):
    mocks = await _log_in_through_router(monkeypatch)
    assert {name: _used_clients(m) for name, m in mocks.items()} == {
        "get_discovery_document": [None, None],
        "request_authorization_code_token": [None],
        "validate_token": [None],
        "get_userinfo": [None],
    }


# --------------------------------------------------------------------------- #
# TokenManager                                                                 #
# --------------------------------------------------------------------------- #


async def _refresh_through_manager(monkeypatch, **kwargs) -> dict[str, AsyncMock]:
    mocks = {
        "get_discovery_document": AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True, token_endpoint="https://op/token", error=None
            )
        ),
        "refresh_token": AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                token={"access_token": "fresh", "expires_in": 3600},
                error=None,
            )
        ),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(tm_mod, name, mock)
    manager = TokenManager(DISCOVERY_URL, "cid", **kwargs)
    manager.set_tokens(access_token="stale", refresh_token="r", expires_in=-10)
    assert await manager.get_access_token() == "fresh"
    return mocks


async def test_token_manager_refreshes_with_the_given_client(monkeypatch, http_client):
    mocks = await _refresh_through_manager(monkeypatch, http_client=http_client)
    assert {name: _used_clients(m) for name, m in mocks.items()} == {
        "get_discovery_document": [http_client],
        "refresh_token": [http_client],
    }


async def test_token_manager_defaults_to_the_library_client(monkeypatch):
    mocks = await _refresh_through_manager(monkeypatch)
    assert {name: _used_clients(m) for name, m in mocks.items()} == {
        "get_discovery_document": [None],
        "refresh_token": [None],
    }
