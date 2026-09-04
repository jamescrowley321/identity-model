import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, Request
import httpx
import pytest
from starlette.middleware.sessions import SessionMiddleware

from fastapi_identity_model import OIDCSettings, build_oidc_router, rp
from py_identity_model import AuthorizeCallbackException, TokenValidationException


pytestmark = pytest.mark.unit

SETTINGS = OIDCSettings(
    discovery_url="https://op/.well-known/openid-configuration",
    client_id="cid",
    redirect_uri="http://localhost:8000/auth/callback",
)

_DISCO = SimpleNamespace(
    is_successful=True,
    error=None,
    authorization_endpoint="https://op/authorize",
    token_endpoint="https://op/token",
    userinfo_endpoint="https://op/userinfo",
    issuer="https://op",
)


def _patch(monkeypatch, *, disco=_DISCO, token=None, claims=None, userinfo=None):
    monkeypatch.setattr(rp, "get_discovery_document", AsyncMock(return_value=disco))
    monkeypatch.setattr(
        rp,
        "request_authorization_code_token",
        AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                error=None,
                token=token
                if token is not None
                else {"id_token": "idt", "access_token": "at"},
            )
        ),
    )
    monkeypatch.setattr(
        rp,
        "validate_token",
        AsyncMock(return_value=claims if claims is not None else {"sub": "user-1"}),
    )
    monkeypatch.setattr(
        rp,
        "get_userinfo",
        AsyncMock(
            return_value=SimpleNamespace(
                is_successful=True,
                claims=userinfo
                if userinfo is not None
                else {"sub": "user-1", "email": "u@e"},
            )
        ),
    )


def _app(store_tokens: bool = False, fetch_userinfo: bool = True) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(
        build_oidc_router(
            SETTINGS, store_tokens=store_tokens, fetch_userinfo=fetch_userinfo
        ),
        prefix="/auth",
    )

    @app.get("/me")
    async def me(request: Request):
        return request.session.get("oidc", {})

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def _login(client: httpx.AsyncClient) -> tuple[str, str]:
    resp = await client.get("/auth/login")
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["redirect_uri"][0] == SETTINGS.redirect_uri
    assert q["code_challenge_method"][0] == "S256"
    return q["state"][0], q["nonce"][0]


async def test_login_redirects_to_provider(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        resp = await client.get("/auth/login")
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://op/authorize")


async def test_full_login_flow(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}

        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

        me = (await client.get("/me")).json()
    assert me["sub"] == "user-1"
    assert me["userinfo"] == {"sub": "user-1", "email": "u@e"}
    assert "tokens" not in me


async def test_store_tokens_persists_tokens(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app(store_tokens=True)) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert me["tokens"]["access_token"] == "at"


async def test_form_post_callback_full_login_flow(monkeypatch):
    # form_post response mode: the provider POSTs code/state as form fields
    # instead of query parameters; the flow must complete identically to GET.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}

        resp = await client.post("/auth/callback", data={"code": "abc", "state": state})
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"

        me = (await client.get("/me")).json()
    assert me["sub"] == "user-1"
    assert me["userinfo"] == {"sub": "user-1", "email": "u@e"}


async def test_form_post_callback_state_mismatch(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        await _login(client)
        resp = await client.post(
            "/auth/callback", data={"code": "abc", "state": "wrong"}
        )
    assert resp.status_code == 400
    assert "State mismatch" in resp.json()["detail"]


async def test_callback_without_active_flow(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        resp = await client.get("/auth/callback?code=abc&state=xyz")
    assert resp.status_code == 400
    assert "No active login flow" in resp.json()["detail"]


async def test_callback_state_mismatch(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        await _login(client)
        resp = await client.get("/auth/callback?code=abc&state=wrong")
    assert resp.status_code == 400
    assert "State mismatch" in resp.json()["detail"]


async def test_callback_missing_code(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        resp = await client.get(f"/auth/callback?state={state}")
    assert resp.status_code == 400
    assert "missing code" in resp.json()["detail"]


async def test_login_discovery_failure(monkeypatch, caplog):
    _patch(monkeypatch, disco=SimpleNamespace(is_successful=False, error="down"))
    with caplog.at_level(logging.WARNING, logger="fastapi_identity_model"):
        async with _client(_app()) as client:
            resp = await client.get("/auth/login")
    assert resp.status_code == 502
    # Generic client detail — the provider's specific error must not be echoed
    # to the browser (#601), but IS logged server-side for operators.
    assert resp.json()["detail"] == "Identity provider discovery failed"
    assert "down" not in resp.json()["detail"]
    assert "down" in caplog.text


async def test_login_rejects_discovery_issuer_mismatch(monkeypatch, caplog):
    # OIDC Discovery 1.0 §4.3: a document whose issuer does not match the
    # URL it was retrieved from must be rejected (issuer mix-up defense).
    mismatched = SimpleNamespace(
        is_successful=True,
        error=None,
        authorization_endpoint="https://op/authorize",
        token_endpoint="https://op/token",
        userinfo_endpoint="https://op/userinfo",
        issuer="https://op/INVALID",
    )
    _patch(monkeypatch, disco=mismatched)
    with caplog.at_level(logging.WARNING, logger="fastapi_identity_model"):
        async with _client(_app()) as client:
            resp = await client.get("/auth/login")
    assert resp.status_code == 502
    # The mismatched issuer value is not reflected to the client (#601)...
    assert resp.json()["detail"] == "Identity provider configuration error"
    assert "INVALID" not in resp.json()["detail"]
    # ...but the expected/got pair is logged for operators.
    assert "INVALID" in caplog.text


async def test_fetch_userinfo_disabled_skips_userinfo(monkeypatch):
    # fetch_userinfo=False anchors identity on the validated ID token and
    # never calls the UserInfo endpoint.
    _patch(monkeypatch)
    async with _client(_app(fetch_userinfo=False)) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        assert resp.status_code == 302
        me = (await client.get("/me")).json()
    assert me["sub"] == "user-1"
    assert me["userinfo"] == {}
    rp.get_userinfo.assert_not_called()


async def test_callback_token_exchange_failure(monkeypatch, caplog):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.request_authorization_code_token.return_value = SimpleNamespace(
            is_successful=False, error="invalid_grant", token=None
        )
        with caplog.at_level(logging.WARNING, logger="fastapi_identity_model"):
            resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 400
    # The provider's grant error is logged, not reflected to the client (#601).
    assert resp.json()["detail"] == "Authorization code exchange failed"
    assert "invalid_grant" not in resp.json()["detail"]
    assert "invalid_grant" in caplog.text


async def test_callback_invalid_id_token(monkeypatch, caplog):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.validate_token.side_effect = TokenValidationException("bad iss")
        with caplog.at_level(logging.INFO, logger="fastapi_identity_model"):
            resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    # Generic detail — the specific validation cause ("bad iss") is logged, not
    # returned, so the callback can't be used as a validation-stage oracle (#601).
    assert resp.json()["detail"] == "ID token validation failed"
    assert "bad iss" not in resp.json()["detail"]
    assert "bad iss" in caplog.text


async def test_callback_malformed_response_detail_is_generic(monkeypatch, caplog):
    # A parse failure must return a generic detail: the library's exception
    # text (which can carry attacker-influenced callback contents) is logged
    # server-side, never reflected to the browser (#601).
    secret = "parse-cause-4c2e9a-do-not-leak"

    def _raise(_url):
        raise AuthorizeCallbackException(secret)

    _patch(monkeypatch)
    monkeypatch.setattr(rp, "parse_authorize_callback_response", _raise)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        with caplog.at_level(logging.INFO, logger="fastapi_identity_model"):
            resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 400
    # Generic detail — pre-#622 this reflected f"...: {exc}"; the parser's
    # exception text must not appear anywhere in the response body.
    assert resp.json()["detail"] == "Malformed authorization response"
    assert secret not in resp.text
    # ...but the real cause IS logged for operators.
    assert secret in caplog.text


async def test_callback_provider_error_detail_is_generic(monkeypatch, caplog):
    # A provider error response (?error=...) must return a generic detail:
    # neither the provider's error code nor the attacker-controllable
    # error_description is reflected to the browser (#601).
    secret = "err-desc-secret-8b7c1d-do-not-leak"
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        with caplog.at_level(logging.INFO, logger="fastapi_identity_model"):
            resp = await client.get(
                f"/auth/callback?state={state}"
                f"&error=access_denied&error_description={secret}"
            )
    assert resp.status_code == 400
    # Generic detail — pre-#622 this reflected f"Authorization error: {cb.error}".
    assert resp.json()["detail"] == "Authorization request failed"
    # Neither the error code nor the attacker-influenced description leaks to
    # the client...
    assert "access_denied" not in resp.text
    assert secret not in resp.text
    # ...but the error code IS logged for operators (the description is not).
    assert "access_denied" in caplog.text
    assert secret not in caplog.text


async def test_callback_nonce_mismatch(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": "attacker-nonce"}
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "Nonce mismatch" in resp.json()["detail"]


async def test_callback_userinfo_failure_is_tolerated(monkeypatch):
    # An unavailable/failed UserInfo fetch is tolerated: identity comes from
    # the validated ID token, so login still completes with empty userinfo.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = SimpleNamespace(
            is_successful=False, claims=None, error="unreachable"
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        assert resp.status_code == 302
        assert (await client.get("/me")).json()["userinfo"] == {}


async def test_callback_userinfo_sub_mismatch_aborts(monkeypatch):
    # A *successful* UserInfo whose sub disagrees with the ID token is a
    # token-substitution signal and must fail the login, not be swallowed.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = SimpleNamespace(
            is_successful=True, claims={"sub": "someone-else"}, error=None
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "subject" in resp.json()["detail"].lower()


async def test_callback_missing_id_token_rejected(monkeypatch):
    # A token response without an id_token must not establish a session.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        rp.request_authorization_code_token.return_value = SimpleNamespace(
            is_successful=True, error=None, token={"access_token": "at"}
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "ID token" in resp.json()["detail"]


async def test_login_flow_not_visible_as_identity(monkeypatch):
    # Merely starting a login must not make /me (reading the identity key)
    # report an authenticated user, and must not leak the code_verifier.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        await _login(client)
        body = (await client.get("/me")).json()
    assert body == {}


async def test_logout_requires_post(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        resp = await client.get("/auth/logout")
    assert resp.status_code == 405


async def test_logout_clears_session(monkeypatch):
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        assert (await client.get("/me")).json().get("sub") == "user-1"

        resp = await client.post("/auth/logout")
        assert resp.status_code == 303
        assert (await client.get("/me")).json() == {}
