from dataclasses import replace
import json
import logging
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm
import pytest
from starlette.middleware.sessions import SessionMiddleware

from fastapi_identity_model import (
    OIDCSettings,
    TokenValidationMiddleware,
    build_oidc_router,
    oidc_public_paths,
    rp,
)
from py_identity_model import (
    AuthorizeCallbackException,
    ConfigurationException,
    NetworkException,
    TokenValidationException,
    UserInfoResponse,
)
from py_identity_model.aio import validate_id_token as avalidate_id_token
from py_identity_model.core.response_processors import parse_userinfo_response


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
    authorization_response_iss_parameter_supported=None,
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
                else {"id_token": "idt", "access_token": "at", "token_type": "Bearer"},
            )
        ),
    )
    monkeypatch.setattr(
        rp,
        "validate_id_token",
        AsyncMock(return_value=claims if claims is not None else {"sub": "user-1"}),
    )
    monkeypatch.setattr(
        rp,
        "get_userinfo",
        AsyncMock(
            return_value=UserInfoResponse(
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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}

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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert me["tokens"] == {
        "access_token": "at",
        "token_type": "Bearer",
        "refresh_token": None,
        "id_token": "idt",
    }


async def test_form_post_callback_full_login_flow(monkeypatch):
    # form_post response mode: the provider POSTs code/state as form fields
    # instead of query parameters; the flow must complete identically to GET.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}

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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
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
        rp.validate_id_token.side_effect = TokenValidationException("bad iss")
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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": "attacker-nonce"}
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "Nonce mismatch" in resp.json()["detail"]


async def test_callback_userinfo_failure_is_tolerated(monkeypatch):
    # An unavailable/failed UserInfo fetch is tolerated: identity comes from
    # the validated ID token, so login still completes with empty userinfo.
    _patch(monkeypatch)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = UserInfoResponse(
            is_successful=False, error="unreachable"
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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = UserInfoResponse(
            is_successful=True, claims={"sub": "someone-else"}
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 401
    assert "subject" in resp.json()["detail"].lower()


async def test_callback_userinfo_missing_sub_aborts(monkeypatch):
    # A 200 UserInfo body with no sub (OIDC Core 5.3.2) is an identity
    # failure, not a transient one: the login must fail and keep no tokens.
    _patch(monkeypatch)
    async with _client(_app(store_tokens=True)) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        rp.get_userinfo.return_value = parse_userinfo_response(
            httpx.Response(
                200,
                json={"email": "u@e"},
                headers={"Content-Type": "application/json"},
            )
        )
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert resp.status_code == 401
    assert resp.json()["detail"] == "UserInfo response has no subject"
    assert me == {}


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
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        assert (await client.get("/me")).json().get("sub") == "user-1"

        resp = await client.post("/auth/logout")
        assert resp.status_code == 303
        assert (await client.get("/me")).json() == {}


def _composed_app(excluded_paths) -> FastAPI:
    """App with the login router AND the RS middleware installed together —
    the combined RP+RS deployment from issue #599."""
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(build_oidc_router(SETTINGS), prefix="/auth")
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=SETTINGS.discovery_url,
        audience=SETTINGS.audience,
        excluded_paths=excluded_paths,
    )

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    return app


async def test_middleware_composition_excludes_login_routes(monkeypatch):
    # Issue #599: with oidc_public_paths wired into excluded_paths, the login
    # route is reachable THROUGH a globally-installed middleware (302), while a
    # non-excluded route still requires a token.
    _patch(monkeypatch)
    app = _composed_app(oidc_public_paths("/auth"))
    async with _client(app) as client:
        login = await client.get("/auth/login")
        assert login.status_code == 302
        assert login.headers["location"].startswith("https://op/authorize")
        assert (await client.get("/protected")).status_code == 401


async def test_middleware_without_exclusion_blocks_login(monkeypatch):
    # The bug #599 fixes: without the exclusion the middleware demands a bearer
    # token on /auth/login itself, making login impossible.
    _patch(monkeypatch)
    app = _composed_app([])
    async with _client(app) as client:
        assert (await client.get("/auth/login")).status_code == 401


def test_oidc_public_paths_with_prefix():
    # Issue #599: the RS middleware must be able to exclude the login routes.
    assert oidc_public_paths("/auth") == [
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
    ]


def test_oidc_public_paths_normalizes_missing_leading_slash():
    # A relative prefix would yield paths that can never match request.url.path
    # (always absolute), silently failing to exclude the login routes.
    assert oidc_public_paths("auth") == [
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
    ]


def test_oidc_public_paths_root_and_trailing_slash():
    assert oidc_public_paths() == ["/login", "/callback", "/logout"]
    # A trailing slash on the prefix is normalized away (no doubled slash).
    assert oidc_public_paths("/auth/") == [
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
    ]


# --- ID Token audiences on the login callback (OIDC Core §3.1.3.7, #1099) ---
#
# ``validate_id_token`` runs for real against a static key instead of
# discovery, so the audience and ``azp`` rules apply as they would in an app;
# only the key fetch is skipped.


@pytest.fixture(scope="module")
def id_token_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def real_id_token_validation(monkeypatch, id_token_key):
    jwk = json.loads(RSAAlgorithm.to_jwk(id_token_key.public_key()))
    _patch(monkeypatch)

    async def _validate(id_token, *, token_validation_config, **kwargs):
        config = replace(
            token_validation_config, perform_disco=False, key=jwk, algorithms=["RS256"]
        )
        kwargs.pop("disco_doc_address")
        return await avalidate_id_token(id_token, config, **kwargs)

    monkeypatch.setattr(rp, "validate_id_token", _validate)


def _id_token(key, nonce: str, aud: str | list[str], azp: str | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": _DISCO.issuer,
        "sub": "user-1",
        "aud": aud,
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
    }
    if azp is not None:
        claims["azp"] = azp
    return pyjwt.encode(claims, key, algorithm="RS256")


async def _callback(settings: OIDCSettings, key, **token_claims) -> httpx.Response:
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    app.include_router(build_oidc_router(settings), prefix="/auth")
    async with _client(app) as client:
        state, nonce = await _login(client)
        rp.request_authorization_code_token.return_value.token = {
            "id_token": _id_token(key, nonce, **token_claims),
            "access_token": "at",
            "token_type": "Bearer",
        }
        return await client.get(f"/auth/callback?code=abc&state={state}")


@pytest.mark.usefixtures("real_id_token_validation")
class TestLoginCallbackAudiences:
    async def test_untrusted_extra_audience_fails_login(self, id_token_key):
        resp = await _callback(SETTINGS, id_token_key, aud=["cid", "urn:api"])
        assert (resp.status_code, resp.json()) == (
            401,
            {"detail": "ID token validation failed"},
        )

    async def test_trusted_extra_audience_logs_in(self, id_token_key):
        settings = replace(SETTINGS, trusted_audiences=["urn:api"])
        resp = await _callback(settings, id_token_key, aud=["cid", "urn:api"])
        assert (resp.status_code, resp.headers["location"]) == (302, "/")

    async def test_single_audience_logs_in(self, id_token_key):
        resp = await _callback(SETTINGS, id_token_key, aud="cid")
        assert resp.status_code == 302

    async def test_azp_not_checked_by_default(self, id_token_key):
        settings = replace(SETTINGS, trusted_audiences=["urn:api"])
        resp = await _callback(
            settings, id_token_key, aud=["cid", "urn:api"], azp="someone-else"
        )
        assert resp.status_code == 302

    @pytest.mark.parametrize("azp", [None, "someone-else"])
    async def test_validate_azp_rejects_missing_or_wrong_azp(self, id_token_key, azp):
        settings = replace(SETTINGS, trusted_audiences=["urn:api"], validate_azp=True)
        resp = await _callback(settings, id_token_key, aud=["cid", "urn:api"], azp=azp)
        assert (resp.status_code, resp.json()) == (
            401,
            {"detail": "ID token validation failed"},
        )

    async def test_validate_azp_accepts_matching_azp(self, id_token_key):
        settings = replace(SETTINGS, trusted_audiences=["urn:api"], validate_azp=True)
        resp = await _callback(
            settings, id_token_key, aud=["cid", "urn:api"], azp="cid"
        )
        assert resp.status_code == 302


# --- RFC 9207 authorization response issuer ----------------------------------

_ISS_ADVERTISED = SimpleNamespace(
    **{**vars(_DISCO), "authorization_response_iss_parameter_supported": True}
)
_ISS_REJECTED = (400, {"detail": "Authorization response issuer mismatch"})


@pytest.mark.parametrize(
    ("disco", "iss_param"),
    [
        pytest.param(_ISS_ADVERTISED, "", id="advertised-and-missing"),
        pytest.param(_ISS_ADVERTISED, "&iss=https%3A%2F%2Fevil", id="advertised-wrong"),
        pytest.param(_DISCO, "&iss=https%3A%2F%2Fevil", id="not-advertised-wrong"),
        pytest.param(_DISCO, "&iss=https%3A%2F%2Fop%2F", id="trailing-slash"),
    ],
)
async def test_callback_rejects_issuer(monkeypatch, disco, iss_param):
    _patch(monkeypatch, disco=disco)
    async with _client(_app()) as client:
        state, _ = await _login(client)
        resp = await client.get(f"/auth/callback?code=abc&state={state}{iss_param}")
        me = (await client.get("/me")).json()
    assert (resp.status_code, resp.json(), me) == (*_ISS_REJECTED, {})
    rp.request_authorization_code_token.assert_not_awaited()


@pytest.mark.parametrize(
    ("disco", "iss_param"),
    [
        pytest.param(_ISS_ADVERTISED, "&iss=https%3A%2F%2Fop", id="advertised-match"),
        pytest.param(_DISCO, "&iss=https%3A%2F%2Fop", id="not-advertised-match"),
        pytest.param(_DISCO, "", id="not-advertised-absent"),
    ],
)
async def test_callback_accepts_issuer(monkeypatch, disco, iss_param):
    _patch(monkeypatch, disco=disco)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        resp = await client.get(f"/auth/callback?code=abc&state={state}{iss_param}")
        me = (await client.get("/me")).json()
    assert (resp.status_code, me["sub"]) == (302, "user-1")


# --- RFC 6749 §7.1 token_type ------------------------------------------------


@pytest.mark.parametrize("token_type", ["bearer", "BEARER"])
async def test_userinfo_fetched_for_any_case_of_bearer(monkeypatch, token_type):
    _patch(
        monkeypatch,
        token={"id_token": "idt", "access_token": "at", "token_type": token_type},
    )
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert me["userinfo"] == {"sub": "user-1", "email": "u@e"}
    assert rp.get_userinfo.await_args.args[0].token == "at"


@pytest.mark.parametrize("token_type", ["DPoP", "mac", None])
async def test_userinfo_skipped_for_a_non_bearer_token(monkeypatch, token_type):
    token = {"id_token": "idt", "access_token": "at"}
    if token_type is not None:
        token["token_type"] = token_type
    _patch(monkeypatch, token=token)
    async with _client(_app()) as client:
        state, nonce = await _login(client)
        rp.validate_id_token.return_value = {"sub": "user-1", "nonce": nonce}
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
        me = (await client.get("/me")).json()
    assert (resp.status_code, me["sub"], me["userinfo"]) == (302, "user-1", {})
    rp.get_userinfo.assert_not_awaited()


# --- ID token validation error mapping ---------------------------------------


async def test_provider_outage_during_id_token_validation_is_502(monkeypatch):
    _patch(monkeypatch)
    rp.validate_id_token.side_effect = NetworkException("JWKS fetch failed")
    async with _client(_app()) as client:
        state, _ = await _login(client)
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert (resp.status_code, resp.json()) == (
        502,
        {"detail": "Identity provider unavailable"},
    )


async def test_configuration_error_during_id_token_validation_is_500(monkeypatch):
    _patch(monkeypatch)
    rp.validate_id_token.side_effect = ConfigurationException("bad config")
    app = _app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        state, _ = await _login(client)
        resp = await client.get(f"/auth/callback?code=abc&state={state}")
    assert resp.status_code == 500
