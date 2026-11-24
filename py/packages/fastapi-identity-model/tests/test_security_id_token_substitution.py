"""ID-token-substitution behaviour for the middleware (F-07).

``TokenValidationMiddleware`` discriminated ID tokens from access tokens ONLY
by the presence of ``_ID_TOKEN_ONLY_CLAIMS = ("nonce", "at_hash", "c_hash")``.
All three are OPTIONAL for the authorization-code flow, so a code-flow ID token
routinely carries none of them. With ``audience`` defaulted to the client_id,
such an ID token's ``aud`` matches, it passes ``validate_token``, and the
negative guard's ``any(...)`` is False — so an OP-authenticated user could
replay their own ID token as ``Authorization: Bearer`` and reach every protected
route without a client-authorized access token.

The fix adds an OPT-IN positive-marker requirement
(``require_access_token_marker``): when enabled, a validated token must carry a
positive access-token marker (default ``scope``/``scp``) or it is rejected. It
is opt-in and default-off so it never breaks an integration whose access tokens
legitimately omit those claims.

``validate_token`` is mocked to return the claims a genuine token would yield
after passing signature/iss/aud validation — isolating the middleware's
type-confusion guard, matching the existing harness.
"""

from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw


pytestmark = pytest.mark.unit

ISSUER = "https://op"

# A valid code-flow ID token: correct iss/sig/aud, but NONE of the ID-token-only
# marker claims the negative guard keys on, and no access-token marker either.
CODEFLOW_ID_TOKEN_CLAIMS = {
    "sub": "user-1",
    "aud": "cid",
    "iss": "https://op",
    "exp": 9999999999,
}


def _app(monkeypatch, validate, **mw_kwargs) -> FastAPI:
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        issuer=ISSUER,
        audience="cid",
        excluded_paths=["/health"],
        **mw_kwargs,
    )

    @app.get("/me")
    async def me(claims: dict = Depends(get_claims)):
        return claims

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def _get_me(app: FastAPI) -> httpx.Response:
    async with _client(app) as client:
        return await client.get("/me", headers={"Authorization": "Bearer tok"})


async def test_codeflow_id_token_rejected_when_marker_required(monkeypatch):
    """F-07 fix: with the opt-in on, a code-flow ID token (no hash claims, no
    ``scope``) is rejected 401 — it lacks a positive access-token marker."""
    app = _app(
        monkeypatch,
        AsyncMock(return_value=CODEFLOW_ID_TOKEN_CLAIMS),
        require_access_token_marker=True,
    )
    resp = await _get_me(app)
    assert resp.status_code == 401
    assert "access-token marker" in resp.json()["detail"]


async def test_codeflow_id_token_accepted_when_marker_not_required(monkeypatch):
    """Backward-compat: with the opt-in OFF (default), the identical token still
    authenticates (200) — the control changes nothing unless explicitly enabled."""
    app = _app(monkeypatch, AsyncMock(return_value=CODEFLOW_ID_TOKEN_CLAIMS))
    resp = await _get_me(app)
    assert resp.status_code == 200
    assert resp.json()["sub"] == "user-1"


async def test_access_token_with_scope_accepted_when_marker_required(monkeypatch):
    """No false positive: a real access token carrying ``scope`` is accepted even
    with the marker requirement enabled."""
    claims = {**CODEFLOW_ID_TOKEN_CLAIMS, "scope": "openid profile email"}
    app = _app(
        monkeypatch, AsyncMock(return_value=claims), require_access_token_marker=True
    )
    resp = await _get_me(app)
    assert resp.status_code == 200
    assert resp.json()["scope"] == "openid profile email"


async def test_access_token_with_scp_accepted_when_marker_required(monkeypatch):
    """Azure AD convention: an access token carrying scopes under ``scp`` is
    accepted (``scp`` is a default marker claim)."""
    claims = {**CODEFLOW_ID_TOKEN_CLAIMS, "scp": "api.read"}
    app = _app(
        monkeypatch, AsyncMock(return_value=claims), require_access_token_marker=True
    )
    resp = await _get_me(app)
    assert resp.status_code == 200


async def test_custom_marker_claim_is_honoured(monkeypatch):
    """An OP that signals access-token type with a non-default claim can be
    accommodated by overriding ``access_token_marker_claims`` — a token with the
    configured marker is accepted, one without (only ``scope``) is rejected."""
    with_marker = {**CODEFLOW_ID_TOKEN_CLAIMS, "token_use": "access"}
    app = _app(
        monkeypatch,
        AsyncMock(return_value=with_marker),
        require_access_token_marker=True,
        access_token_marker_claims=("token_use",),
    )
    assert (await _get_me(app)).status_code == 200

    only_scope = {**CODEFLOW_ID_TOKEN_CLAIMS, "scope": "openid"}
    app = _app(
        monkeypatch,
        AsyncMock(return_value=only_scope),
        require_access_token_marker=True,
        access_token_marker_claims=("token_use",),
    )
    assert (await _get_me(app)).status_code == 401


async def test_id_token_with_nonce_rejected_regardless_of_marker(monkeypatch):
    """The pre-existing negative guard still fires: an ID token carrying a
    hash/nonce claim is rejected even with the marker requirement off."""
    claims = {**CODEFLOW_ID_TOKEN_CLAIMS, "nonce": "n-123"}
    app = _app(monkeypatch, AsyncMock(return_value=claims))
    resp = await _get_me(app)
    assert resp.status_code == 401
    assert "ID token" in resp.json()["detail"]
