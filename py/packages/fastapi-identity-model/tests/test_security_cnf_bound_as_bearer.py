"""Adversarial sender-constraint test for the middleware (F-02).

A certificate-bound access token (``cnf.x5t#S256`` present) stolen and
replayed as a plain ``Bearer`` token, with no client certificate on the
connection, must be refused (RFC 8705 §3), not accepted like an unbound token.

``validate_token`` is replaced by one that returns the bound token's claims (as
it would after signature/iss/aud validation) and then runs the real
``check_token_binding`` against the presentation the middleware passes.
"""

from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw
from py_identity_model.core.token_binding import check_token_binding


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"


def _app(monkeypatch, validate) -> FastAPI:
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/health"],
    )

    @app.get("/me")
    async def me(claims: dict = Depends(get_claims)):
        return claims

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def test_cnf_bound_token_presented_as_bearer_is_rejected(monkeypatch):
    bound_claims = {
        "sub": "user-1",
        "aud": "cid",
        "iss": "https://op",
        # RFC 8705 certificate-binding confirmation method.
        "cnf": {"x5t#S256": "Gms6oPFq0v2Y7d3f4a1b2c3d4e5f6g7h8i9j0kLmNoP"},
    }

    def _validate(*, jwt, token_validation_config, presentation, **_):
        check_token_binding(bound_claims, jwt, token_validation_config, presentation)
        return bound_claims

    async with _client(_app(monkeypatch, AsyncMock(side_effect=_validate))) as client:
        # No client certificate is presented over ASGI — the bound token is a
        # stolen replay.
        resp = await client.get("/me", headers={"Authorization": "Bearer boundtok"})
    assert resp.status_code == 401
