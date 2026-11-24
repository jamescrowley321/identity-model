"""Adversarial validation-error-oracle test for the middleware (F-18).

On any ``PyIdentityModelException`` the middleware returns
``f"Token validation failed: {e!s}"`` (``middleware.py``), echoing the
stage-specific message ("Invalid signature" / "Invalid audience" / "Token has
expired"). A holder of an out-of-scope but validly-signed token (wrong
tenant/audience) can distinguish failure causes — a CWE-209 information-exposure
oracle. The 401 body must be a UNIFORM generic string regardless of cause.

This drives three distinct validation failures and asserts the 401 bodies are
identical. It XFAILs until the middleware returns a stage-agnostic 401 body.
"""

from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw
from py_identity_model import (
    InvalidAudienceException,
    SignatureVerificationException,
    TokenExpiredException,
)


pytestmark = pytest.mark.unit

ISSUER = "https://op"


def _app(monkeypatch, validate) -> FastAPI:
    monkeypatch.setattr(mw, "validate_token", validate)
    app = FastAPI()
    app.add_middleware(
        TokenValidationMiddleware,
        issuer=ISSUER,
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


async def test_401_body_is_uniform_across_failure_stages(monkeypatch):
    # Three different validation failures, each a PyIdentityModelException.
    failures = [
        SignatureVerificationException("Invalid signature"),
        InvalidAudienceException("Invalid audience"),
        TokenExpiredException("Token has expired"),
    ]
    validate = AsyncMock(side_effect=failures)
    details: list[str] = []
    async with _client(_app(monkeypatch, validate)) as client:
        for _ in failures:
            resp = await client.get("/me", headers={"Authorization": "Bearer x"})
            assert resp.status_code == 401
            details.append(resp.json()["detail"])

    # A non-oracular middleware returns one generic body for every cause.
    assert len(set(details)) == 1
