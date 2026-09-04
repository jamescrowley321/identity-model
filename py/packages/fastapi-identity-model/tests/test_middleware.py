from unittest.mock import AsyncMock

from fastapi import Depends, FastAPI
import httpx
from jwt import DecodeError
import pytest

from fastapi_identity_model import TokenValidationMiddleware, get_claims
import fastapi_identity_model.middleware as mw
from py_identity_model import DiscoveryException, TokenValidationException


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

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/me")
    async def me(claims: dict = Depends(get_claims)):
        return claims

    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


async def test_excluded_path_skips_validation(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        assert (await client.get("/health")).status_code == 200


async def test_missing_authorization_header(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/me")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Missing Authorization header"


async def test_malformed_authorization_header(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/me", headers={"Authorization": "Token abc"})
    assert resp.status_code == 401
    assert "Invalid Authorization header format" in resp.json()["detail"]


async def test_valid_token_attaches_claims(monkeypatch):
    claims = {"sub": "user-1", "scope": "openid"}
    async with _client(_app(monkeypatch, AsyncMock(return_value=claims))) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer good"})
    assert resp.status_code == 200
    assert resp.json() == claims


async def test_invalid_token_returns_401(monkeypatch):
    validate = AsyncMock(side_effect=TokenValidationException("bad sig"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer bad"})
    assert resp.status_code == 401
    # F-18: uniform, non-oracular 401 body (does not echo the validation cause).
    assert resp.json()["detail"] == mw._GENERIC_401_DETAIL


async def test_unexpected_error_returns_500(monkeypatch):
    validate = AsyncMock(side_effect=RuntimeError("boom"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Internal server error during authentication"


async def test_network_exception_returns_503(monkeypatch):
    # The `except NetworkException` branch: if the core raises a NetworkException
    # subtype, a provider outage is a 503.
    validate = AsyncMock(side_effect=DiscoveryException("provider unreachable"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503


async def test_upstream_fetch_failure_returns_503(monkeypatch):
    # The real path: a discovery/JWKS fetch failure surfaces from the core as a
    # TokenValidationException carrying the "Network error during ..." message
    # (NOT a NetworkException), so the middleware must still map it to 503 — a
    # transient provider outage, not an "invalid token". (The prior test mocked
    # DiscoveryException, which the real disco/JWKS path never raises, so this
    # 401->503 gap went uncaught.)
    validate = AsyncMock(
        side_effect=TokenValidationException(
            "Network error during discovery document request: connection refused"
        )
    )
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Authentication temporarily unavailable"


async def test_generic_validation_failure_still_returns_401(monkeypatch):
    # The 503 mapping must be narrow: a genuinely invalid token (a non-network
    # TokenValidationException) stays a 401.
    validate = AsyncMock(side_effect=TokenValidationException("Invalid signature"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == mw._GENERIC_401_DETAIL


async def test_malformed_token_returns_401_not_500(monkeypatch):
    # A non-JWT ("invalid-token-123") makes the library's header parsing raise
    # a raw pyjwt DecodeError before validation wraps it; that is a client
    # error (401), not a server fault (500).
    validate = AsyncMock(side_effect=DecodeError("Not enough segments"))
    async with _client(_app(monkeypatch, validate)) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer invalid"})
    assert resp.status_code == 401
    # F-18: malformed tokens return the same uniform body as any other rejection.
    assert resp.json()["detail"] == mw._GENERIC_401_DETAIL


async def test_id_token_rejected_as_access_token(monkeypatch):
    # A token bearing an ID-token-only claim (nonce) must not authenticate at
    # the resource server even though its aud matches the client_id.
    claims = {"sub": "user-1", "aud": "cid", "nonce": "n-123"}
    async with _client(_app(monkeypatch, AsyncMock(return_value=claims))) as client:
        resp = await client.get("/me", headers={"Authorization": "Bearer idtok"})
    assert resp.status_code == 401
    assert "ID token" in resp.json()["detail"]


async def test_excluded_subpath_is_validated_by_default(monkeypatch):
    # Issue #600: matching is exact by default, so a subpath of an excluded
    # entry ("/health") is NOT excluded — it is validated and, with no token,
    # rejected 401 (fail closed) rather than silently reaching routing.
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.get("/health/live")
    assert resp.status_code == 401


async def test_options_preflight_passes_through(monkeypatch):
    async with _client(_app(monkeypatch, AsyncMock())) as client:
        resp = await client.options("/me")
    assert resp.status_code != 401


def test_audience_is_required():
    with pytest.raises(ValueError, match="audience"):
        TokenValidationMiddleware(FastAPI(), discovery_url=DISCOVERY_URL)


def test_explicit_empty_excluded_paths_excludes_nothing():
    mw_obj = TokenValidationMiddleware(
        FastAPI(), discovery_url=DISCOVERY_URL, audience="cid", excluded_paths=[]
    )
    assert mw_obj.excluded_paths == []
    assert mw_obj._is_excluded("/docs") is False


def test_root_excluded_path_is_not_a_catch_all():
    # A "/" entry must match only the root, not every path via subpath prefix.
    mw_obj = TokenValidationMiddleware(
        FastAPI(),
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/", "/docs"],
    )
    assert mw_obj._is_excluded("/") is True
    assert mw_obj._is_excluded("/api/me") is False
    assert mw_obj._is_excluded("/docs") is True


def test_exact_match_default_does_not_exclude_subpaths():
    # Issue #600: matching is exact by default. A plain "/health" entry must NOT
    # exclude a nested route — fail closed so a sensitive nested path under an
    # excluded prefix is not silently exposed.
    mw_obj = TokenValidationMiddleware(
        FastAPI(),
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/health", "/docs"],
    )
    assert mw_obj._is_excluded("/health") is True
    assert mw_obj._is_excluded("/health/db-dump") is False
    assert mw_obj._is_excluded("/docs/oauth2-redirect") is False


def test_subtree_wildcard_opt_in_excludes_prefix_and_below():
    # A trailing "/*" is the explicit opt-in for subtree exclusion.
    mw_obj = TokenValidationMiddleware(
        FastAPI(),
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/docs/*"],
    )
    assert mw_obj._is_excluded("/docs") is True
    assert mw_obj._is_excluded("/docs/oauth2-redirect") is True
    assert mw_obj._is_excluded("/docs/anything/deep") is True
    # A sibling that merely shares the string prefix is not under the subtree.
    assert mw_obj._is_excluded("/docsx") is False


def test_bare_star_is_not_a_catch_all():
    # "/*" (root subtree) must not disable auth wholesale via a one-char typo.
    mw_obj = TokenValidationMiddleware(
        FastAPI(),
        discovery_url=DISCOVERY_URL,
        audience="cid",
        excluded_paths=["/*"],
    )
    assert mw_obj._is_excluded("/anything") is False
    assert mw_obj._is_excluded("/") is False


def test_default_excluded_paths_cover_swagger_oauth2_redirect():
    # Exact matching no longer implies the /docs subtree, so the Swagger OAuth2
    # redirect must be listed explicitly in the defaults.
    mw_obj = TokenValidationMiddleware(
        FastAPI(), discovery_url=DISCOVERY_URL, audience="cid"
    )
    assert mw_obj._is_excluded("/docs") is True
    assert mw_obj._is_excluded("/docs/oauth2-redirect") is True
    assert mw_obj._is_excluded("/openapi.json") is True
    assert mw_obj._is_excluded("/health") is True
    # But not an arbitrary nested route under the excluded docs path.
    assert mw_obj._is_excluded("/docs/secret") is False


def test_access_token_marker_defaults_off():
    # The F-07 defence is opt-in: default construction leaves it disabled with
    # the scope/scp marker set, so existing deployments are unaffected.
    mw_obj = TokenValidationMiddleware(
        FastAPI(), discovery_url=DISCOVERY_URL, audience="cid"
    )
    assert mw_obj.require_access_token_marker is False
    assert mw_obj.access_token_marker_claims == ("scope", "scp")


def test_require_access_token_marker_with_empty_claims_raises():
    # Enabling the requirement with no marker claims would 401 every token;
    # reject it at construction rather than silently blocking all traffic.
    with pytest.raises(ValueError, match="access_token_marker_claims"):
        TokenValidationMiddleware(
            FastAPI(),
            discovery_url=DISCOVERY_URL,
            audience="cid",
            require_access_token_marker=True,
            access_token_marker_claims=(),
        )
