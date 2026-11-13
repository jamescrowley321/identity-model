import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fastapi_identity_model import (
    TokenManager,
    TokenManagerError,
    TokenManagerErrorKind,
)
import fastapi_identity_model.token_manager as tm_mod
from py_identity_model import AuthorizationScheme


pytestmark = pytest.mark.unit

BEARER = "Bearer"


def _disco(ok=True, token_endpoint="https://op/token", error=None):
    return SimpleNamespace(is_successful=ok, token_endpoint=token_endpoint, error=error)


def _refresh_response(ok=True, token=None, error=None):
    return SimpleNamespace(is_successful=ok, token=token, error=error)


def _patch_refresh(monkeypatch, response) -> AsyncMock:
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    refresh = AsyncMock(return_value=response)
    monkeypatch.setattr(tm_mod, "refresh_token", refresh)
    return refresh


def _stale(**kwargs) -> TokenManager:
    tm = TokenManager("d", "cid", **kwargs)
    tm.set_tokens(
        access_token="stale", refresh_token="r1", expires_in=-10, token_type=BEARER
    )
    return tm


def _error(exc: pytest.ExceptionInfo) -> tuple:
    return exc.value.kind, exc.value.details


async def test_returns_cached_token_when_not_expired():
    tm = TokenManager("d", "cid")
    tm.set_tokens(
        access_token="cached", refresh_token="r", expires_in=3600, token_type=BEARER
    )
    assert await tm.get_access_token() == "cached"
    assert (tm.access_token, tm.refresh_token, tm.token_type) == (
        "cached",
        "r",
        AuthorizationScheme.BEARER,
    )


async def test_no_expiry_is_never_expired():
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="a", token_type=BEARER)
    assert tm.is_token_expired() is False


async def test_token_type_is_none_before_set_tokens():
    assert TokenManager("d", "cid").token_type is None


@pytest.mark.parametrize(
    ("token_type", "expected"),
    [
        ("bearer", AuthorizationScheme.BEARER),
        ("BEARER", AuthorizationScheme.BEARER),
        ("dpop", AuthorizationScheme.DPOP),
        ("DPoP", AuthorizationScheme.DPOP),
        (AuthorizationScheme.DPOP, AuthorizationScheme.DPOP),
    ],
)
async def test_token_type_is_case_insensitive(token_type, expected):
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="a", token_type=token_type)
    assert tm.token_type is expected


@pytest.mark.parametrize("token_type", ["mac", "", None, 1])
async def test_unknown_token_type_is_refused_and_not_stored(token_type):
    tm = TokenManager("d", "cid")
    with pytest.raises(TokenManagerError) as exc:
        tm.set_tokens(access_token="a", token_type=token_type)
    assert _error(exc) == (
        TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE,
        {"kind": "unsupported_token_type"},
    )
    assert (tm.access_token, tm.token_type) == (None, None)


async def test_refresh_when_expired(monkeypatch):
    _patch_refresh(
        monkeypatch,
        _refresh_response(
            token={
                "access_token": "fresh",
                "refresh_token": "r2",
                "expires_in": 3600,
                "token_type": "DPoP",
            }
        ),
    )
    tm = _stale(client_secret="secret")
    assert await tm.get_access_token() == "fresh"
    assert (tm.refresh_token, tm.token_type) == ("r2", AuthorizationScheme.DPOP)


async def test_refresh_keeps_old_refresh_token_when_none_returned(monkeypatch):
    _patch_refresh(
        monkeypatch,
        _refresh_response(token={"access_token": "fresh", "token_type": BEARER}),
    )
    tm = _stale()
    await tm.get_access_token()
    assert tm.refresh_token == "r1"


@pytest.mark.parametrize(
    "token", [{"access_token": "fresh"}, {"access_token": "fresh", "token_type": "mac"}]
)
async def test_refresh_with_unknown_token_type_raises(monkeypatch, token):
    _patch_refresh(monkeypatch, _refresh_response(token=token))
    tm = _stale()
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert _error(exc) == (
        TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE,
        {"kind": "unsupported_token_type"},
    )
    assert tm.access_token == "stale"


async def test_no_refresh_token_raises():
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="stale", expires_in=-10, token_type=BEARER)
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert _error(exc) == (
        TokenManagerErrorKind.NO_REFRESH_TOKEN,
        {"kind": "no_refresh_token"},
    )


async def test_discovery_failure_raises(monkeypatch):
    monkeypatch.setattr(
        tm_mod,
        "get_discovery_document",
        AsyncMock(return_value=_disco(ok=False, token_endpoint=None, error="down")),
    )
    with pytest.raises(TokenManagerError) as exc:
        await _stale().get_access_token()
    assert _error(exc) == (
        TokenManagerErrorKind.DISCOVERY_FAILED,
        {"kind": "discovery_failed", "error": "down"},
    )


async def test_refresh_grant_failure_raises(monkeypatch):
    _patch_refresh(monkeypatch, _refresh_response(ok=False, error="invalid_grant"))
    with pytest.raises(TokenManagerError) as exc:
        await _stale().get_access_token()
    assert _error(exc) == (
        TokenManagerErrorKind.REFRESH_FAILED,
        {"kind": "refresh_failed", "error": "invalid_grant"},
    )


async def test_refresh_without_access_token_raises(monkeypatch):
    _patch_refresh(monkeypatch, _refresh_response(token={"refresh_token": "r2"}))
    with pytest.raises(TokenManagerError) as exc:
        await _stale().get_access_token()
    assert _error(exc) == (
        TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
        {"kind": "missing_access_token"},
    )


async def test_zero_expires_in_is_expired():
    # expires_in=0 means already expired, not "no expiry" — the token must be
    # treated as needing refresh, not served forever.
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="a", refresh_token="r", expires_in=0, token_type=BEARER)
    assert tm.is_token_expired() is True


async def test_concurrent_get_access_token_refreshes_once(monkeypatch):
    refresh = _patch_refresh(
        monkeypatch,
        _refresh_response(
            token={
                "access_token": "fresh",
                "refresh_token": "r2",
                "expires_in": 3600,
                "token_type": BEARER,
            }
        ),
    )
    tm = _stale(client_secret="secret")

    results = await asyncio.gather(*(tm.get_access_token() for _ in range(5)))

    assert results == ["fresh"] * 5
    # The lock + re-check must collapse the concurrent callers into one grant.
    assert refresh.await_count == 1
