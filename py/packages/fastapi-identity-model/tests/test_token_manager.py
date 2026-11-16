import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from fastapi_identity_model import (
    TokenManager,
    TokenManagerError,
    TokenManagerErrorKind,
)
import fastapi_identity_model.token_manager as tm_mod
from py_identity_model import AuthorizationScheme
from py_identity_model.aio import RefreshTokenResponse, TokenErrorKind


pytestmark = pytest.mark.unit

BEARER = "Bearer"
TOKEN_ENDPOINT = "https://op/token"


def _disco(ok=True, token_endpoint=TOKEN_ENDPOINT, error=None):
    return SimpleNamespace(is_successful=ok, token_endpoint=token_endpoint, error=error)


@pytest.fixture
def token_endpoint(monkeypatch):
    """The mocked token endpoint the real ``refresh_token`` grant posts to."""
    monkeypatch.setattr(
        tm_mod, "get_discovery_document", AsyncMock(return_value=_disco())
    )
    with respx.mock:
        yield respx.post(TOKEN_ENDPOINT)


def _answer(route: respx.Route, body: dict) -> None:
    route.mock(return_value=httpx.Response(200, json=body))


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


async def test_refresh_when_expired(token_endpoint):
    _answer(
        token_endpoint,
        {
            "access_token": "fresh",
            "refresh_token": "r2",
            "expires_in": 3600,
            "token_type": "DPoP",
        },
    )
    tm = _stale(client_secret="secret")
    assert await tm.get_access_token() == "fresh"
    assert (tm.refresh_token, tm.token_type) == ("r2", AuthorizationScheme.DPOP)


async def test_refresh_keeps_old_refresh_token_when_none_returned(token_endpoint):
    _answer(token_endpoint, {"access_token": "fresh", "token_type": BEARER})
    tm = _stale()
    await tm.get_access_token()
    assert tm.refresh_token == "r1"


_REFUSED = [
    pytest.param(
        {"refresh_token": "r2"},
        TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
        id="no-access-token-or-type",
    ),
    pytest.param(
        {"refresh_token": "r2", "token_type": BEARER},
        TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
        id="no-access-token",
    ),
    pytest.param(
        {"access_token": "", "refresh_token": "r2", "token_type": BEARER},
        TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
        id="empty-access-token",
    ),
    pytest.param(
        {"access_token": "fresh", "refresh_token": "r2"},
        TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE,
        id="no-token-type",
    ),
    pytest.param(
        {"access_token": "fresh", "refresh_token": "r2", "token_type": "mac"},
        TokenManagerErrorKind.UNSUPPORTED_TOKEN_TYPE,
        id="unknown-token-type",
    ),
]


@pytest.mark.parametrize(("body", "kind"), _REFUSED)
async def test_refused_response_keeps_the_rotated_refresh_token(
    token_endpoint, body, kind
):
    _answer(token_endpoint, body)
    tm = _stale()
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert (*_error(exc), tm.access_token, tm.refresh_token, tm.token_type) == (
        kind,
        {"kind": kind.value},
        "stale",
        "r2",
        AuthorizationScheme.BEARER,
    )


@pytest.mark.parametrize(
    "expires_in",
    [
        pytest.param("3600", id="string"),
        pytest.param([3600], id="list"),
        pytest.param(True, id="bool"),
        pytest.param(1e30, id="too-large"),
        pytest.param(1e12, id="past-the-last-date"),
        pytest.param(-1e12, id="before-the-first-date"),
    ],
)
async def test_unusable_expires_in_is_refused_and_keeps_the_rotated_refresh_token(
    token_endpoint, expires_in
):
    _answer(
        token_endpoint,
        {
            "access_token": "fresh",
            "refresh_token": "r2",
            "token_type": BEARER,
            "expires_in": expires_in,
        },
    )
    tm = _stale()
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert (*_error(exc), tm.access_token, tm.refresh_token, tm.token_type) == (
        TokenManagerErrorKind.REFRESH_FAILED,
        {"kind": "refresh_failed", "error": "expires_in is not a number of seconds"},
        "stale",
        "r2",
        AuthorizationScheme.BEARER,
    )


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        pytest.param(
            {k: v for k, v in param.values[0].items() if k != "refresh_token"},
            param.values[1],
            id=param.id,
        )
        for param in _REFUSED
    ]
    + [
        pytest.param(
            {"refresh_token": "", "token_type": BEARER},
            TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
            id="empty-refresh-token",
        ),
        pytest.param(
            {"refresh_token": 5, "token_type": BEARER},
            TokenManagerErrorKind.MISSING_ACCESS_TOKEN,
            id="non-string-refresh-token",
        ),
    ],
)
async def test_refused_response_without_a_refresh_token_keeps_the_old_one(
    token_endpoint, body, kind
):
    _answer(token_endpoint, body)
    tm = _stale()
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert (*_error(exc), tm.access_token, tm.refresh_token) == (
        kind,
        {"kind": kind.value},
        "stale",
        "r1",
    )


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


_INVALID_GRANT = b'{"error":"invalid_grant","refresh_token":"r2"}'


@pytest.mark.parametrize(
    ("response", "error"),
    [
        pytest.param(
            httpx.Response(400, content=_INVALID_GRANT),
            "Token refresh failed with status code: 400. "
            f"Response Content: {_INVALID_GRANT!r}",
            id="error-response",
        ),
        pytest.param(
            httpx.Response(200, json=["r2"]),
            "Token response is not a JSON object: list",
            id="not-a-json-object",
        ),
    ],
)
async def test_refresh_grant_failure_raises(token_endpoint, response, error):
    token_endpoint.mock(return_value=response)
    tm = _stale()
    with pytest.raises(TokenManagerError) as exc:
        await tm.get_access_token()
    assert (*_error(exc), tm.access_token, tm.refresh_token) == (
        TokenManagerErrorKind.REFRESH_FAILED,
        {"kind": "refresh_failed", "error": error},
        "stale",
        "r1",
    )


async def test_zero_expires_in_is_expired():
    # expires_in=0 means already expired, not "no expiry" — the token must be
    # treated as needing refresh, not served forever.
    tm = TokenManager("d", "cid")
    tm.set_tokens(access_token="a", refresh_token="r", expires_in=0, token_type=BEARER)
    assert tm.is_token_expired() is True


async def test_concurrent_get_access_token_refreshes_once(token_endpoint):
    _answer(
        token_endpoint,
        {
            "access_token": "fresh",
            "refresh_token": "r2",
            "expires_in": 3600,
            "token_type": BEARER,
        },
    )
    tm = _stale(client_secret="secret")

    results = await asyncio.gather(*(tm.get_access_token() for _ in range(5)))

    assert results == ["fresh"] * 5
    # The lock + re-check must collapse the concurrent callers into one grant.
    assert token_endpoint.call_count == 1


def test_rejection_with_both_required_members_reports_the_library_error():
    """An invalid response the manager cannot explain keeps the library's error."""
    error = tm_mod._rejection(
        RefreshTokenResponse(
            is_successful=False,
            error="expires_in must be a number",
            error_kind=TokenErrorKind.INVALID_TOKEN_RESPONSE,
            rejected_token={"access_token": "fresh", "token_type": "Bearer"},
        )
    )

    assert (error.kind, error.details) == (
        TokenManagerErrorKind.REFRESH_FAILED,
        {"kind": "refresh_failed", "error": "expires_in must be a number"},
    )
