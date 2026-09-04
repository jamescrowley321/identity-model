"""WebSocket authentication (issue #598).

WebSocket handshakes bypass ``BaseHTTPMiddleware`` entirely, so
``TokenValidationMiddleware`` cannot guard them. ``build_ws_authenticator``
provides an equivalent FastAPI dependency that runs the same core
``validate_token`` path and the same F-07 ID-token-substitution guard, closing
the socket on failure.

The dependency is exercised directly with a fake ``WebSocket`` (its only ASGI
surface here is ``.headers`` / ``.query_params`` / ``.state``), isolating the
authenticator's own logic — the same mock-``validate_token`` approach the HTTP
middleware tests use. Driving a real handshake via ``starlette.testclient`` is
avoided on purpose: it pulls in the deprecated httpx TestClient path.
"""

from types import SimpleNamespace

from fastapi import WebSocketException
from jwt import DecodeError
import pytest

from fastapi_identity_model import build_ws_authenticator, ws
from py_identity_model import NetworkException, TokenValidationException


pytestmark = pytest.mark.unit

DISCOVERY_URL = "https://op/.well-known/openid-configuration"
_ACCESS_CLAIMS = {"sub": "u1", "scope": "read"}


class _FakeWebSocket:
    """Minimal stand-in for starlette's WebSocket for the dependency under test."""

    def __init__(self, *, headers=None, query_params=None):
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.state = SimpleNamespace()


def _authenticator(monkeypatch, *, returns=None, raises=None, **kwargs):
    async def fake_validate_token(**_):
        if raises is not None:
            raise raises
        return dict(returns)

    monkeypatch.setattr(ws, "validate_token", fake_validate_token)
    return build_ws_authenticator(discovery_url=DISCOVERY_URL, audience="cid", **kwargs)


async def test_valid_token_via_query_param(monkeypatch):
    auth = _authenticator(monkeypatch, returns=_ACCESS_CLAIMS)
    sock = _FakeWebSocket(query_params={"access_token": "good"})
    claims = await auth(sock)
    assert claims["sub"] == "u1"
    # Validated identity is attached to websocket.state, mirroring request.state.
    assert sock.state.claims["sub"] == "u1"
    assert sock.state.token == "good"
    assert sock.state.user is not None


async def test_valid_token_via_authorization_header(monkeypatch):
    auth = _authenticator(monkeypatch, returns=_ACCESS_CLAIMS)
    sock = _FakeWebSocket(headers={"Authorization": "Bearer good"})
    claims = await auth(sock)
    assert claims["sub"] == "u1"


async def test_missing_token_closes_policy_violation(monkeypatch):
    auth = _authenticator(monkeypatch, returns=_ACCESS_CLAIMS)
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket())
    assert exc.value.code == 1008


async def test_malformed_authorization_header_does_not_fall_through(monkeypatch):
    # A present-but-malformed header must not fall through to the query param;
    # validate_token must never be reached.
    called = {"n": 0}

    async def fake_validate_token(**_):
        called["n"] += 1
        return dict(_ACCESS_CLAIMS)

    monkeypatch.setattr(ws, "validate_token", fake_validate_token)
    auth = build_ws_authenticator(discovery_url=DISCOVERY_URL, audience="cid")
    sock = _FakeWebSocket(
        headers={"Authorization": "Token abc"}, query_params={"access_token": "good"}
    )
    with pytest.raises(WebSocketException) as exc:
        await auth(sock)
    assert exc.value.code == 1008
    assert called["n"] == 0


async def test_invalid_token_closes_generic_policy_violation(monkeypatch):
    auth = _authenticator(monkeypatch, raises=TokenValidationException("bad signature"))
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "bad"}))
    assert exc.value.code == 1008
    # Generic reason — the close frame must not distinguish rejection causes.
    assert exc.value.reason == "Invalid or unauthorized token"


async def test_malformed_jwt_closes_generic_policy_violation(monkeypatch):
    # A raw pyjwt InvalidTokenError (e.g. DecodeError during header parsing) is a
    # client error, closed 1008 with the same generic reason as any rejection.
    auth = _authenticator(monkeypatch, raises=DecodeError("not a jwt"))
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "xxx"}))
    assert exc.value.code == 1008
    assert exc.value.reason == "Invalid or unauthorized token"


async def test_upstream_outage_closes_try_again_later(monkeypatch):
    auth = _authenticator(monkeypatch, raises=NetworkException("provider down"))
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "good"}))
    # 1013 Try Again Later, not a policy violation — a transient fault, not a
    # bad token.
    assert exc.value.code == 1013


async def test_upstream_fetch_failure_prefix_maps_to_try_again_later(monkeypatch):
    # A discovery/JWKS fetch failure surfaces as a TokenValidationException whose
    # message carries a known prefix; it must map to 1013, not a 1008 rejection.
    auth = _authenticator(
        monkeypatch,
        raises=TokenValidationException("Network error during discovery: boom"),
    )
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "good"}))
    assert exc.value.code == 1013


async def test_unexpected_error_closes_internal_error(monkeypatch):
    auth = _authenticator(monkeypatch, raises=RuntimeError("boom"))
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "good"}))
    assert exc.value.code == 1011


async def test_id_token_substitution_rejected(monkeypatch):
    # An ID-token-only claim (nonce) present → wrong type, rejected even with the
    # positive-marker check off.
    auth = _authenticator(
        monkeypatch, returns={"sub": "u1", "nonce": "n", "scope": "read"}
    )
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "idtok"}))
    assert exc.value.code == 1008
    assert exc.value.reason == "Invalid or unauthorized token"


async def test_require_access_token_marker_rejects_markerless_token(monkeypatch):
    # Opt-in F-07 positive marker: a token with none of scope/scp is rejected.
    auth = _authenticator(
        monkeypatch, returns={"sub": "u1"}, require_access_token_marker=True
    )
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "nomarker"}))
    assert exc.value.code == 1008


async def test_marker_token_passes_when_required(monkeypatch):
    auth = _authenticator(
        monkeypatch,
        returns={"sub": "u1", "scope": "read"},
        require_access_token_marker=True,
    )
    claims = await auth(_FakeWebSocket(query_params={"access_token": "ok"}))
    assert claims["sub"] == "u1"


async def test_custom_query_param(monkeypatch):
    auth = _authenticator(monkeypatch, returns=_ACCESS_CLAIMS, query_param="tok")
    claims = await auth(_FakeWebSocket(query_params={"tok": "good"}))
    assert claims["sub"] == "u1"


async def test_threads_config_into_validate_token(monkeypatch):
    # The authenticator must thread audience, discovery URL, perform_disco AND
    # the injected custom_claims_validator into TokenValidationConfig — a
    # regression dropping any of these would otherwise pass silently.
    captured = {}

    async def capturing_validate_token(
        *, token_validation_config, disco_doc_address, **_
    ):
        captured["cfg"] = token_validation_config
        captured["disco"] = disco_doc_address
        return dict(_ACCESS_CLAIMS)

    monkeypatch.setattr(ws, "validate_token", capturing_validate_token)

    def my_validator(_claims):
        return None

    auth = build_ws_authenticator(
        discovery_url=DISCOVERY_URL,
        audience="cid",
        custom_claims_validator=my_validator,
    )
    await auth(_FakeWebSocket(query_params={"access_token": "good"}))

    cfg = captured["cfg"]
    assert cfg.audience == "cid"
    assert cfg.perform_disco is True
    assert cfg.claims_validator is my_validator
    assert captured["disco"] == DISCOVERY_URL


async def test_to_principal_failure_closes_internal_error(monkeypatch):
    # A failure building the principal AFTER the token validated must fail closed
    # with a mapped 1011, not escape as an unhandled exception (parity with the
    # HTTP middleware's 500 guard).
    def _raise(_claims):
        raise RuntimeError("boom")

    auth = _authenticator(monkeypatch, returns=_ACCESS_CLAIMS)
    monkeypatch.setattr(ws, "to_principal", _raise)
    with pytest.raises(WebSocketException) as exc:
        await auth(_FakeWebSocket(query_params={"access_token": "good"}))
    assert exc.value.code == 1011


def test_empty_audience_raises():
    with pytest.raises(ValueError, match="audience"):
        build_ws_authenticator(discovery_url=DISCOVERY_URL, audience="")


def test_require_marker_with_empty_claims_raises():
    with pytest.raises(ValueError, match="access_token_marker_claims"):
        build_ws_authenticator(
            discovery_url=DISCOVERY_URL,
            audience="cid",
            require_access_token_marker=True,
            access_token_marker_claims=(),
        )
