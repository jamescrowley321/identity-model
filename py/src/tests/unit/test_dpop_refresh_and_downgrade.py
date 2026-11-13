"""DPoP on the refresh grant and the opt-in Bearer-downgrade check.

- RFC 9449 §5 / FAPI 2.0 Security Profile §5.3.3.1: a refresh request carries a
  DPoP proof so the refreshed access token stays bound to the client's key.
- RFC 9449 §8: a single ``use_dpop_nonce`` retry, as on the other token calls.
- ``require_dpop_token_type`` (RFC 9449 §5: the client "MUST discard the
  response ... if this protection is deemed important"): a 2xx response whose
  ``token_type`` is not ``DPoP`` (compared case-insensitively, RFC 6749 §7.1)
  fails with ``TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH`` and keeps the issued
  tokens on ``rejected_token``.  Off by default: a DPoP-bound request then
  continues as a regular OAuth interaction.
"""

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import respx

from py_identity_model import (
    AuthorizationCodeTokenRequest,
    FailedResponseAccessError,
    RefreshTokenRequest,
    TokenErrorKind,
    generate_dpop_key,
)
from py_identity_model.aio.token_client import (
    refresh_token as refresh_token_async,
)
from py_identity_model.aio.token_client import (
    request_authorization_code_token as request_authorization_code_token_async,
)
from py_identity_model.exceptions import InvalidArgumentError
from py_identity_model.sync.token_client import (
    refresh_token,
    request_authorization_code_token,
)


TOKEN_URL = "https://auth.example.com/token"
DPOP_TOKEN = {"access_token": "at-1", "token_type": "DPoP", "expires_in": 300}
BEARER_TOKEN = {**DPOP_TOKEN, "token_type": "Bearer"}
NONCE_CHALLENGE = httpx.Response(
    400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "srv-nonce"}
)
# One original request + exactly one use_dpop_nonce retry (RFC 9449 §8).
EXPECTED_RETRY_CALLS = 2

DPOP_KEY = generate_dpop_key("ES256")


def _refresh(**overrides: Any) -> RefreshTokenRequest:
    fields: dict[str, Any] = {
        "address": TOKEN_URL,
        "client_id": "app1",
        "refresh_token": "rt-1",
        "dpop_key": DPOP_KEY,
        **overrides,
    }
    return RefreshTokenRequest(**fields)


def _auth_code(**overrides: Any) -> AuthorizationCodeTokenRequest:
    fields: dict[str, Any] = {
        "address": TOKEN_URL,
        "client_id": "app1",
        "code": "code",
        "redirect_uri": "https://app.example.com/cb",
        "code_verifier": "verifier",
        "dpop_key": DPOP_KEY,
        **overrides,
    }
    return AuthorizationCodeTokenRequest(**fields)


def _proof_claims(request: httpx.Request) -> dict:
    proof = request.headers.get("DPoP")
    assert proof is not None, "DPoP proof header missing"
    return pyjwt.decode(proof, options={"verify_signature": False})


SyncCall = Callable[[Any], Any]
AsyncCall = Callable[[Any], Awaitable[Any]]


@pytest.mark.unit
class TestSyncRefreshDpop:
    @respx.mock
    def test_proof_attached_without_ath(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=DPOP_TOKEN)
        )
        response = refresh_token(_refresh())
        assert response.is_successful is True
        claims = _proof_claims(route.calls.last.request)
        assert {k: claims[k] for k in ("htm", "htu")} == {
            "htm": "POST",
            "htu": TOKEN_URL,
        }
        assert "ath" not in claims
        assert "nonce" not in claims

    @respx.mock
    def test_no_proof_without_key(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=DPOP_TOKEN)
        )
        refresh_token(_refresh(dpop_key=None))
        assert route.calls.last.request.headers.get("DPoP") is None

    @respx.mock
    def test_use_dpop_nonce_retried_once(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[NONCE_CHALLENGE, httpx.Response(200, json=DPOP_TOKEN)]
        )
        response = refresh_token(_refresh())
        assert response.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        assert _proof_claims(route.calls.last.request)["nonce"] == "srv-nonce"

    @respx.mock
    def test_use_dpop_nonce_retry_bounded_to_one(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[NONCE_CHALLENGE, NONCE_CHALLENGE]
        )
        response = refresh_token(_refresh())
        assert response.is_successful is False
        assert route.call_count == EXPECTED_RETRY_CALLS

    @respx.mock
    def test_nonce_challenge_ignored_without_key(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[NONCE_CHALLENGE, httpx.Response(200, json=DPOP_TOKEN)]
        )
        response = refresh_token(_refresh(dpop_key=None))
        assert response.is_successful is False
        assert route.call_count == 1


@pytest.mark.asyncio
class TestAsyncRefreshDpop:
    @respx.mock
    async def test_proof_attached_without_ath(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=DPOP_TOKEN)
        )
        response = await refresh_token_async(_refresh())
        assert response.is_successful is True
        claims = _proof_claims(route.calls.last.request)
        assert {k: claims[k] for k in ("htm", "htu")} == {
            "htm": "POST",
            "htu": TOKEN_URL,
        }
        assert "ath" not in claims

    @respx.mock
    async def test_use_dpop_nonce_retried_once(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[NONCE_CHALLENGE, httpx.Response(200, json=DPOP_TOKEN)]
        )
        response = await refresh_token_async(_refresh())
        assert response.is_successful is True
        assert route.call_count == EXPECTED_RETRY_CALLS
        assert _proof_claims(route.calls.last.request)["nonce"] == "srv-nonce"

    @respx.mock
    async def test_use_dpop_nonce_retry_bounded_to_one(self):
        route = respx.post(TOKEN_URL).mock(
            side_effect=[NONCE_CHALLENGE, NONCE_CHALLENGE]
        )
        response = await refresh_token_async(_refresh())
        assert response.is_successful is False
        assert route.call_count == EXPECTED_RETRY_CALLS


SYNC_CALLS = [
    pytest.param(refresh_token, _refresh, id="refresh"),
    pytest.param(request_authorization_code_token, _auth_code, id="auth_code"),
]
ASYNC_CALLS = [
    pytest.param(refresh_token_async, _refresh, id="refresh"),
    pytest.param(request_authorization_code_token_async, _auth_code, id="auth_code"),
]


@pytest.mark.unit
class TestSyncDpopTokenTypeRequired:
    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @pytest.mark.parametrize(
        "token_type", ["Bearer", "bearer", "", None, 1, "DPoP-ish"]
    )
    @respx.mock
    def test_downgrade_fails(self, call: SyncCall, build, token_type):
        token = {**DPOP_TOKEN, "token_type": token_type}
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token))
        response = call(build(require_dpop_token_type=True))
        assert response.is_successful is False
        assert response.error_kind is TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH
        assert response.error == (
            f"Expected token_type 'DPoP' for a DPoP-bound request, got "
            f"{token_type!r} (RFC 9449 §5)"
        )
        assert response.rejected_token == token

    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @respx.mock
    def test_missing_token_type_fails(self, call: SyncCall, build):
        token = {k: v for k, v in DPOP_TOKEN.items() if k != "token_type"}
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token))
        response = call(build(require_dpop_token_type=True))
        assert response.is_successful is False
        assert response.error_kind is TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH

    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @pytest.mark.parametrize("token_type", ["DPoP", "dpop", "DPOP"])
    @respx.mock
    def test_dpop_token_type_accepted(self, call: SyncCall, build, token_type):
        token = {**DPOP_TOKEN, "token_type": token_type}
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token))
        response = call(build(require_dpop_token_type=True))
        assert response.is_successful is True
        assert response.error_kind is None
        assert response.rejected_token is None
        assert response.token == token

    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @respx.mock
    def test_bearer_accepted_by_default(self, call: SyncCall, build):
        """Off by default: a DPoP-bound request continues on a Bearer answer."""
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=BEARER_TOKEN))
        response = call(build())
        assert response.is_successful is True
        assert response.token == BEARER_TOKEN

    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @respx.mock
    def test_error_response_keeps_no_kind(self, call: SyncCall, build):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        response = call(build(require_dpop_token_type=True))
        assert response.is_successful is False
        assert response.error_kind is None
        assert response.rejected_token is None


@pytest.mark.asyncio
class TestAsyncDpopTokenTypeRequired:
    @pytest.mark.parametrize(("call", "build"), ASYNC_CALLS)
    @respx.mock
    async def test_downgrade_fails(self, call: AsyncCall, build):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=BEARER_TOKEN))
        response = await call(build(require_dpop_token_type=True))
        assert response.is_successful is False
        assert response.error_kind is TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH
        assert response.rejected_token == BEARER_TOKEN

    @pytest.mark.parametrize(("call", "build"), ASYNC_CALLS)
    @respx.mock
    async def test_dpop_token_type_accepted(self, call: AsyncCall, build):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=DPOP_TOKEN))
        response = await call(build(require_dpop_token_type=True))
        assert response.is_successful is True
        assert response.token == DPOP_TOKEN

    @pytest.mark.parametrize(("call", "build"), ASYNC_CALLS)
    @respx.mock
    async def test_bearer_accepted_by_default(self, call: AsyncCall, build):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=BEARER_TOKEN))
        response = await call(build())
        assert response.is_successful is True
        assert response.token == BEARER_TOKEN


@pytest.mark.unit
class TestRejectedTokenRedacted:
    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @respx.mock
    def test_repr_redacts_rejected_token(self, call: SyncCall, build):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=BEARER_TOKEN))
        response = call(build(require_dpop_token_type=True))
        assert "rejected_token='[REDACTED]'" in repr(response)
        assert BEARER_TOKEN["access_token"] not in repr(response)

    @pytest.mark.parametrize(("call", "build"), SYNC_CALLS)
    @respx.mock
    def test_token_stays_guarded_on_refused_response(self, call: SyncCall, build):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=BEARER_TOKEN))
        response = call(build(require_dpop_token_type=True))
        with pytest.raises(FailedResponseAccessError):
            _ = response.token


@pytest.mark.unit
class TestOptInNeedsKey:
    @pytest.mark.parametrize("build", [_refresh, _auth_code])
    def test_flag_without_key_refused(self, build):
        with pytest.raises(
            InvalidArgumentError, match=r"^require_dpop_token_type needs a dpop_key$"
        ):
            build(dpop_key=None, require_dpop_token_type=True)

    @pytest.mark.parametrize("build", [_refresh, _auth_code])
    def test_no_flag_without_key_allowed(self, build):
        assert build(dpop_key=None).require_dpop_token_type is False
