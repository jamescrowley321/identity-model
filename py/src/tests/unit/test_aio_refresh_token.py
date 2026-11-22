"""Async tests for aio.token_client.refresh_token (NFR-9 parity)."""

import httpx
import pytest
import respx

from py_identity_model import (
    RefreshTokenRequest,
)
from py_identity_model.aio.token_client import refresh_token
from py_identity_model.exceptions import FailedResponseAccessError


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {
    "access_token": "new_access_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new_refresh_token",
}


@pytest.mark.asyncio
class TestAsyncRefreshToken:
    @respx.mock
    async def test_successful_refresh(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        response = await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="old_rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "new_access_token"

    @respx.mock
    async def test_refresh_error(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, content=b'{"error": "invalid_grant"}')
        )

        response = await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="expired_rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None

    @respx.mock
    async def test_network_error(self):
        respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

        response = await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        # The exception detail is logged server-side, never returned (#1182).
        assert response.error == "Network error during token refresh"

    @respx.mock
    async def test_failed_response_guard(self):
        """Accessing .token on failed response raises FailedResponseAccessError."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(401, content=b'{"error": "invalid_client"}')
        )

        response = await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="wrong",
            )
        )

        assert response.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = response.token

    @respx.mock
    async def test_confidential_client_uses_basic_auth(self):
        """RFC 6749: Confidential clients authenticate via HTTP Basic."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        request = route.calls[0].request
        assert request.headers.get("authorization") is not None
        assert request.headers["authorization"].startswith("Basic ")
        body = request.content.decode()
        assert "client_id=" not in body

    @respx.mock
    async def test_public_client_sends_client_id_in_body(self):
        """RFC 6749: Public clients send client_id in POST body without auth."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="public_app",
                refresh_token="rt",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "client_id=public_app" in body
        assert request.headers.get("authorization") is None

    @respx.mock
    async def test_scope_sent_in_body(self):
        """RFC 6749 Section 6: scope included in POST body when provided."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
                scope="openid profile",
            )
        )

        request = route.calls[0].request
        body = request.content.decode()
        assert "scope=openid+profile" in body or "scope=openid%20profile" in body

    @respx.mock
    async def test_content_type_header(self):
        """RFC 6749: Token requests use form-urlencoded content type."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        request = route.calls[0].request
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"

    @respx.mock
    async def test_unexpected_error_returns_error_response(self):
        """Non-RequestError exceptions are caught and returned as error responses."""
        respx.post(TOKEN_URL).mock(side_effect=RuntimeError("unexpected"))

        response = await refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
