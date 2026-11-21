"""Unit tests for OAuth 2.0 Refresh Token Grant."""

import httpx
import pytest
import respx

from py_identity_model import (
    RefreshTokenRequest,
    RefreshTokenResponse,
)
from py_identity_model.exceptions import FailedResponseAccessError
from py_identity_model.sync.token_client import refresh_token


TOKEN_URL = "https://auth.example.com/token"
TOKEN_JSON = {
    "access_token": "new_access_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new_refresh_token",
}


@pytest.mark.unit
class TestRefreshToken:
    @respx.mock
    def test_successful_refresh(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="old_refresh_token",
                client_secret="secret",
            )
        )

        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] == "new_access_token"

    @respx.mock
    def test_refresh_with_scope(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
                scope="openid profile",
            )
        )

        assert response.is_successful is True
        request = route.calls[0].request
        body = request.content.decode()
        assert "scope=openid+profile" in body or "scope=openid%20profile" in body

    @respx.mock
    def test_refresh_http_error_reports_only_status(self) -> None:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, content=b'{"error": "invalid_grant"}')
        )

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="expired_rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error == "Token refresh failed with status code: 400"

    @respx.mock
    def test_public_client_refresh(self):
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=TOKEN_JSON))

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="public_app",
                refresh_token="rt",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_failed_response_guard(self):
        """Accessing .token on failed response raises FailedResponseAccessError."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(401, content=b'{"error": "invalid_client"}')
        )

        response = refresh_token(
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
    def test_confidential_client_uses_basic_auth(self):
        """RFC 6749 §2.3.1: Confidential clients use Basic Auth, no client_id in body."""
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json=TOKEN_JSON)
        )

        refresh_token(
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
    def test_network_error(self):
        """Network errors are caught and returned as error responses."""
        respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

        response = refresh_token(
            RefreshTokenRequest(
                address=TOKEN_URL,
                client_id="app1",
                refresh_token="rt",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error


SECRET_TOKEN = {
    "access_token": "SUPER_SECRET_AT",
    "refresh_token": "SUPER_SECRET_RT",
}


@pytest.mark.unit
class TestRefreshTokenResponseReprRedaction:
    """#431: the ``token`` dict is a secret and must not leak via repr/str."""

    def test_repr_redacts_token_value(self):
        response = RefreshTokenResponse(is_successful=True, token=SECRET_TOKEN)

        rendered = repr(response)
        assert "RefreshTokenResponse" in rendered
        assert "[REDACTED]" in rendered
        assert "SUPER_SECRET_AT" not in rendered
        assert "SUPER_SECRET_RT" not in rendered

    def test_str_redacts_token_value(self):
        # str() falls back to __repr__ for dataclasses, so it must redact too.
        response = RefreshTokenResponse(is_successful=True, token=SECRET_TOKEN)

        assert "SUPER_SECRET_AT" not in str(response)
        assert "[REDACTED]" in str(response)

    def test_repr_of_failed_response_does_not_crash_or_leak(self):
        # token is None on failure -> printed as None, guard not tripped, no leak.
        response = RefreshTokenResponse(
            is_successful=False, error="invalid_grant", token=None
        )

        rendered = repr(response)
        assert "invalid_grant" in rendered
        assert "[REDACTED]" not in rendered
        assert "token=None" in rendered

    def test_equality_still_behaves(self):
        a = RefreshTokenResponse(is_successful=True, token=SECRET_TOKEN)
        b = RefreshTokenResponse(is_successful=True, token=dict(SECRET_TOKEN))
        c = RefreshTokenResponse(is_successful=True, token={"access_token": "other"})

        assert a == b
        assert a != c
        assert a != "not-a-response"
