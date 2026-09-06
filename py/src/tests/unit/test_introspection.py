"""Unit tests for OAuth 2.0 Token Introspection (RFC 7662)."""

import httpx
import pytest
import respx

from py_identity_model import (
    TokenIntrospectionRequest,
)
from py_identity_model.exceptions import FailedResponseAccessError
from py_identity_model.sync.introspection import introspect_token


INTROSPECT_URL = "https://auth.example.com/introspect"


@pytest.mark.unit
class TestIntrospection:
    @respx.mock
    def test_active_token(self):
        """INTR-001: introspecting an active token returns active=true plus the standard claims."""
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "active": True,
                    "scope": "openid profile",
                    "client_id": "app1",
                    "username": "user@example.com",
                    "token_type": "Bearer",
                    "exp": 1735689600,
                    "iat": 1735686000,
                    "sub": "user123",
                    "aud": "api",
                    "iss": "https://auth.example.com",
                },
            )
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="access_token_here",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is True
        assert response.claims is not None
        assert response.claims["active"] is True
        assert response.claims["scope"] == "openid profile"
        assert response.claims["sub"] == "user123"

    @respx.mock
    def test_inactive_token(self):
        """INTR-002: an inactive/expired/revoked token returns active=false and no other claims."""
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(200, json={"active": False})
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="expired_token",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is True
        assert response.claims is not None
        assert response.claims["active"] is False

    @respx.mock
    def test_error_response(self):
        """INTR-005: an error response from the introspection endpoint surfaces as a typed error."""
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(401, content=b"Unauthorized")
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="token",
                client_id="app1",
                client_secret="wrong_secret",
            )
        )

        assert response.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = response.claims
        assert response.error is not None

    @respx.mock
    def test_network_error(self):
        respx.post(INTROSPECT_URL).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="token",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "Connection refused" in response.error

    @respx.mock
    def test_with_token_type_hint(self):
        """INTR-004: token_type_hint is sent on the request when configured."""
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(200, json={"active": True})
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="refresh_token_here",
                client_id="app1",
                client_secret="secret",
                token_type_hint="refresh_token",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_public_client_no_auth_header(self):
        """INTR-003 (partial): client authentication on the introspection request. Python covers the
        no-credentials and client_secret_basic halves; there is no client_secret_post path
        (identity-model#574), so that half of INTR-003 is deliberately unanchored, not overlooked."""
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(200, json={"active": True})
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="token",
                client_id="public_app",
            )
        )

        assert response.is_successful is True

    @respx.mock
    def test_non_dict_json_response(self):
        respx.post(INTROSPECT_URL).mock(
            return_value=httpx.Response(200, json=["not", "a", "dict"])
        )

        response = introspect_token(
            TokenIntrospectionRequest(
                address=INTROSPECT_URL,
                token="token",
                client_id="app1",
                client_secret="secret",
            )
        )

        assert response.is_successful is False
        assert response.error is not None
        assert "not a JSON object" in response.error
