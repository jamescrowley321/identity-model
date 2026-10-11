"""
Unit tests for sync UserInfo client.

These tests verify sync-specific UserInfo client logic including
the get_userinfo function with JSON and JWT response handling.
"""

import httpx
import respx

from py_identity_model.core.models import UserInfoRequest
from py_identity_model.sync.userinfo import get_userinfo


class TestSyncUserInfo:
    """Test sync UserInfo client functionality."""

    @respx.mock
    def test_get_userinfo_json_success(self):
        """Test successful UserInfo request with JSON response."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json={
                    "sub": "248289761001",
                    "name": "Jane Doe",
                    "email": "janedoe@example.com",
                    "email_verified": True,
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="test_access_token",
        )

        response = get_userinfo(request)

        assert response.is_successful is True
        assert response.claims is not None
        assert response.claims["sub"] == "248289761001"
        assert response.claims["name"] == "Jane Doe"
        assert response.claims["email"] == "janedoe@example.com"
        assert response.raw is None

    @respx.mock
    def test_get_userinfo_jwt_response(self):
        """Test UserInfo request with JWT response (raw stored, claims empty)."""
        jwt_string = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.signature"
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                text=jwt_string,
                headers={"Content-Type": "application/jwt"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="test_access_token",
        )

        response = get_userinfo(request)

        assert response.is_successful is True
        assert response.raw == jwt_string
        assert response.claims is None

    @respx.mock
    def test_get_userinfo_http_error(self):
        """Test UserInfo request with HTTP error response."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                401,
                json={"error": "invalid_token"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="expired_token",
        )

        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "401" in response.error

    @respx.mock
    def test_get_userinfo_network_error(self):
        """Test UserInfo request with network error."""
        respx.get("https://example.com/userinfo").mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="test_access_token",
        )

        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "Network error" in response.error


class TestSyncUserInfoSubValidation:
    """Test sub claim validation per OIDC Core 1.0 Section 5.3.4."""

    @respx.mock
    def test_sub_validation_match(self):
        """Matching expected_sub passes through successfully."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-123", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
            expected_sub="user-123",
        )
        response = get_userinfo(request)

        assert response.is_successful is True
        assert response.claims is not None
        assert response.claims["sub"] == "user-123"

    @respx.mock
    def test_sub_validation_mismatch(self):
        """Mismatched expected_sub returns error response."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-999", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
            expected_sub="user-123",
        )
        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "sub mismatch" in response.error
        assert "user-123" in response.error
        assert "user-999" in response.error

    @respx.mock
    def test_sub_validation_missing_sub(self):
        """Missing sub claim in response returns error."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json={"name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
            expected_sub="user-123",
        )
        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "missing" in response.error.lower()

    @respx.mock
    def test_sub_validation_not_requested(self):
        """No expected_sub skips validation entirely."""
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-123", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
        )
        response = get_userinfo(request)

        assert response.is_successful is True
        assert response.claims is not None
        assert response.claims["sub"] == "user-123"

    @respx.mock
    def test_sub_validation_jwt_response(self):
        """A JWT response with expected_sub fails closed (OIDC Core §5.3.4).

        The payload sub equals expected_sub: only an unverified decode could
        compare it, so the unverifiable response is rejected, not accepted.
        """
        jwt_string = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.sig"
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                text=jwt_string,
                headers={"Content-Type": "application/jwt"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
            expected_sub="248289761001",
        )
        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error == (
            "UserInfo sub cannot be verified: the response is a signed or encrypted "
            "JWT (application/jwt). Verify and decode it, then compare its sub, "
            "or omit expected_sub."
        )
