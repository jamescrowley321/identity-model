"""
Unit tests for sync UserInfo client.

These tests verify sync-specific UserInfo client logic including
the get_userinfo function with JSON and JWT response handling.
"""

from typing import Any

import httpx
import pytest
import respx

from py_identity_model.core.models import UserInfoErrorKind, UserInfoRequest
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
            expected_sub="248289761001",
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
        """A JWT response cannot be checked against the ID token sub."""
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
            expected_sub="248289761001",
        )

        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error_kind is UserInfoErrorKind.UNVERIFIABLE_SUB
        assert response.unverified_jwt == jwt_string

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
            expected_sub="248289761001",
        )

        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "401" in response.error
        assert response.error_kind is None

    @respx.mock
    def test_get_userinfo_network_error(self):
        """Test UserInfo request with network error."""
        respx.get("https://example.com/userinfo").mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="test_access_token",
            expected_sub="248289761001",
        )

        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error is not None
        assert "Network error" in response.error


class TestSyncUserInfoSubValidation:
    """Test sub claim validation per OIDC Core 1.0 Section 5.3.2."""

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
        assert response.error == (
            "UserInfo sub mismatch: expected 'user-123', got 'user-999'"
        )
        assert response.error_kind is UserInfoErrorKind.SUB_MISMATCH

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

    @pytest.mark.parametrize(
        "body",
        [
            {"name": "Test"},
            {"sub": "", "name": "Test"},
            {"sub": 123, "name": "Test"},
            {"sub": None, "name": "Test"},
            ["sub", "user-123"],
        ],
        ids=["absent", "empty", "non-string", "null", "non-object"],
    )
    @respx.mock
    def test_missing_sub_rejected(self, body):
        """A response with no usable sub is rejected.

        OIDC Core 1.0 §5.3.2: the sub claim MUST always be returned.
        """
        respx.get("https://example.com/userinfo").mock(
            return_value=httpx.Response(
                200,
                json=body,
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address="https://example.com/userinfo",
            token="tok",
            expected_sub="248289761001",
        )
        response = get_userinfo(request)

        assert response.is_successful is False
        assert response.error == "UserInfo response is missing required 'sub' claim"
        assert response.error_kind is UserInfoErrorKind.MISSING_SUB

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
            "JWT (application/jwt)"
        )
        assert response.error_kind is UserInfoErrorKind.UNVERIFIABLE_SUB
        assert response.unverified_jwt == jwt_string


def test_expected_sub_is_required():
    """OIDC Core 1.0 §5.3.2: there is no UserInfoRequest without expected_sub."""
    kwargs: dict[str, Any] = {"address": "https://example.com/userinfo", "token": "tok"}
    with pytest.raises(TypeError, match="expected_sub"):
        UserInfoRequest(**kwargs)
