"""Async tests for aio.userinfo module."""

import httpx
import pytest
import respx

from py_identity_model.aio.userinfo import UserInfoRequest, get_userinfo
from py_identity_model.exceptions import FailedResponseAccessError


@pytest.mark.asyncio
class TestAsyncUserInfo:
    @respx.mock
    async def test_async_get_userinfo_json_success(self):
        """Test successful async UserInfo request with JSON response."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
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
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.claims is not None
        assert result.claims["sub"] == "248289761001"
        assert result.claims["name"] == "Jane Doe"
        assert result.raw is None

    @respx.mock
    async def test_async_get_userinfo_jwt_response(self):
        """Test async UserInfo request with JWT response."""
        url = "https://example.com/userinfo"
        jwt_string = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.signature"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                text=jwt_string,
                headers={"Content-Type": "application/jwt"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.raw == jwt_string
        assert result.claims is None

    @respx.mock
    async def test_async_get_userinfo_http_error(self):
        """Test async UserInfo request with HTTP error."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(return_value=httpx.Response(401, content=b"Unauthorized"))

        request = UserInfoRequest(
            address=url,
            token="expired_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        with pytest.raises(FailedResponseAccessError):
            _ = result.claims
        assert result.error is not None
        assert "401" in result.error

    @respx.mock
    async def test_async_get_userinfo_network_error(self):
        """Test async UserInfo request with network error."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = UserInfoRequest(
            address=url,
            token="test_access_token",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error


@pytest.mark.asyncio
class TestAsyncUserInfoSubValidation:
    """Test sub claim validation per OIDC Core 1.0 Section 5.3.4."""

    @respx.mock
    async def test_sub_validation_match(self):
        """Matching expected_sub passes through successfully."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-123", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="tok",
            expected_sub="user-123",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.claims is not None
        assert result.claims["sub"] == "user-123"

    @respx.mock
    async def test_sub_validation_mismatch(self):
        """Mismatched expected_sub returns error response."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-999", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="tok",
            expected_sub="user-123",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "sub mismatch" in result.error
        assert "user-123" in result.error
        assert "user-999" in result.error

    @respx.mock
    async def test_sub_validation_missing_sub(self):
        """Missing sub claim in response returns error."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="tok",
            expected_sub="user-123",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "missing" in result.error.lower()

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
    async def test_missing_sub_rejected_without_expected_sub(self, body):
        """A response with no usable sub is rejected even without expected_sub.

        OIDC Core 1.0 §5.3.2: the sub claim MUST always be returned.
        """
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json=body,
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(address=url, token="tok")
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error == "UserInfo response is missing required 'sub' claim"

    @respx.mock
    async def test_sub_validation_not_requested(self):
        """No expected_sub skips validation entirely."""
        url = "https://example.com/userinfo"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"sub": "user-123", "name": "Test"},
                headers={"Content-Type": "application/json"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="tok",
        )
        result = await get_userinfo(request)

        assert result.is_successful is True
        assert result.claims is not None
        assert result.claims["sub"] == "user-123"

    @respx.mock
    async def test_sub_validation_jwt_response(self):
        """A JWT response with expected_sub fails closed (OIDC Core §5.3.4).

        The payload sub equals expected_sub: only an unverified decode could
        compare it, so the unverifiable response is rejected, not accepted.
        """
        url = "https://example.com/userinfo"
        jwt_string = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.sig"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                text=jwt_string,
                headers={"Content-Type": "application/jwt"},
            )
        )

        request = UserInfoRequest(
            address=url,
            token="tok",
            expected_sub="248289761001",
        )
        result = await get_userinfo(request)

        assert result.is_successful is False
        assert result.error == (
            "UserInfo sub cannot be verified: the response is a signed or encrypted "
            "JWT (application/jwt). Verify and decode it, then compare its sub, "
            "or omit expected_sub."
        )
