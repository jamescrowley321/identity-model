"""Integration tests for UserInfo endpoint operations."""

from py_identity_model import (
    UserInfoRequest,
    get_userinfo,
)


# These requests fail before any sub comparison: a client credentials token
# has no end user, so there is no ID token sub to expect.
NO_END_USER_SUB = "no-end-user"


def test_discovery_document_has_userinfo_endpoint(discovery_document, require_https):
    """Test that the discovery document includes a userinfo_endpoint."""
    assert discovery_document.is_successful is True
    assert discovery_document.userinfo_endpoint is not None
    if require_https:
        assert discovery_document.userinfo_endpoint.startswith("https://")
    else:
        assert discovery_document.userinfo_endpoint.startswith(
            "http://"
        ) or discovery_document.userinfo_endpoint.startswith("https://")


def test_get_userinfo_with_invalid_token(userinfo_endpoint):
    """Test that UserInfo fails with an invalid token."""
    assert userinfo_endpoint is not None

    request = UserInfoRequest(
        address=userinfo_endpoint,
        token="invalid-token-that-does-not-exist",
        expected_sub=NO_END_USER_SUB,
    )
    response = get_userinfo(request)

    assert response.is_successful is False
    assert response.error is not None


def test_get_userinfo_with_invalid_endpoint(client_credentials_token):
    """Test that UserInfo fails with an invalid endpoint."""
    assert client_credentials_token.token is not None

    request = UserInfoRequest(
        address="https://invalid.example.com/userinfo",
        token=client_credentials_token.token["access_token"],
        expected_sub=NO_END_USER_SUB,
    )
    response = get_userinfo(request)

    assert response.is_successful is False
    assert response.error is not None
