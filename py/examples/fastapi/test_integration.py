"""
Integration tests for the FastAPI OAuth/OIDC example.

These tests verify that the FastAPI application correctly integrates with
an identity server and properly validates tokens.
"""

import os
import pathlib
import sys
import time
import traceback

import requests
import urllib3

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    UserInfoRequest,
    get_discovery_document,
    get_userinfo,
    request_client_credentials_token,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy


# HTTP status codes
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_INTERNAL_SERVER_ERROR = 500

# Configuration from environment
DISCOVERY_URL = os.getenv(
    "DISCOVERY_URL",
    "https://localhost:5001/.well-known/openid-configuration",
)
FASTAPI_URL = os.getenv("FASTAPI_URL", "http://localhost:8000")
CLIENT_ID = os.getenv("CLIENT_ID", "py-identity-model-client")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "py-identity-model-secret")
SCOPE = os.getenv("SCOPE", "py-identity-model")


def _get_ssl_verify() -> bool | str:
    """Get SSL verification setting from environment."""
    ca_bundle = os.getenv("REQUESTS_CA_BUNDLE")
    return ca_bundle if ca_bundle else False


def _make_request(
    method: str,
    endpoint: str,
    headers: dict | None = None,
    **kwargs,
) -> requests.Response:
    """Helper to make HTTP requests to the FastAPI service."""
    url = f"{FASTAPI_URL}{endpoint}"
    return requests.request(method, url, headers=headers, timeout=30, **kwargs)


def _create_auth_headers(token: str) -> dict:
    """Create authorization headers with bearer token."""
    return {"Authorization": f"Bearer {token}"}


def get_access_token() -> tuple[str | None, str | None]:
    """Get an access token and userinfo endpoint from the identity server.

    Returns:
        Tuple of (access_token, userinfo_endpoint). Either may be None on failure.
    """
    print(f"🔍 Getting discovery document from {DISCOVERY_URL}")

    try:
        # Get discovery document using py-identity-model
        # Disable endpoint validation for Docker: the identity server's
        # internal hostname differs from the external discovery URL.
        policy = DiscoveryPolicy(validate_endpoints=False)
        disco_request = DiscoveryDocumentRequest(address=DISCOVERY_URL, policy=policy)
        disco_response = get_discovery_document(disco_request)

        if not disco_response.is_successful:
            print(f"❌ Discovery failed: {disco_response.error}")
            return None, None

        if not disco_response.token_endpoint:
            print("❌ Token endpoint not found in discovery document")
            return None, None

        userinfo_endpoint = disco_response.userinfo_endpoint
        if userinfo_endpoint:
            print(f"📋 UserInfo endpoint: {userinfo_endpoint}")

        print(f"🎫 Requesting token from {disco_response.token_endpoint}")

        # Request token using py-identity-model
        token_request = ClientCredentialsTokenRequest(
            address=disco_response.token_endpoint,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=SCOPE,
        )
        token_response = request_client_credentials_token(token_request)

        if not token_response.is_successful:
            print(f"❌ Token request failed: {token_response.error}")
            return None, userinfo_endpoint

        access_token = (
            token_response.token.get("access_token") if token_response.token else None
        )
        if access_token:
            print("✅ Successfully obtained access token")
            return access_token, userinfo_endpoint
        print("❌ No access token in response")
        return None, userinfo_endpoint

    except Exception as e:
        print(f"❌ Error getting access token: {e}")
        return None, None


def wait_for_service(url: str, max_attempts: int = 30) -> bool:
    """Wait for a service to become available."""
    print(f"⏳ Waiting for service at {url}")

    for attempt in range(max_attempts):
        try:
            response = requests.get(url, timeout=5, verify=_get_ssl_verify())
            if response.status_code < HTTP_INTERNAL_SERVER_ERROR:
                print(f"✅ Service available at {url}")
                return True
        except requests.exceptions.RequestException as e:
            if attempt == 0 or attempt % 10 == 0:
                print(f"  Attempt {attempt + 1}/{max_attempts}: {e}")

        if attempt < max_attempts - 1:
            time.sleep(2)

    print(f"❌ Service at {url} did not become available")
    return False


def test_public_endpoints():
    """Test public endpoints that don't require authentication."""
    print("\n🧪 Testing public endpoints...")

    # Test root endpoint
    response = _make_request("GET", "/")
    assert response.status_code == HTTP_OK, f"Root endpoint failed: {response.text}"
    data = response.json()
    assert "message" in data
    print("✅ Root endpoint works")

    # Test health endpoint
    response = _make_request("GET", "/health")
    assert response.status_code == HTTP_OK, f"Health endpoint failed: {response.text}"
    data = response.json()
    assert data["status"] == "healthy"
    print("✅ Health endpoint works")


def test_protected_endpoints_without_token():
    """Test that protected endpoints reject requests without tokens."""
    print("\n🧪 Testing protected endpoints without token...")

    protected_endpoints = [
        "/api/me",
        "/api/claims",
        "/api/token-info",
        "/api/profile",
        "/api/data",
    ]

    for endpoint in protected_endpoints:
        response = _make_request("GET", endpoint)
        assert response.status_code == HTTP_UNAUTHORIZED, (
            f"Expected 401 for {endpoint} without token, got {response.status_code}"
        )
        print(f"✅ {endpoint} correctly rejects request without token")


def test_protected_endpoints_with_invalid_token():
    """Test that protected endpoints reject requests with invalid tokens."""
    print("\n🧪 Testing protected endpoints with invalid token...")

    headers = {"Authorization": "Bearer invalid-token-123"}
    response = _make_request("GET", "/api/me", headers=headers)
    assert response.status_code == HTTP_UNAUTHORIZED, (
        f"Expected 401 for invalid token, got {response.status_code}"
    )
    print("✅ Protected endpoint correctly rejects invalid token")


def test_protected_endpoints_with_valid_token(token: str):
    """Test protected endpoints with a valid token."""
    print("\n🧪 Testing protected endpoints with valid token...")

    headers = _create_auth_headers(token)

    # Test /api/me
    response = _make_request("GET", "/api/me", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/me failed: {response.text}"
    data = response.json()
    assert data["authenticated"] is True, (
        f"Expected authenticated=True, got {data.get('authenticated')}"
    )
    assert data["authentication_type"] == "Bearer", (
        f"Expected authentication_type='Bearer', got {data.get('authentication_type')}"
    )
    print("✅ /api/me works with valid token")

    # Test /api/claims
    response = _make_request("GET", "/api/claims", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/claims failed: {response.text}"
    data = response.json()
    assert "claims" in data
    assert "scope" in data["claims"] or "scp" in data["claims"]
    print("✅ /api/claims works with valid token")

    # Test /api/token-info
    response = _make_request("GET", "/api/token-info", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/token-info failed: {response.text}"
    data = response.json()
    assert "token_length" in data
    assert data["token_length"] > 0
    print("✅ /api/token-info works with valid token")

    # Test /api/profile
    response = _make_request("GET", "/api/profile", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/profile failed: {response.text}"
    data = response.json()
    assert "user_id" in data
    print("✅ /api/profile works with valid token")

    # Test /api/data (requires scope)
    response = _make_request("GET", "/api/data", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/data failed: {response.text}"
    data = response.json()
    assert "data" in data
    assert len(data["data"]) > 0
    print("✅ /api/data works with valid token and correct scope")


def test_scope_based_authorization(token: str):
    """Test scope-based authorization."""
    print("\n🧪 Testing scope-based authorization...")

    headers = _create_auth_headers(token)

    # Test endpoint requiring write scope (should fail with default token)
    response = _make_request(
        "POST",
        "/api/data",
        headers=headers,
        params={"name": "Test Item"},
    )
    # This should fail because the token doesn't have write scope
    assert response.status_code == HTTP_FORBIDDEN, (
        "Expected 403 for missing write scope"
    )
    print("✅ Write endpoint correctly rejects token without write scope")


def test_admin_endpoints_without_role(token: str):
    """Test that admin endpoints reject tokens without admin role."""
    print("\n🧪 Testing admin endpoints without admin role...")

    headers = _create_auth_headers(token)

    # Test admin endpoints (should fail without admin role)
    response = _make_request("DELETE", "/api/admin/users/123", headers=headers)
    assert response.status_code == HTTP_FORBIDDEN, (
        f"Expected 403 for missing admin role, got {response.status_code}: {response.text}"
    )
    print(
        "✅ Admin delete endpoint correctly rejects token without admin role",
    )

    response = _make_request("GET", "/api/admin/stats", headers=headers)
    assert response.status_code == HTTP_FORBIDDEN, "Expected 403 for missing admin role"
    print("✅ Admin stats endpoint correctly rejects token without admin role")


def test_userinfo_endpoint(userinfo_endpoint: str):
    """Test UserInfo endpoint integration using py-identity-model."""
    print("\n🧪 Testing UserInfo endpoint...")

    # UserInfo returns claims about the end user of an OIDC login, checked
    # against that login's ID token sub (OIDC Core 1.0 §5.3.2). A client
    # credentials token has no end user, so only the rejection path runs here.
    # An invalid token fails at the endpoint, before the sub comparison.
    request = UserInfoRequest(
        address=userinfo_endpoint,
        token="invalid-token",
        expected_sub="no-end-user",
    )
    response = get_userinfo(request)

    assert response.is_successful is False, (
        "Expected UserInfo to fail with invalid token"
    )
    assert response.error is not None
    print("✅ UserInfo correctly rejects invalid token")


def run_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("FastAPI OAuth/OIDC Integration Tests")
    print("=" * 60)

    # Print environment info
    print("\n📋 Environment Configuration:")
    print(f"  DISCOVERY_URL: {DISCOVERY_URL}")
    print(f"  FASTAPI_URL: {FASTAPI_URL}")
    print(
        f"  REQUESTS_CA_BUNDLE: {os.getenv('REQUESTS_CA_BUNDLE', 'Not set')}",
    )

    # Check if CA bundle exists
    ca_bundle = os.getenv("REQUESTS_CA_BUNDLE")
    if ca_bundle:
        if pathlib.Path(ca_bundle).exists():
            print("  ✅ CA bundle file exists")
        else:
            print(f"  ⚠️  CA bundle file not found at {ca_bundle}")

    # Disable SSL warnings for local testing
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Wait for services to be ready
    if not wait_for_service(FASTAPI_URL):
        print("❌ FastAPI service not available")
        return 1

    if not wait_for_service(DISCOVERY_URL):
        print("❌ Identity server not available")
        return 1

    # Get access token and userinfo endpoint
    token, userinfo_endpoint = get_access_token()
    if not token:
        print("❌ Failed to obtain access token")
        return 1

    try:
        # Run all tests
        test_public_endpoints()
        test_protected_endpoints_without_token()
        test_protected_endpoints_with_invalid_token()
        test_protected_endpoints_with_valid_token(token)
        test_scope_based_authorization(token)
        test_admin_endpoints_without_role(token)
        if userinfo_endpoint:
            test_userinfo_endpoint(userinfo_endpoint)
        else:
            print("\n⚠️  Skipping UserInfo tests (no userinfo_endpoint in discovery)")

        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        return 0

    except Exception as e:
        error_type = (
            "Test failed" if isinstance(e, AssertionError) else "Unexpected error"
        )
        print(f"\n❌ {error_type}: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
