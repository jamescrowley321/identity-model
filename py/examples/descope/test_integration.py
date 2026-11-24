"""
Integration tests for the Descope FastAPI example.

These tests verify that the FastAPI application correctly integrates with
Descope's OIDC provider and properly validates tokens.
"""

import os
import sys
import time
import traceback

import requests

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)


# HTTP status codes
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_SERVER_ERROR_THRESHOLD = 500

# Configuration from environment
DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID", "")
ISSUER = os.getenv("ISSUER", f"https://api.descope.com/{DESCOPE_PROJECT_ID}")
FASTAPI_URL = os.getenv("FASTAPI_URL", "http://localhost:8000")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
SCOPE = os.getenv("SCOPE", "openid")


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


def get_access_token() -> str | None:
    """Get an access token from Descope using client credentials."""
    print(f"🔍 Getting discovery document for {ISSUER}")

    try:
        # Get discovery document using py-identity-model
        disco_request = DiscoveryDocumentRequest(issuer=ISSUER)
        disco_response = get_discovery_document(disco_request)

        if not disco_response.is_successful:
            print(f"❌ Discovery failed: {disco_response.error}")
            return None

        if not disco_response.token_endpoint:
            print("❌ Token endpoint not found in discovery document")
            return None

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
            return None

        access_token = (
            token_response.token.get("access_token") if token_response.token else None
        )
        if access_token:
            print("✅ Successfully obtained access token from Descope")
            return access_token
        print("❌ No access token in response")
        return None

    except Exception as e:
        print(f"❌ Error getting access token: {e}")
        return None


def wait_for_service(url: str, max_attempts: int = 30) -> bool:
    """Wait for a service to become available."""
    print(f"⏳ Waiting for service at {url}")

    for attempt in range(max_attempts):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < HTTP_SERVER_ERROR_THRESHOLD:
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
    assert "descope_project_id" in data
    print("✅ Root endpoint works")

    # Test health endpoint
    response = _make_request("GET", "/health")
    assert response.status_code == HTTP_OK, f"Health endpoint failed: {response.text}"
    data = response.json()
    assert data["status"] == "healthy"
    assert data["provider"] == "descope"
    print("✅ Health endpoint works")


def test_protected_endpoints_without_token():
    """Test that protected endpoints reject requests without tokens."""
    print("\n🧪 Testing protected endpoints without token...")

    protected_endpoints = [
        "/api/me",
        "/api/claims",
        "/api/token-info",
        "/api/profile",
        "/api/descope/roles",
        "/api/descope/permissions",
    ]

    for endpoint in protected_endpoints:
        response = _make_request("GET", endpoint)
        assert response.status_code == HTTP_UNAUTHORIZED, (
            f"Expected 401 for {endpoint}, got {response.status_code}"
        )
        print(f"✅ {endpoint} correctly rejects missing token")


def test_protected_endpoints_with_invalid_token():
    """Test that protected endpoints reject invalid tokens."""
    print("\n🧪 Testing protected endpoints with invalid token...")

    invalid_token = "invalid.jwt.token"
    headers = _create_auth_headers(invalid_token)

    protected_endpoints = [
        "/api/me",
        "/api/claims",
    ]

    for endpoint in protected_endpoints:
        response = _make_request("GET", endpoint, headers=headers)
        assert response.status_code == HTTP_UNAUTHORIZED, (
            f"Expected 401 for {endpoint}, got {response.status_code}"
        )
        print(f"✅ {endpoint} correctly rejects invalid token")


def test_protected_endpoints_with_valid_token():
    """Test that protected endpoints work with valid tokens."""
    print("\n🧪 Testing protected endpoints with valid token...")

    # Get a valid token
    token = get_access_token()
    if not token:
        print("⚠️  Skipping tests - could not obtain access token")
        print("   Make sure Descope credentials are configured correctly")
        return

    headers = _create_auth_headers(token)

    # Test /api/me endpoint
    response = _make_request("GET", "/api/me", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/me failed: {response.text}"
    data = response.json()
    assert data["authenticated"] is True
    print("✅ /api/me works with valid token")

    # Test /api/claims endpoint
    response = _make_request("GET", "/api/claims", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/claims failed: {response.text}"
    data = response.json()
    assert "claims" in data
    assert isinstance(data["claims"], dict)
    print("✅ /api/claims works with valid token")

    # Test /api/profile endpoint
    response = _make_request("GET", "/api/profile", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/profile failed: {response.text}"
    data = response.json()
    assert "user_id" in data
    print("✅ /api/profile works with valid token")

    # Test /api/token-info endpoint
    response = _make_request("GET", "/api/token-info", headers=headers)
    assert response.status_code == HTTP_OK, f"/api/token-info failed: {response.text}"
    data = response.json()
    assert "token_length" in data
    print("✅ /api/token-info works with valid token")


def test_descope_specific_endpoints():
    """Test Descope-specific endpoints (roles and permissions)."""
    print("\n🧪 Testing Descope-specific endpoints...")

    token = get_access_token()
    if not token:
        print("⚠️  Skipping tests - could not obtain access token")
        return

    headers = _create_auth_headers(token)

    # Test /api/descope/roles endpoint
    response = _make_request("GET", "/api/descope/roles", headers=headers)
    assert response.status_code == HTTP_OK, (
        f"/api/descope/roles failed: {response.text}"
    )
    data = response.json()
    assert "roles" in data
    assert isinstance(data["roles"], list)
    print(f"✅ /api/descope/roles works - found {len(data['roles'])} roles")

    # Test /api/descope/permissions endpoint
    response = _make_request("GET", "/api/descope/permissions", headers=headers)
    assert response.status_code == HTTP_OK, (
        f"/api/descope/permissions failed: {response.text}"
    )
    data = response.json()
    assert "permissions" in data
    assert isinstance(data["permissions"], list)
    print(
        f"✅ /api/descope/permissions works - found {len(data['permissions'])} permissions"
    )


def test_scope_based_authorization():
    """Test scope-based authorization."""
    print("\n🧪 Testing scope-based authorization...")

    token = get_access_token()
    if not token:
        print("⚠️  Skipping tests - could not obtain access token")
        return

    headers = _create_auth_headers(token)

    # Test /api/data endpoint (requires openid scope)
    response = _make_request("GET", "/api/data", headers=headers)
    # Will be 200 if token has required scope, 403 otherwise
    assert response.status_code in [HTTP_OK, HTTP_FORBIDDEN], (
        f"Unexpected status code: {response.status_code}"
    )

    if response.status_code == HTTP_OK:
        data = response.json()
        assert "data" in data
        print("✅ /api/data works with valid scope")
    else:
        print("⚠️  /api/data returned 403 - token missing required scope")


def test_role_based_authorization():
    """Test role-based authorization."""
    print("\n🧪 Testing role-based authorization...")

    token = get_access_token()
    if not token:
        print("⚠️  Skipping tests - could not obtain access token")
        return

    headers = _create_auth_headers(token)

    # Test /api/admin/users endpoint (requires admin role)
    response = _make_request("GET", "/api/admin/users", headers=headers)
    # Will be 200 if token has admin role, 403 otherwise
    assert response.status_code in [HTTP_OK, HTTP_FORBIDDEN], (
        f"Unexpected status code: {response.status_code}"
    )

    if response.status_code == HTTP_OK:
        data = response.json()
        assert "message" in data
        print("✅ /api/admin/users works with admin role")
    else:
        print("⚠️  /api/admin/users returned 403 - token missing admin role")


def test_permission_based_authorization():
    """Test permission-based authorization."""
    print("\n🧪 Testing permission-based authorization...")

    token = get_access_token()
    if not token:
        print("⚠️  Skipping tests - could not obtain access token")
        return

    headers = _create_auth_headers(token)

    # Test /api/users POST endpoint (requires users.create permission)
    response = _make_request(
        "POST",
        "/api/users?name=Test&email=test@example.com",
        headers=headers,
    )
    # Will be 200 if token has permission, 403 otherwise
    assert response.status_code in [HTTP_OK, HTTP_FORBIDDEN], (
        f"Unexpected status code: {response.status_code}"
    )

    if response.status_code == HTTP_OK:
        data = response.json()
        assert "message" in data
        print("✅ /api/users POST works with users.create permission")
    else:
        print("⚠️  /api/users POST returned 403 - token missing users.create permission")


def main():
    """Run all integration tests."""
    print("🚀 Starting Descope FastAPI Integration Tests")
    print(f"📍 FastAPI URL: {FASTAPI_URL}")
    print(f"📍 Descope Project ID: {DESCOPE_PROJECT_ID}")
    print(f"📍 Issuer: {ISSUER}")

    # Wait for FastAPI service to be ready
    if not wait_for_service(f"{FASTAPI_URL}/health"):
        print("❌ FastAPI service is not available")
        return 1

    try:
        # Run all tests
        test_public_endpoints()
        test_protected_endpoints_without_token()
        test_protected_endpoints_with_invalid_token()
        test_protected_endpoints_with_valid_token()
        test_descope_specific_endpoints()
        test_scope_based_authorization()
        test_role_based_authorization()
        test_permission_based_authorization()

        print("\n✅ All tests passed!")
        return 0

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
