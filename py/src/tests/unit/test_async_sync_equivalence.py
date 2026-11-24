"""
Async/Sync API equivalence tests.

These tests verify that the async and sync implementations produce identical
results for the same inputs, ensuring consistent behavior across both APIs.
"""

from httpx import Response
import pytest
import respx

from py_identity_model import (
    DiscoveryDocumentRequest,
    JwksRequest,
)
from py_identity_model import (
    get_discovery_document as sync_get_discovery,
)
from py_identity_model import (
    get_jwks as sync_get_jwks,
)
from py_identity_model.aio import (
    get_discovery_document as async_get_discovery,
)
from py_identity_model.aio import (
    get_jwks as async_get_jwks,
)


class TestDiscoveryEquivalence:
    """Test that async and sync discovery APIs produce identical results."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_discovery_success_equivalence(self):
        """Test that successful discovery returns identical results."""
        # Mock discovery response
        discovery_data = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

        respx.get("https://auth.example.com/.well-known/openid-configuration").mock(
            return_value=Response(200, json=discovery_data)
        )

        request = DiscoveryDocumentRequest(issuer="https://auth.example.com")

        # Get results from both APIs
        sync_result = sync_get_discovery(request)
        async_result = await async_get_discovery(request)

        # Both should be successful
        assert sync_result.is_successful
        assert async_result.is_successful

        # Results should be identical
        assert sync_result.issuer == async_result.issuer
        assert sync_result.jwks_uri == async_result.jwks_uri
        assert sync_result.authorization_endpoint == async_result.authorization_endpoint
        assert sync_result.token_endpoint == async_result.token_endpoint

    @respx.mock
    @pytest.mark.asyncio
    async def test_discovery_http_error_equivalence(self):
        """Test that HTTP errors are handled identically."""
        # Mock 404 response
        respx.get("https://auth.example.com/.well-known/openid-configuration").mock(
            return_value=Response(404, text="Not Found")
        )

        request = DiscoveryDocumentRequest(issuer="https://auth.example.com")

        # Get results from both APIs
        sync_result = sync_get_discovery(request)
        async_result = await async_get_discovery(request)

        # Both should fail
        assert not sync_result.is_successful
        assert not async_result.is_successful

        # Both should have error messages
        assert sync_result.error is not None
        assert async_result.error is not None

        # Error messages should mention the same status code
        assert "404" in sync_result.error
        assert "404" in async_result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_discovery_invalid_json_equivalence(self):
        """Test that invalid JSON is handled identically."""
        # Mock invalid JSON response
        respx.get("https://auth.example.com/.well-known/openid-configuration").mock(
            return_value=Response(
                200,
                headers={"content-type": "application/json"},
                text="invalid json {",
            )
        )

        request = DiscoveryDocumentRequest(issuer="https://auth.example.com")

        # Get results from both APIs
        sync_result = sync_get_discovery(request)
        async_result = await async_get_discovery(request)

        # Both should fail
        assert not sync_result.is_successful
        assert not async_result.is_successful

        # Both should have error messages about JSON
        assert sync_result.error is not None
        assert async_result.error is not None
        assert (
            "json" in sync_result.error.lower() or "parse" in sync_result.error.lower()
        )
        assert (
            "json" in async_result.error.lower()
            or "parse" in async_result.error.lower()
        )


class TestJWKSEquivalence:
    """Test that async and sync JWKS APIs produce identical results."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_jwks_success_equivalence(self):
        """Test that successful JWKS fetch returns identical results."""
        # Mock JWKS response
        jwks_data = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-1",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
                    "e": "AQAB",
                }
            ]
        }

        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_data)
        )

        request = JwksRequest(address="https://auth.example.com/.well-known/jwks.json")

        # Get results from both APIs
        sync_result = sync_get_jwks(request)
        async_result = await async_get_jwks(request)

        # Both should be successful
        assert sync_result.is_successful
        assert async_result.is_successful

        # Both should have keys
        assert sync_result.keys is not None
        assert async_result.keys is not None
        assert len(sync_result.keys) == len(async_result.keys) == 1

        # Keys should have identical properties
        assert sync_result.keys[0].kid == async_result.keys[0].kid == "test-key-1"
        assert sync_result.keys[0].kty == async_result.keys[0].kty == "RSA"
        assert sync_result.keys[0].alg == async_result.keys[0].alg == "RS256"

    @respx.mock
    @pytest.mark.asyncio
    async def test_jwks_http_error_equivalence(self):
        """Test that JWKS HTTP errors are handled identically."""
        # Mock 500 response
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=Response(500, text="Internal Server Error")
        )

        request = JwksRequest(address="https://auth.example.com/.well-known/jwks.json")

        # Get results from both APIs
        sync_result = sync_get_jwks(request)
        async_result = await async_get_jwks(request)

        # Both should fail
        assert not sync_result.is_successful
        assert not async_result.is_successful

        # Both should have error messages
        assert sync_result.error is not None
        assert async_result.error is not None

        # Error messages should mention the same status code
        assert "500" in sync_result.error
        assert "500" in async_result.error


class TestResponseStructureEquivalence:
    """Test that response structures are identical between async and sync."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_discovery_response_structure(self):
        """Test that discovery response structure is identical."""
        discovery_data = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

        respx.get("https://auth.example.com/.well-known/openid-configuration").mock(
            return_value=Response(200, json=discovery_data)
        )

        request = DiscoveryDocumentRequest(issuer="https://auth.example.com")

        sync_result = sync_get_discovery(request)
        async_result = await async_get_discovery(request)

        # Check that both have the same attributes
        assert dir(sync_result) == dir(async_result)

        # Check that all attributes have the same type
        # Skip 'error' — guarded on successful responses
        for attr in dir(sync_result):
            if not attr.startswith("_") and attr != "error":
                sync_val = getattr(sync_result, attr)
                async_val = getattr(async_result, attr)
                assert type(sync_val) is type(async_val), (
                    f"Attribute {attr} has different types"
                )

    @respx.mock
    @pytest.mark.asyncio
    async def test_jwks_response_structure(self):
        """Test that JWKS response structure is identical."""
        jwks_data = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
                    "e": "AQAB",
                }
            ]
        }

        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=Response(200, json=jwks_data)
        )

        request = JwksRequest(address="https://auth.example.com/.well-known/jwks.json")

        sync_result = sync_get_jwks(request)
        async_result = await async_get_jwks(request)

        # Check that both have the same attributes
        assert dir(sync_result) == dir(async_result)

        # Check keys structure
        assert type(sync_result.keys) is type(async_result.keys)
        if sync_result.keys and async_result.keys:
            assert dir(sync_result.keys[0]) == dir(async_result.keys[0])
