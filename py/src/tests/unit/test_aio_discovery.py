"""Async tests for aio.discovery module."""

import httpx
import pytest
import respx

from py_identity_model import DiscoveryPolicy
from py_identity_model.aio.discovery import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)


@pytest.mark.asyncio
class TestAsyncDiscoveryDocument:
    @respx.mock
    async def test_async_get_discovery_document_success(self):
        """Test successful async discovery document fetch"""
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "response_types_supported": ["code", "id_token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = await get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "https://example.com"
        assert result.jwks_uri == "https://example.com/jwks"
        assert result.authorization_endpoint == "https://example.com/auth"
        assert result.token_endpoint == "https://example.com/token"

    @respx.mock
    async def test_async_get_discovery_document_http_error(self):
        """Test async discovery document fetch with HTTP error"""
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(return_value=httpx.Response(404, content=b"Not Found"))

        request = DiscoveryDocumentRequest(address=url)
        result = await get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "404" in result.error

    @respx.mock
    async def test_async_get_discovery_document_network_error(self):
        """Test async discovery document with network error"""
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = DiscoveryDocumentRequest(address=url)
        result = await get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error" in result.error

    @respx.mock
    async def test_async_get_discovery_document_invalid_json(self):
        """Test async discovery document with invalid JSON"""
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                content=b"invalid json{",
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = await get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid JSON" in result.error


@pytest.mark.asyncio
@pytest.mark.unit
class TestAsyncDiscoveryPreFlightSchemeValidation:
    """Verify pre-flight URL scheme check prevents HTTP requests (M4)."""

    async def test_http_url_rejected_before_request(self):
        """HTTP to non-loopback host fails without making any HTTP request."""
        request = DiscoveryDocumentRequest(
            address="http://auth.example.com/.well-known/openid-configuration",
        )
        result = await get_discovery_document(request)
        assert result.is_successful is False
        assert result.error is not None
        assert "HTTPS" in result.error

    @respx.mock
    async def test_http_loopback_allowed_by_default(self):
        """HTTP to loopback is allowed by default policy (no pre-flight block)."""
        url = "http://127.0.0.1:9999/.well-known/openid-configuration"
        route = respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "http://127.0.0.1:9999",
                    "jwks_uri": "http://127.0.0.1:9999/jwks",
                    "authorization_endpoint": "http://127.0.0.1:9999/auth",
                    "token_endpoint": "http://127.0.0.1:9999/token",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )
        request = DiscoveryDocumentRequest(address=url)
        result = await get_discovery_document(request)
        # Pre-flight passes for loopback — mock was actually called
        assert route.called
        # Loopback HTTP issuer is allowed by default policy
        assert result.is_successful
        assert result.issuer == "http://127.0.0.1:9999"

    @respx.mock
    async def test_relaxed_policy_allows_http(self):
        """Relaxed policy allows HTTP URLs and validates full response."""
        url = "http://auth.example.com:9999/.well-known/openid-configuration"
        route = respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "http://auth.example.com:9999",
                    "jwks_uri": "http://auth.example.com:9999/jwks",
                    "authorization_endpoint": "http://auth.example.com:9999/auth",
                    "token_endpoint": "http://auth.example.com:9999/token",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )
        policy = DiscoveryPolicy(require_https=False, validate_issuer=False)
        request = DiscoveryDocumentRequest(address=url, policy=policy)
        result = await get_discovery_document(request)
        # Pre-flight and post-flight both pass with relaxed policy
        assert route.called
        assert result.is_successful is True
