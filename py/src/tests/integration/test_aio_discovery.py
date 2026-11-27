"""Async integration tests for discovery document fetching."""

import pytest

from py_identity_model.aio.discovery import get_discovery_document
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.models import DiscoveryDocumentRequest


@pytest.mark.integration
class TestAsyncDiscovery:
    """Async counterparts of sync discovery integration tests."""

    async def test_get_discovery_document_success(self, test_config):
        """Fetch discovery document via async API and validate key fields."""
        require_https = test_config.get("TEST_REQUIRE_HTTPS", True)
        policy = DiscoveryPolicy(require_https=require_https)
        request = DiscoveryDocumentRequest(
            issuer=test_config["TEST_ISSUER"],
            policy=policy,
        )
        response = await get_discovery_document(request)

        assert response.is_successful is True
        assert response.issuer is not None
        assert response.jwks_uri is not None
        assert response.token_endpoint is not None
        assert response.authorization_endpoint is not None

    async def test_get_discovery_document_failure(self):
        """Non-OIDC URL returns unsuccessful response."""
        request = DiscoveryDocumentRequest(issuer="https://google.com")
        response = await get_discovery_document(request)

        assert response.is_successful is False
        assert response.error is not None

    async def test_get_discovery_document_network_error(self):
        """Malformed issuer returns unsuccessful response with error detail."""
        request = DiscoveryDocumentRequest(issuer="not-a-valid-url")
        response = await get_discovery_document(request)

        assert response.is_successful is False
        assert response.error is not None

    async def test_async_sync_parity(self, discovery_document, test_config):
        """Async result matches the session-scoped sync discovery document."""
        require_https = test_config.get("TEST_REQUIRE_HTTPS", True)
        policy = DiscoveryPolicy(require_https=require_https)
        request = DiscoveryDocumentRequest(
            issuer=test_config["TEST_ISSUER"],
            policy=policy,
        )
        async_response = await get_discovery_document(request)

        assert async_response.is_successful is True
        assert async_response.issuer == discovery_document.issuer
        assert async_response.token_endpoint == discovery_document.token_endpoint
        assert async_response.jwks_uri == discovery_document.jwks_uri
