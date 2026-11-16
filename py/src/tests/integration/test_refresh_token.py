"""Integration tests for OAuth 2.0 Refresh Token Grant."""

import pytest

from py_identity_model import RefreshTokenRequest
from py_identity_model.sync.token_client import refresh_token

from .conftest import AuthCodeFlowConfig, perform_auth_code_flow


@pytest.mark.integration
class TestRefreshTokenIntegration:
    def test_request_with_real_token_endpoint(self, discovery_document):
        req = RefreshTokenRequest(
            address=discovery_document.token_endpoint or "",
            client_id="test_client",
            refresh_token="test_refresh_token",
            client_secret="test_secret",
        )
        assert req.address != ""

    def test_invalid_refresh_token_returns_error(self, discovery_document, test_config):
        """Sending an invalid refresh token to the real endpoint returns an error."""
        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint or "",
                client_id=test_config["TEST_CLIENT_ID"],
                refresh_token="invalid_refresh_token",
                client_secret=test_config.get("TEST_CLIENT_SECRET", ""),
            )
        )
        assert response.is_successful is False
        assert response.error is not None


@pytest.mark.integration
class TestLiveRefreshToken:
    """Test refresh token grant with live auth code flow.

    Each test performs its own auth code flow to get a fresh
    refresh token, avoiding order-dependent failures from
    refresh token rotation (consuming a token invalidates it).
    """

    def _get_fresh_tokens(self, discovery_document, test_config) -> dict:
        """Perform a fresh auth code flow and return tokens."""
        result = perform_auth_code_flow(
            discovery=discovery_document,
            client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
            redirect_uri=test_config["TEST_AUTH_CODE_REDIRECT_URI"],
            config=AuthCodeFlowConfig(
                client_secret=test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
                scope="openid profile email offline_access",
            ),
        )
        token_response = result["token_response"]
        assert token_response.is_successful is True, (
            f"Auth code flow failed: {token_response.error}"
        )
        token = token_response.token
        assert "refresh_token" in token, (
            "No refresh_token — offline_access not granted?"
        )
        return token

    def test_refresh_token_success(
        self,
        discovery_document,
        test_config,
        provider_capabilities,
    ):
        """Get tokens via auth code, then refresh."""
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support devInteractions")
        if "refresh_token" not in provider_capabilities:
            pytest.skip("Provider does not support refresh_token grant")

        token = self._get_fresh_tokens(discovery_document, test_config)
        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint,
                client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
                refresh_token=token["refresh_token"],
                client_secret=test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
            )
        )
        assert response.is_successful is True, f"Refresh failed: {response.error}"
        assert response.token is not None
        assert "access_token" in response.token

    def test_refresh_token_returns_new_access_token(
        self,
        discovery_document,
        test_config,
        provider_capabilities,
    ):
        """New access_token differs from original."""
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support devInteractions")
        if "refresh_token" not in provider_capabilities:
            pytest.skip("Provider does not support refresh_token grant")

        original_token = self._get_fresh_tokens(discovery_document, test_config)
        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint,
                client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
                refresh_token=original_token["refresh_token"],
                client_secret=test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
            )
        )
        assert response.is_successful is True
        assert response.token is not None
        assert response.token["access_token"] != original_token["access_token"]

    def test_refresh_token_invalid_grant(
        self,
        discovery_document,
        test_config,
        provider_capabilities,
        invalid_grant_error,
    ):
        """Invalid refresh token returns invalid_grant error."""
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support devInteractions")
        if "refresh_token" not in provider_capabilities:
            pytest.skip("Provider does not support refresh_token grant")

        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint,
                client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
                refresh_token="invalid-refresh-token-value",
                client_secret=test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
            )
        )
        assert response.is_successful is False
        assert response.error is not None
        assert invalid_grant_error in response.error

    def test_refresh_token_scope_downscope(
        self,
        discovery_document,
        test_config,
        provider_capabilities,
    ):
        """Refresh with reduced scope."""
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support devInteractions")
        if "refresh_token" not in provider_capabilities:
            pytest.skip("Provider does not support refresh_token grant")

        original_token = self._get_fresh_tokens(discovery_document, test_config)
        response = refresh_token(
            RefreshTokenRequest(
                address=discovery_document.token_endpoint,
                client_id=test_config["TEST_AUTH_CODE_CLIENT_ID"],
                refresh_token=original_token["refresh_token"],
                client_secret=test_config.get("TEST_AUTH_CODE_CLIENT_SECRET"),
                scope="openid",
            )
        )
        assert response.is_successful is True, (
            f"Downscoped refresh failed: {response.error}"
        )
        assert response.token is not None
        assert "access_token" in response.token
