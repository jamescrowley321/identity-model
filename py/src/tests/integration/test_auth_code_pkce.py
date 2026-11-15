"""Integration tests for authorization code grant with PKCE."""

import secrets

import pytest

from py_identity_model import (
    BaseRequest,
    build_authorization_url,
    generate_pkce_pair,
    parse_authorize_callback_response,
    request_authorization_code_token,
    validate_authorize_callback_state,
)
from py_identity_model.core.models import (
    AuthorizationCodeTokenRequest,
)


@pytest.mark.integration
class TestAuthCodePKCEIntegration:
    def test_build_authorize_url_from_discovery(self, discovery_document):
        """Build authorize URL using real discovery document metadata."""
        _verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        url = build_authorization_url(
            authorization_endpoint=discovery_document.authorization_endpoint,
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            scope="openid profile",
            state=state,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        assert discovery_document.authorization_endpoint in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url
        assert f"state={state}" in url

    def test_full_flow_simulation(self, discovery_document, require_https):
        """Simulate the complete auth code + PKCE flow (except actual auth)."""
        # Step 1: Generate PKCE pair
        verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(32)

        # Step 2: Build authorize URL
        url = build_authorization_url(
            authorization_endpoint=discovery_document.authorization_endpoint,
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            state=state,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        if require_https:
            assert url.startswith("https://")

        # Step 3: Simulate callback (would come from browser redirect)
        callback = f"https://app.example.com/callback?code=simulated_code&state={state}"
        response = parse_authorize_callback_response(callback)
        assert response.is_successful is True
        assert response.code == "simulated_code"

        # Step 4: Validate state
        result = validate_authorize_callback_state(response, state)
        assert result.is_valid is True

        # Step 5: Build token exchange request
        token_request = AuthorizationCodeTokenRequest(
            address=discovery_document.token_endpoint or "",
            client_id="test-client",
            code=response.code,
            redirect_uri="https://app.example.com/callback",
            code_verifier=verifier,
        )
        assert isinstance(token_request, BaseRequest)
        assert token_request.code_verifier == verifier


@pytest.mark.integration
class TestLiveAuthCodePKCE:
    """Test live auth code + PKCE flows.

    These tests require a provider with devInteractions
    (automated login/consent). They skip gracefully when
    the provider does not support this.
    """

    def test_auth_code_pkce_confidential_client(self, auth_code_result):
        """Full auth code + PKCE flow with confidential client."""
        token_response = auth_code_result["token_response"]
        assert token_response.is_successful is True, (
            f"Token exchange failed: {token_response.error}"
        )

        token = token_response.token
        assert "access_token" in token
        assert "refresh_token" in token
        assert token["token_type"] == "Bearer"

    def test_auth_code_pkce_public_client(self, public_auth_code_result):
        """Full auth code + PKCE flow with public client."""
        token_response = public_auth_code_result["token_response"]
        assert token_response.is_successful is True, (
            f"Token exchange failed: {token_response.error}"
        )

        token = token_response.token
        assert "access_token" in token
        assert token["token_type"] == "Bearer"

    def test_auth_code_invalid_code_rejected(
        self,
        discovery_document,
        test_config,
        provider_capabilities,
        invalid_grant_error,
    ):
        """Invalid authorization code is rejected with invalid_grant."""
        if "dev_interactions" not in provider_capabilities:
            pytest.skip("Provider does not support devInteractions")
        if "authorization_code" not in provider_capabilities:
            pytest.skip("Provider does not advertise authorization_endpoint")

        client_id = test_config.get("TEST_AUTH_CODE_CLIENT_ID", "")
        redirect_uri = test_config.get("TEST_AUTH_CODE_REDIRECT_URI", "")
        client_secret = test_config.get("TEST_AUTH_CODE_CLIENT_SECRET", "")
        if not client_id or not redirect_uri:
            pytest.skip("Auth code client config not available")

        wrong_verifier = "wrong-verifier-" + secrets.token_urlsafe(32)
        token_response = request_authorization_code_token(
            AuthorizationCodeTokenRequest(
                address=discovery_document.token_endpoint,
                client_id=client_id,
                code="invalid-authorization-code",
                redirect_uri=redirect_uri,
                code_verifier=wrong_verifier,
                client_secret=client_secret,
            )
        )
        assert token_response.is_successful is False
        assert token_response.error is not None
        assert invalid_grant_error in token_response.error
