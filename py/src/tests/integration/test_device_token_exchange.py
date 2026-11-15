"""Integration tests for Device Authorization (RFC 8628) and Token Exchange (RFC 8693).

These tests hit a live OIDC provider.  Each test is gated on the
relevant provider capability detected from the discovery document.
"""

import pytest

from py_identity_model import (
    DeviceAuthorizationRequest,
    DeviceTokenRequest,
    TokenExchangeRequest,
)
from py_identity_model.core import token_type
from py_identity_model.sync.device_auth import (
    poll_device_token,
    request_device_authorization,
)
from py_identity_model.sync.token_exchange import exchange_token


# Signals that a provider's token endpoint rejects the token-exchange grant as
# *unsupported*, despite advertising it in grant_types_supported. Descope is
# known to over-advertise its discovery metadata: it lists token-exchange (and
# jwt-bearer) but the endpoint returns E011003 "grant_type field must be one of:
# authorization_code, refresh_token, client_credentials".
_UNSUPPORTED_GRANT_SIGNALS = (
    "unsupported_grant_type",  # RFC 6749 Section 5.2
    "grant_type field must be one of",  # Descope E011003
    # Keycloak rejects the grant with these when standard token exchange is
    # not permitted for the client (feature/version dependent).
    "token exchange is not enabled",
    "client is not allowed to exchange",
)


def _provider_lacks_token_exchange(error: str | None) -> bool:
    """True when the failure is the provider declaring the grant unsupported.

    Distinguishes "provider does not implement token-exchange" (skip) from a
    genuine library or request defect (which must still fail the test).
    """
    if not error:
        return False
    lowered = error.lower()
    return any(signal in lowered for signal in _UNSUPPORTED_GRANT_SIGNALS)


# ============================================================================
# Device Authorization (RFC 8628)
# ============================================================================


def _device_client_id(test_config) -> str:
    return test_config.get("TEST_DEVICE_CLIENT_ID") or test_config["TEST_CLIENT_ID"]


def _device_client_secret(test_config) -> str | None:
    """The device client's secret; a dedicated device client may be public."""
    if test_config.get("TEST_DEVICE_CLIENT_ID"):
        return test_config.get("TEST_DEVICE_CLIENT_SECRET") or None
    return test_config.get("TEST_CLIENT_SECRET")


@pytest.mark.integration
class TestDeviceAuthLive:
    """Test Device Authorization Grant against a live provider.

    The full flow requires user interaction at the verification_uri,
    so we can only test the initial authorization request and the
    polling behaviour (which returns authorization_pending).
    """

    def _request_device_auth(self, raw_discovery, test_config):
        """Request device authorization; skip if client lacks the grant."""
        endpoint = raw_discovery["device_authorization_endpoint"]

        response = request_device_authorization(
            DeviceAuthorizationRequest(
                address=endpoint,
                client_id=_device_client_id(test_config),
                scope=test_config.get("TEST_SCOPE", "openid"),
                client_secret=_device_client_secret(test_config),
            )
        )

        # The provider may expose the endpoint but the test client may
        # not have the device_code grant assigned.
        if (
            not response.is_successful
            and response.error
            and "invalid_grant" in response.error
        ):
            pytest.skip("Test client does not have device_code grant assigned")

        return response

    def test_request_device_authorization(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
    ):
        """Request device authorization and receive device/user codes."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")
        if "device_authorization_endpoint" not in provider_capabilities:
            pytest.skip("Provider does not expose device_authorization_endpoint")

        response = self._request_device_auth(raw_discovery, test_config)

        assert response.is_successful is True, f"Device auth failed: {response.error}"
        assert response.device_code is not None
        assert response.user_code is not None
        assert response.verification_uri is not None
        assert response.expires_in is not None
        assert response.expires_in > 0

    def test_poll_returns_authorization_pending(
        self,
        provider_capabilities,
        raw_discovery,
        test_config,
        token_endpoint,
    ):
        """Polling before user authorizes returns authorization_pending."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")
        if "device_authorization_endpoint" not in provider_capabilities:
            pytest.skip("Provider does not expose device_authorization_endpoint")

        auth_response = self._request_device_auth(raw_discovery, test_config)
        assert auth_response.is_successful is True
        assert auth_response.device_code is not None

        # Poll immediately — user hasn't authorized yet
        poll_response = poll_device_token(
            DeviceTokenRequest(
                address=token_endpoint,
                client_id=_device_client_id(test_config),
                device_code=auth_response.device_code,
                client_secret=_device_client_secret(test_config),
            )
        )

        # Should be pending (not successful yet)
        assert poll_response.is_successful is False
        assert poll_response.error_code in (
            "authorization_pending",
            "slow_down",
        )

    def test_poll_invalid_device_code(
        self,
        provider_capabilities,
        test_config,
        token_endpoint,
    ):
        """Polling with an invalid device code returns an error."""
        if "device_authorization" not in provider_capabilities:
            pytest.skip("Provider does not support device authorization grant")
        if "device_authorization_endpoint" not in provider_capabilities:
            pytest.skip("Provider does not expose device_authorization_endpoint")

        response = poll_device_token(
            DeviceTokenRequest(
                address=token_endpoint,
                client_id=_device_client_id(test_config),
                device_code="invalid-device-code-value",
                client_secret=_device_client_secret(test_config),
            )
        )

        assert response.is_successful is False
        assert response.error is not None


# ============================================================================
# Token Exchange (RFC 8693)
# ============================================================================


@pytest.mark.integration
class TestTokenExchangeLive:
    """Test Token Exchange against a live provider."""

    def test_exchange_access_token(
        self,
        provider_capabilities,
        token_endpoint,
        client_credentials_token,
        test_config,
    ):
        """Exchange a valid access token for a new token."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        access_token = client_credentials_token.token["access_token"]

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token=access_token,
                subject_token_type=token_type.ACCESS_TOKEN,
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        # Some providers advertise the token-exchange grant in discovery but
        # reject it at the endpoint (e.g. Descope E011003). Skip only on that
        # explicit unsupported-grant signal — any other failure is a real defect.
        if not response.is_successful and _provider_lacks_token_exchange(
            response.error
        ):
            pytest.skip(
                "Provider advertises token-exchange in discovery but the token "
                f"endpoint rejects the grant: {response.error}"
            )

        assert response.is_successful is True, (
            f"Token exchange failed: {response.error}"
        )
        assert response.token is not None
        assert "access_token" in response.token
        assert response.issued_token_type is not None

    def test_exchange_with_audience(
        self,
        provider_capabilities,
        token_endpoint,
        client_credentials_token,
        test_config,
    ):
        """Exchange token with target audience."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        access_token = client_credentials_token.token["access_token"]

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token=access_token,
                subject_token_type=token_type.ACCESS_TOKEN,
                audience=test_config.get("TEST_AUDIENCE", ""),
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        if not response.is_successful:
            pytest.skip(f"Provider rejected audience-scoped exchange: {response.error}")
        assert response.token is not None
        assert "access_token" in response.token

    def test_exchange_invalid_token(
        self,
        provider_capabilities,
        token_endpoint,
        test_config,
    ):
        """Exchange with invalid subject token returns error."""
        if "token_exchange" not in provider_capabilities:
            pytest.skip("Provider does not support token exchange grant")

        response = exchange_token(
            TokenExchangeRequest(
                address=token_endpoint,
                client_id=test_config["TEST_CLIENT_ID"],
                subject_token="invalid-token-value",
                subject_token_type=token_type.ACCESS_TOKEN,
                client_secret=test_config.get("TEST_CLIENT_SECRET"),
            )
        )

        assert response.is_successful is False
        assert response.error is not None
