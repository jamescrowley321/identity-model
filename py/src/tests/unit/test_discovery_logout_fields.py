"""Unit tests for Back-Channel Logout discovery metadata fields.

Verifies that ``backchannel_logout_supported`` and
``backchannel_logout_session_supported`` (OpenID Connect Back-Channel Logout
1.0 §3) are parsed onto ``DiscoveryDocumentResponse``.
"""

import httpx
import respx

from py_identity_model.discovery import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)


_BASE_DISCO = {
    "issuer": "https://example.com",
    "jwks_uri": "https://example.com/jwks",
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


class TestBackchannelLogoutDiscoveryFields:
    @respx.mock
    def test_backchannel_logout_flags_populated(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "backchannel_logout_supported": True,
                    "backchannel_logout_session_supported": True,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.backchannel_logout_supported is True
        assert result.backchannel_logout_session_supported is True

    @respx.mock
    def test_backchannel_logout_flags_absent_default_none(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(return_value=httpx.Response(200, json=_BASE_DISCO))

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.backchannel_logout_supported is None
        assert result.backchannel_logout_session_supported is None

    @respx.mock
    def test_backchannel_logout_session_supported_false_preserved(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "backchannel_logout_supported": True,
                    "backchannel_logout_session_supported": False,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.backchannel_logout_supported is True
        assert result.backchannel_logout_session_supported is False


class TestEndSessionEndpointDiscoveryField:
    """OpenID Connect RP-Initiated Logout 1.0 §2 — ``end_session_endpoint``."""

    @respx.mock
    def test_end_session_endpoint_populated(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "end_session_endpoint": "https://example.com/logout",
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.end_session_endpoint == "https://example.com/logout"

    @respx.mock
    def test_end_session_endpoint_absent_default_none(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(return_value=httpx.Response(200, json=_BASE_DISCO))

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.end_session_endpoint is None
