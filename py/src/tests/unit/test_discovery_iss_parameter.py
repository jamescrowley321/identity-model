"""Unit tests for the RFC 9207 authorization-response issuer discovery field.

Verifies that ``authorization_response_iss_parameter_supported`` (RFC 9207
Section 3) is parsed onto ``DiscoveryDocumentResponse`` so callers can drive
issuer-validation enforcement from the AS metadata.
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


class TestIssParameterDiscoveryField:
    @respx.mock
    def test_iss_parameter_supported_true(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "authorization_response_iss_parameter_supported": True,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.authorization_response_iss_parameter_supported is True

    @respx.mock
    def test_iss_parameter_supported_absent_defaults_none(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(return_value=httpx.Response(200, json=_BASE_DISCO))

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.authorization_response_iss_parameter_supported is None

    @respx.mock
    def test_iss_parameter_supported_false(self):
        url = "https://example.com/.well-known/openid-configuration"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "authorization_response_iss_parameter_supported": False,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=url))

        assert result.is_successful is True
        assert result.authorization_response_iss_parameter_supported is False
