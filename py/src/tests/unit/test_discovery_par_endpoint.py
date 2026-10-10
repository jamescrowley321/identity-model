"""Unit tests for the RFC 9126 Pushed Authorization Request discovery fields.

Verifies that ``pushed_authorization_request_endpoint`` and
``require_pushed_authorization_requests`` (RFC 9126 Section 5) are parsed onto
``DiscoveryDocumentResponse`` so a FAPI 2.0 RP can discover the PAR endpoint and
honour a PAR-required authorization server entirely through the public API.
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

_DISCO_URL = "https://example.com/.well-known/openid-configuration"


class TestParEndpointDiscoveryField:
    @respx.mock
    def test_par_endpoint_parsed(self):
        respx.get(_DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "pushed_authorization_request_endpoint": (
                        "https://example.com/par"
                    ),
                    "require_pushed_authorization_requests": True,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=_DISCO_URL))

        assert result.is_successful is True
        assert result.pushed_authorization_request_endpoint == "https://example.com/par"
        assert result.require_pushed_authorization_requests is True

    @respx.mock
    def test_par_endpoint_absent_defaults_none(self):
        respx.get(_DISCO_URL).mock(return_value=httpx.Response(200, json=_BASE_DISCO))

        result = get_discovery_document(DiscoveryDocumentRequest(address=_DISCO_URL))

        assert result.is_successful is True
        assert result.pushed_authorization_request_endpoint is None
        assert result.require_pushed_authorization_requests is None

    @respx.mock
    def test_require_par_false(self):
        respx.get(_DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    **_BASE_DISCO,
                    "pushed_authorization_request_endpoint": (
                        "https://example.com/par"
                    ),
                    "require_pushed_authorization_requests": False,
                },
            )
        )

        result = get_discovery_document(DiscoveryDocumentRequest(address=_DISCO_URL))

        assert result.is_successful is True
        assert result.pushed_authorization_request_endpoint == "https://example.com/par"
        assert result.require_pushed_authorization_requests is False
