"""Tests for HTTP security hardening (Batch 3).

Covers:
- #350: SSRF via redirect following (disabled)
- #354: Endpoint authority validation derived from issuer
- #355: JWKS Content-Type validation
- #356: validate_https_url requires HTTPS
"""

import json
from typing import ClassVar
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.http_utils import check_no_redirect
from py_identity_model.core.response_processors import (
    parse_jwks_response,
    validate_and_parse_discovery_response,
)
from py_identity_model.core.validators import (
    validate_https_url,
    validate_https_url_with_policy,
)
from py_identity_model.discovery import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryException,
    NetworkException,
)
from py_identity_model.sync.http_client import (
    _reset_http_client,
    get_http_client,
    retry_with_backoff,
)

from ..constants import DISCO_URL


# ============================================================================
# #350 — Redirect following disabled
# ============================================================================


class TestRedirectBlocking:
    """Verify that HTTP redirects are blocked to prevent SSRF."""

    def test_check_no_redirect_allows_2xx(self):
        response = MagicMock()
        response.status_code = 200
        check_no_redirect(response)  # Should not raise

    def test_check_no_redirect_allows_4xx(self):
        response = MagicMock()
        response.status_code = 404
        check_no_redirect(response)  # Should not raise

    def test_check_no_redirect_allows_5xx(self):
        response = MagicMock()
        response.status_code = 500
        check_no_redirect(response)  # Should not raise

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
    def test_check_no_redirect_blocks_3xx(self, status_code):
        response = MagicMock()
        response.status_code = status_code
        response.url = "https://example.com/original"
        response.headers = {"location": "https://evil.com/steal"}
        with pytest.raises(NetworkException, match="redirect blocked"):
            check_no_redirect(response)

    def test_check_no_redirect_includes_location_in_error(self):
        response = MagicMock()
        response.status_code = 302
        response.url = DISCO_URL
        response.headers = {"location": "https://evil.com/phish"}
        with pytest.raises(NetworkException, match=r"https://evil\.com/phish"):
            check_no_redirect(response)

    def test_check_no_redirect_missing_location_header(self):
        response = MagicMock()
        response.status_code = 301
        response.url = "https://example.com/resource"
        response.headers = {}
        with pytest.raises(NetworkException, match="<not provided>"):
            check_no_redirect(response)

    def test_sync_client_follow_redirects_disabled(self):
        """Verify the sync HTTP client has follow_redirects=False."""
        _reset_http_client()
        try:
            client = get_http_client()
            assert not client.follow_redirects
        finally:
            _reset_http_client()

    def test_retry_decorator_blocks_redirect(self, monkeypatch):
        """Verify retry decorator raises NetworkException on redirect response."""
        monkeypatch.setenv("HTTP_RETRY_MAX_ATTEMPTS", "0")

        @retry_with_backoff()
        def redirecting_request():
            response = MagicMock()
            response.status_code = 302
            response.url = "https://example.com/disco"
            response.headers = {"location": "https://evil.com"}
            return response

        with pytest.raises(NetworkException, match="redirect blocked"):
            redirecting_request()

    @respx.mock
    def test_discovery_blocks_redirect(self):
        """End-to-end: discovery fetch rejects redirect responses."""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://evil.com/fake-disco"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)
        assert result.is_successful is False
        assert result.error is not None
        assert "redirect" in result.error.lower()


# ============================================================================
# #354 — Endpoint authority validation from issuer
# ============================================================================


class TestEndpointAuthorityFromIssuer:
    """Verify endpoint authority is validated against issuer even without
    explicit policy.authority."""

    def _make_response(self, issuer, endpoints=None):
        """Build a minimal valid discovery response."""
        data = {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
            "authorization_endpoint": f"{issuer}/auth",
            "token_endpoint": f"{issuer}/token",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        if endpoints:
            data.update(endpoints)
        return httpx.Response(
            200,
            json=data,
            headers={"Content-Type": "application/json"},
        )

    def test_validates_authority_without_explicit_policy_authority(self):
        """Endpoints with a different authority than the issuer should be rejected."""
        response = self._make_response(
            "https://example.com",
            {"jwks_uri": "https://evil.com/jwks"},
        )
        with pytest.raises(DiscoveryException, match=r"authority.*does not match"):
            validate_and_parse_discovery_response(response, policy=None)

    def test_allows_matching_authority_from_issuer(self):
        """Endpoints matching the issuer authority should pass."""
        response = self._make_response("https://example.com")
        result = validate_and_parse_discovery_response(response, policy=None)
        assert result["issuer"] == "https://example.com"

    def test_allows_additional_endpoint_base_addresses(self):
        """Endpoints on additional allowed domains should pass."""
        policy = DiscoveryPolicy(
            additional_endpoint_base_addresses=["https://cdn.example.com"],
        )
        response = self._make_response(
            "https://example.com",
            {"jwks_uri": "https://cdn.example.com/jwks"},
        )
        result = validate_and_parse_discovery_response(response, policy)
        assert result["issuer"] == "https://example.com"

    def test_explicit_policy_authority_overrides_issuer(self):
        """When policy.authority is set, it should be used instead of issuer."""
        policy = DiscoveryPolicy(authority="https://auth.example.com")
        response = self._make_response(
            "https://example.com",
            {
                "jwks_uri": "https://auth.example.com/jwks",
                "authorization_endpoint": "https://auth.example.com/auth",
                "token_endpoint": "https://auth.example.com/token",
            },
        )
        result = validate_and_parse_discovery_response(response, policy)
        assert result["issuer"] == "https://example.com"

    def test_rejects_endpoint_not_matching_issuer_no_policy(self):
        """Without any policy, endpoints must still match issuer authority."""
        response = self._make_response(
            "https://example.com",
            {"token_endpoint": "https://attacker.com/token"},
        )
        with pytest.raises(DiscoveryException, match=r"authority.*does not match"):
            validate_and_parse_discovery_response(response)

    def test_skips_authority_when_validation_disabled(self):
        """When validate_endpoints is False, authority check is skipped."""
        policy = DiscoveryPolicy(validate_endpoints=False)
        response = self._make_response(
            "https://example.com",
            {"jwks_uri": "https://different.com/jwks"},
        )
        result = validate_and_parse_discovery_response(response, policy)
        assert result["issuer"] == "https://example.com"


# ============================================================================
# #355 — JWKS Content-Type validation
# ============================================================================


class TestJwksContentTypeValidation:
    """Verify JWKS responses are validated for correct Content-Type."""

    _VALID_JWKS_JSON: ClassVar[dict] = {
        "keys": [{"kty": "RSA", "use": "sig", "kid": "k1", "n": "test_n", "e": "AQAB"}]
    }

    def test_accepts_application_json(self):
        response = httpx.Response(
            200,
            json=self._VALID_JWKS_JSON,
            headers={"Content-Type": "application/json"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is True

    def test_accepts_application_json_with_charset(self):
        response = httpx.Response(
            200,
            json=self._VALID_JWKS_JSON,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is True

    def test_accepts_application_jwk_set_json(self):
        response = httpx.Response(
            200,
            json=self._VALID_JWKS_JSON,
            headers={"Content-Type": "application/jwk-set+json"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is True

    def test_rejects_text_html(self):
        response = httpx.Response(
            200,
            content=b'{"keys": []}',
            headers={"Content-Type": "text/html"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "Content-Type" in result.error

    def test_rejects_text_plain(self):
        response = httpx.Response(
            200,
            content=b'{"keys": []}',
            headers={"Content-Type": "text/plain"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "text/plain" in result.error

    def test_rejects_missing_content_type(self):
        response = httpx.Response(
            200,
            content=json.dumps(self._VALID_JWKS_JSON).encode(),
            # No Content-Type header
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "missing Content-Type" in result.error

    def test_rejects_application_xml(self):
        response = httpx.Response(
            200,
            content=b"<keys/>",
            headers={"Content-Type": "application/xml"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "application/xml" in result.error

    def test_non_success_response_skips_content_type_check(self):
        """Non-2xx responses should report the HTTP error, not content-type."""
        response = httpx.Response(
            500,
            content=b"Server Error",
            headers={"Content-Type": "text/html"},
        )
        result = parse_jwks_response(response)
        assert result.is_successful is False
        assert result.error is not None
        assert "500" in result.error


# ============================================================================
# #356 — validate_https_url requires HTTPS
# ============================================================================


class TestHttpsEnforcement:
    """Verify validate_https_url strictly requires HTTPS."""

    def test_allows_https(self):
        validate_https_url("https://example.com/path", "test_param")

    def test_rejects_http(self):
        with pytest.raises(ConfigurationException, match="must use HTTPS"):
            validate_https_url("http://example.com", "test_param")

    def test_rejects_http_localhost(self):
        """HTTP on localhost requires DiscoveryPolicy, not bare validate_https_url."""
        with pytest.raises(ConfigurationException, match="must use HTTPS"):
            validate_https_url("http://localhost:8080", "test_param")

    def test_rejects_ftp(self):
        with pytest.raises(ConfigurationException, match="must use HTTPS"):
            validate_https_url("ftp://example.com", "test_param")

    def test_allows_empty(self):
        validate_https_url("", "test_param")  # optional params
        validate_https_url(None, "test_param")  # type: ignore

    def test_rejects_no_host(self):
        with pytest.raises(ConfigurationException, match="absolute URL"):
            validate_https_url("https://", "test_param")

    def test_policy_allows_http_on_loopback(self):
        """DiscoveryPolicy with allow_http_on_loopback=True permits HTTP localhost."""
        policy = DiscoveryPolicy(require_https=True, allow_http_on_loopback=True)
        validate_https_url_with_policy(
            "http://localhost:8080/path", "test_param", policy
        )

    def test_policy_require_https_false_allows_http(self):
        """DiscoveryPolicy with require_https=False permits any HTTP URL."""
        policy = DiscoveryPolicy(require_https=False)
        validate_https_url_with_policy("http://example.com", "test_param", policy)

    def test_no_policy_delegates_to_strict_validator(self):
        """When policy is None, HTTP URLs are rejected."""
        with pytest.raises(ConfigurationException, match="must use HTTPS"):
            validate_https_url_with_policy("http://example.com", "test_param", None)
