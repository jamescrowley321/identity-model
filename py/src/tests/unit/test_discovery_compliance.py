import httpx
import pytest
import respx

from py_identity_model.core.validators import (
    validate_https_url as _validate_https_url,
)
from py_identity_model.core.validators import (
    validate_issuer as _validate_issuer,
)
from py_identity_model.core.validators import (
    validate_parameter_values as _validate_parameter_values,
)
from py_identity_model.core.validators import (
    validate_required_parameters as _validate_required_parameters,
)
from py_identity_model.discovery import (
    DiscoveryDocumentRequest,
    get_discovery_document,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    DiscoveryException,
)

from .token_validation_helpers import DISCO_URL


class TestDiscoveryValidationFunctions:
    """Test the new validation functions for Discovery compliance"""

    def test_validate_issuer_valid_https(self):
        """Test that valid HTTPS issuers pass validation"""
        valid_issuers = [
            "https://example.com",
            "https://auth.example.com",
            "https://example.com/auth",
            "https://example.com:8443",
        ]
        for issuer in valid_issuers:
            _validate_issuer(issuer)  # Should not raise

    def test_validate_issuer_invalid_scheme(self):
        """Test that non-HTTPS issuers fail validation"""
        invalid_issuers = [
            "http://example.com",
            "ftp://example.com",
            "ws://example.com",
        ]
        for issuer in invalid_issuers:
            with pytest.raises(
                ConfigurationException,
                match="must use HTTPS scheme",
            ):
                _validate_issuer(issuer)

    def test_validate_issuer_with_query_fragment(self):
        """Test that issuers with query or fragment components fail validation"""
        with pytest.raises(
            ConfigurationException,
            match="must not contain query or fragment",
        ):
            _validate_issuer("https://example.com?query=param")

        with pytest.raises(
            ConfigurationException,
            match="must not contain query or fragment",
        ):
            _validate_issuer("https://example.com#fragment")

    def test_validate_issuer_empty_or_invalid(self):
        """Test that empty or invalid issuers fail validation"""
        with pytest.raises(ConfigurationException, match="required"):
            _validate_issuer("")

        with pytest.raises(
            ConfigurationException,
            match="valid URL with host",
        ):
            _validate_issuer("https://")

    def test_validate_https_url_valid_urls(self):
        """Test that valid HTTPS URLs pass validation"""
        valid_urls = [
            "https://example.com/path",
            "https://api.example.com:443/endpoint",
        ]
        for url in valid_urls:
            _validate_https_url(url, "test_param")  # Should not raise

    def test_validate_https_url_rejects_http(self):
        """Test that HTTP URLs are rejected (use DiscoveryPolicy for dev exceptions)"""
        with pytest.raises(ConfigurationException, match="must use HTTPS"):
            _validate_https_url("http://localhost:8080", "test_param")

    def test_validate_https_url_empty_allowed(self):
        """Test that empty URLs are allowed (optional parameters)"""
        _validate_https_url("", "test_param")  # Should not raise
        _validate_https_url(None, "test_param")  # type: ignore # Should not raise

    def test_validate_https_url_invalid_urls(self):
        """Test that non-HTTPS URLs fail validation"""
        invalid_urls = [
            "ftp://example.com",
            "http://example.com",
            "ws://example.com",
        ]
        for url in invalid_urls:
            with pytest.raises(
                ConfigurationException,
                match="must use HTTPS",
            ):
                _validate_https_url(url, "test_param")

    def test_validate_https_url_no_host(self):
        """Test that URLs without a host fail validation"""
        for url in ["not-a-url", "relative/path"]:
            with pytest.raises(
                ConfigurationException,
                match="must be an absolute URL with host",
            ):
                _validate_https_url(url, "test_param")

    def test_validate_required_parameters_all_present(self):
        """Test that validation passes when all required parameters are present"""
        valid_data = {
            "issuer": "https://example.com",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        _validate_required_parameters(valid_data)  # Should not raise

    def test_validate_required_parameters_missing(self):
        """Test that validation fails when required parameters are missing"""
        # Missing issuer
        with pytest.raises(
            DiscoveryException,
            match=r"Missing required parameters.*issuer",
        ):
            _validate_required_parameters(
                {
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )

        # Missing multiple parameters
        with pytest.raises(
            DiscoveryException,
            match="Missing required parameters",
        ):
            _validate_required_parameters({"issuer": "https://example.com"})

    def test_validate_parameter_values_valid_subject_types(self):
        """Test that valid subject types pass validation"""
        valid_data = {
            "subject_types_supported": ["public"],
        }
        _validate_parameter_values(valid_data)  # Should not raise

        valid_data = {
            "subject_types_supported": ["public", "pairwise"],
        }
        _validate_parameter_values(valid_data)  # Should not raise

    def test_validate_parameter_values_invalid_subject_types(self):
        """Test that invalid subject types fail validation"""
        with pytest.raises(
            DiscoveryException,
            match=r"Invalid subject type.*Must be 'public' or 'pairwise'",
        ):
            _validate_parameter_values(
                {
                    "subject_types_supported": ["invalid_type"],
                },
            )

    def test_validate_parameter_values_valid_response_types(self):
        """Test that valid response types pass validation"""
        valid_response_types = [
            ["code"],
            ["id_token"],
            ["code", "id_token"],
            ["code id_token token"],
        ]
        for response_types in valid_response_types:
            _validate_parameter_values(
                {
                    "response_types_supported": response_types,
                },
            )  # Should not raise

    def test_validate_parameter_values_invalid_response_types(self):
        """Test that invalid response types fail validation"""
        with pytest.raises(DiscoveryException, match="Invalid response type"):
            _validate_parameter_values(
                {
                    "response_types_supported": ["invalid_response_type"],
                },
            )


class TestDiscoveryComplianceIntegration:
    """Test the integrated compliance validation in get_discovery_document"""

    @respx.mock
    def test_discovery_validates_required_parameters(self):
        """Test that discovery document validation catches missing required parameters"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    # Missing required parameters
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Missing required parameters" in result.error

    @respx.mock
    def test_discovery_validates_issuer_format(self):
        """Test that discovery document validation catches invalid issuer format"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "http://example.com?query=param",  # Invalid issuer
                    "jwks_uri": "https://example.com/jwks",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid issuer" in result.error

    @respx.mock
    def test_discovery_validates_parameter_values(self):
        """Test that discovery document validation catches invalid parameter values"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "https://example.com/jwks",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["invalid_subject_type"],  # Invalid
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid parameter values" in result.error

    @respx.mock
    def test_discovery_validates_endpoint_urls(self):
        """Test that discovery document validation catches invalid endpoint URLs"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://example.com",
                    "jwks_uri": "not-a-valid-url",  # Invalid URL
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid endpoint URL" in result.error

    @respx.mock
    def test_discovery_handles_network_errors(self):
        """Test that discovery document handles network errors properly"""
        url = DISCO_URL
        respx.get(url).mock(side_effect=httpx.ConnectError("Network error"))

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Network error during discovery document request" in result.error

    @respx.mock
    def test_discovery_handles_invalid_json(self):
        """Test that discovery document handles invalid JSON responses"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                content=b"not valid json{",
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid JSON response" in result.error

    @respx.mock
    def test_discovery_validates_content_type(self):
        """Test that discovery document validates content type"""
        url = DISCO_URL
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is False
        assert result.error is not None
        assert "Invalid content type" in result.error

    @respx.mock
    def test_discovery_success_with_valid_data(self):
        """Test that discovery document succeeds with valid, compliant data"""
        url = DISCO_URL
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
                    "id_token_signing_alg_values_supported": [
                        "RS256",
                        "HS256",
                    ],
                },
                headers={"Content-Type": "application/json"},
            )
        )

        request = DiscoveryDocumentRequest(address=url)
        result = get_discovery_document(request)

        assert result.is_successful is True
        assert result.issuer == "https://example.com"
        assert result.jwks_uri == "https://example.com/jwks"
        assert result.response_types_supported == ["code", "id_token"]
        assert result.subject_types_supported == ["public"]
        assert result.id_token_signing_alg_values_supported == [
            "RS256",
            "HS256",
        ]
