"""Unit tests for FAPI 2.0 Security Profile compliance validation."""

import pytest

from py_identity_model.core.fapi import (
    FAPIValidationResult,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)
from py_identity_model.core.models import DiscoveryDocumentResponse


@pytest.mark.unit
class TestFAPIValidationResult:
    def test_empty_violations_is_compliant(self):
        result = FAPIValidationResult(violations=[])
        assert result.is_compliant is True

    def test_violations_is_not_compliant(self):
        result = FAPIValidationResult(violations=["problem"])
        assert result.is_compliant is False

    def test_default_is_compliant(self):
        result = FAPIValidationResult()
        assert result.is_compliant is True
        assert result.violations == []


@pytest.mark.unit
class TestValidateFAPIAuthorizationRequest:
    def test_compliant_request(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge_value",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/callback",
            use_par=True,
            algorithm="ES256",
        )
        assert result.is_compliant is True
        assert result.violations == []

    def test_wrong_response_type(self):
        result = validate_fapi_authorization_request(
            response_type="token",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("response_type" in v for v in result.violations)

    def test_missing_code_challenge(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge=None,
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("code_challenge" in v for v in result.violations)

    def test_wrong_pkce_method(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="plain",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("S256" in v for v in result.violations)

    def test_par_not_used(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=False,
        )
        assert result.is_compliant is False
        assert any("PAR" in v for v in result.violations)

    def test_http_redirect_uri(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="http://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("HTTPS" in v for v in result.violations)

    def test_disallowed_algorithm(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
            algorithm="RS256",
        )
        assert result.is_compliant is False
        assert any("RS256" in v for v in result.violations)

    def test_empty_code_challenge_rejected(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("code_challenge" in v for v in result.violations)

    def test_whitespace_code_challenge_rejected(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="   ",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("code_challenge" in v for v in result.violations)

    def test_none_code_challenge_method_message(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method=None,
            redirect_uri="https://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("code_challenge_method is required" in v for v in result.violations)
        # Must NOT contain Python repr 'None'
        assert not any("'None'" in v for v in result.violations)

    def test_redirect_uri_case_insensitive_https(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="HTTPS://app.example.com/cb",
            use_par=True,
        )
        assert result.is_compliant is True

    def test_redirect_uri_no_host_rejected(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://",
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("host" in v for v in result.violations)

    def test_redirect_uri_whitespace_stripped(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri=" https://app.example.com/cb ",
            use_par=True,
        )
        assert result.is_compliant is True

    def test_non_string_redirect_uri(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri=None,  # type: ignore[arg-type]
            use_par=True,
        )
        assert result.is_compliant is False
        assert any("must be a string" in v for v in result.violations)

    def test_algorithm_none_is_ok(self):
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
            algorithm=None,
        )
        assert result.is_compliant is True

    def test_algorithm_violation_message_readable(self):
        """Algorithm violation message should use comma-separated list, not Python repr."""
        result = validate_fapi_authorization_request(
            response_type="code",
            code_challenge="challenge",
            code_challenge_method="S256",
            redirect_uri="https://app.example.com/cb",
            use_par=True,
            algorithm="RS256",
        )
        alg_violation = next(v for v in result.violations if "RS256" in v)
        assert "[" not in alg_violation
        assert "]" not in alg_violation

    def test_multiple_violations(self):
        result = validate_fapi_authorization_request(
            response_type="token",
            code_challenge=None,
            code_challenge_method="plain",
            redirect_uri="http://app.example.com/cb",
            use_par=False,
            algorithm="RS256",
        )
        assert result.is_compliant is False
        assert any("response_type" in v for v in result.violations)
        assert any("code_challenge" in v for v in result.violations)
        assert any("S256" in v for v in result.violations)
        assert any("PAR" in v for v in result.violations)
        assert any("HTTPS" in v for v in result.violations)
        assert any("RS256" in v for v in result.violations)


@pytest.mark.unit
class TestValidateFAPIClientConfig:
    def test_compliant_dpop(self):
        result = validate_fapi_client_config(
            auth_method="private_key_jwt",
            use_dpop=True,
        )
        assert result.is_compliant is True

    def test_compliant_mtls(self):
        result = validate_fapi_client_config(
            auth_method="tls_client_auth",
            use_mtls=True,
        )
        assert result.is_compliant is True

    def test_compliant_self_signed_tls(self):
        result = validate_fapi_client_config(
            auth_method="self_signed_tls_client_auth",
            use_mtls=True,
        )
        assert result.is_compliant is True

    def test_no_client_auth(self):
        result = validate_fapi_client_config(
            auth_method=None,
            use_dpop=True,
        )
        assert result.is_compliant is False
        assert any("Client authentication" in v for v in result.violations)

    def test_prohibited_auth_method_client_secret_basic(self):
        result = validate_fapi_client_config(
            auth_method="client_secret_basic",
            use_dpop=True,
        )
        assert result.is_compliant is False
        assert any("not FAPI 2.0 compliant" in v for v in result.violations)
        assert any("client_secret_basic" in v for v in result.violations)

    def test_prohibited_auth_method_client_secret_post(self):
        result = validate_fapi_client_config(
            auth_method="client_secret_post",
            use_dpop=True,
        )
        assert result.is_compliant is False
        assert any("not FAPI 2.0 compliant" in v for v in result.violations)

    def test_no_sender_constraint(self):
        result = validate_fapi_client_config(
            auth_method="private_key_jwt",
            use_dpop=False,
            use_mtls=False,
        )
        assert result.is_compliant is False
        assert any("Sender-constrained" in v for v in result.violations)

    def test_both_dpop_and_mtls(self):
        result = validate_fapi_client_config(
            auth_method="private_key_jwt",
            use_dpop=True,
            use_mtls=True,
        )
        assert result.is_compliant is True


@pytest.mark.unit
class TestValidateFAPIDiscovery:
    def test_compliant_discovery(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256", "PS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_missing_auth_code_grant(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["client_credentials"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("authorization_code" in v for v in result.violations)

    def test_weak_auth_methods(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["client_secret_basic"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("client auth" in v for v in result.violations)

    def test_weak_algorithms(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("signing algorithms" in v for v in result.violations)

    def test_failed_discovery_returns_non_compliant(self):
        disco = DiscoveryDocumentResponse(
            is_successful=False,
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("fetch failed" in v for v in result.violations)

    def test_none_auth_methods_non_compliant(self):
        """RFC 8414 §2 default is client_secret_basic — FAPI-prohibited."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=None,
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("client_secret_basic" in v for v in result.violations)

    def test_none_signing_algs_non_compliant(self):
        """Absent signing algs is a violation (REQUIRED by Discovery §3, no default)."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=None,
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("RS256" in v for v in result.violations)

    def test_none_fields_non_compliant(self):
        """Discovery with all None metadata is non-compliant."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("client_secret_basic" in v for v in result.violations)
        assert any("RS256" in v for v in result.violations)

    def test_response_types_missing_code(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            response_types_supported=["token"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("response type" in v for v in result.violations)

    def test_response_types_none_is_compliant(self):
        """An absent response_types_supported is not reported (Discovery §3: REQUIRED, no default)."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            response_types_supported=None,
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_pkce_methods_without_s256(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
            code_challenge_methods_supported=["plain"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is False
        assert any("S256" in v for v in result.violations)

    def test_pkce_methods_with_s256(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
            code_challenge_methods_supported=["S256", "plain"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_pkce_methods_none_passes(self):
        """When code_challenge_methods_supported is absent, no violation."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["ES256"],
            code_challenge_methods_supported=None,
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_signing_alg_violation_message_readable(self):
        """Signing algorithm violation message should use comma-separated list."""
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://auth.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["private_key_jwt"],
            id_token_signing_alg_values_supported=["RS256"],
        )
        result = validate_fapi_discovery(disco)
        alg_violation = next(v for v in result.violations if "signing" in v)
        assert "[" not in alg_violation
        assert "]" not in alg_violation


@pytest.mark.unit
class TestValidateFAPIDiscoveryAuthMethods:
    def test_discovery_with_tls_client_auth(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://fapi.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["tls_client_auth"],
            id_token_signing_alg_values_supported=["PS256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True

    def test_discovery_with_self_signed_tls(self):
        disco = DiscoveryDocumentResponse(
            is_successful=True,
            issuer="https://fapi.example.com",
            grant_types_supported=["authorization_code"],
            token_endpoint_auth_methods_supported=["self_signed_tls_client_auth"],
            id_token_signing_alg_values_supported=["ES256"],
        )
        result = validate_fapi_discovery(disco)
        assert result.is_compliant is True
