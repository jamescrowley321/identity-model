"""Integration tests for FAPI 2.0 Security Profile compliance.

These tests validate a live provider's discovery document against
FAPI 2.0 requirements and test the validation helpers with real
provider metadata.
"""

from functools import partial
from typing import Any
from urllib.parse import urlparse

import pytest

from py_identity_model import (
    FAPI2ClientProfile,
    FAPIProfileError,
    MtlsClientAuth,
    PrivateKeyJwt,
    PushedAuthorizationRequest,
    generate_dpop_key,
    validate_fapi_authorization_request,
    validate_fapi_client_config,
    validate_fapi_discovery,
)


@pytest.mark.integration
class TestFAPIDiscoveryCompliance:
    """Validate a live provider's discovery document against FAPI 2.0."""

    def test_validate_live_discovery(self, discovery_document):
        """Run FAPI 2.0 discovery validation against the live provider.

        Most test providers won't be FAPI-compliant.  This test verifies
        the validation runs without error and produces a meaningful result.
        """
        result = validate_fapi_discovery(discovery_document)

        # Result should always be well-formed
        assert isinstance(result.violations, list)
        assert isinstance(result.is_compliant, bool)
        assert result.is_compliant == (len(result.violations) == 0)

    def test_fapi_violations_are_descriptive(self, discovery_document):
        """Each violation string describes what's wrong."""
        result = validate_fapi_discovery(discovery_document)

        for violation in result.violations:
            assert isinstance(violation, str)
            assert len(violation) > 0

    def test_profile_from_live_discovery(self, discovery_document):
        """The profile refuses whatever validate_fapi_discovery refuses, and more.

        Non-compliant metadata is refused with exactly the discovery
        violations. Compliant metadata can still be refused for the client's
        own requirements; the local fixtures serve plain http, which the
        profile never accepts for the issuer.
        """
        violations = validate_fapi_discovery(discovery_document).violations
        issuer = discovery_document.issuer
        build = partial(
            FAPI2ClientProfile,
            discovery_document,
            client_id="fapi-client",
            redirect_uri=REDIRECT_URI,
            client_auth=_pkj(),
        )
        if violations:
            with pytest.raises(FAPIProfileError) as exc_info:
                build()
            assert exc_info.value.violations == violations
        elif urlparse(issuer).scheme != "https":
            with pytest.raises(FAPIProfileError) as exc_info:
                build()
            assert f"issuer must use https, got {issuer!r}" in exc_info.value.violations
        else:
            profile = build()
            assert profile.issuer == issuer
            assert profile.private_key_jwt == _pkj(issuer=issuer)


REDIRECT_URI = "https://bank.example.com/callback"
DPOP_KEY = generate_dpop_key("ES256")


def _pkj(**overrides: Any) -> PrivateKeyJwt:
    fields: dict[str, Any] = {
        "private_key": DPOP_KEY.private_key_pem,
        "algorithm": "ES256",
        **overrides,
    }
    return PrivateKeyJwt(**fields)


def _par(**overrides: Any) -> PushedAuthorizationRequest:
    fields: dict[str, Any] = {
        "address": "https://auth.example.com/par",
        "client_id": "fapi-client",
        "redirect_uri": REDIRECT_URI,
        "code_challenge": "valid-challenge",
        "code_challenge_method": "S256",
        "private_key_jwt": _pkj(),
        "dpop_key": DPOP_KEY,
        **overrides,
    }
    return PushedAuthorizationRequest(**fields)


@pytest.mark.integration
class TestFAPIClientConfigValidation:
    """FAPI client configuration validation on real client settings."""

    def test_private_key_jwt_with_dpop(self, discovery_document):
        issuer = discovery_document.issuer
        result = validate_fapi_client_config(
            issuer=issuer, private_key_jwt=_pkj(issuer=issuer), dpop_key=DPOP_KEY
        )
        assert result.violations == []

    def test_tls_client_auth_with_mtls(self, discovery_document):
        result = validate_fapi_client_config(
            issuer=discovery_document.issuer,
            mtls=MtlsClientAuth(certificate="client.pem", private_key="client.key"),
        )
        assert result.violations == []

    def test_no_client_auth_rejected(self, discovery_document):
        result = validate_fapi_client_config(
            issuer=discovery_document.issuer, dpop_key=DPOP_KEY
        )
        assert result.is_compliant is False

    def test_no_sender_constraining_rejected(self, discovery_document):
        issuer = discovery_document.issuer
        result = validate_fapi_client_config(
            issuer=issuer, private_key_jwt=_pkj(issuer=issuer)
        )
        assert result.is_compliant is False

    def test_endpoint_url_audience_rejected(self, discovery_document):
        result = validate_fapi_client_config(
            issuer=discovery_document.issuer,
            private_key_jwt=_pkj(audience=discovery_document.token_endpoint),
            dpop_key=DPOP_KEY,
        )
        assert result.is_compliant is False


@pytest.mark.integration
class TestFAPIAuthRequestValidation:
    """FAPI authorization request validation on real request objects."""

    def test_fully_compliant_request(self):
        assert validate_fapi_authorization_request(_par()).violations == []

    def test_implicit_flow_rejected(self):
        result = validate_fapi_authorization_request(_par(response_type="token"))
        assert result.violations == ["response_type must be 'code', got 'token'"]

    def test_http_redirect_uri_rejected(self):
        result = validate_fapi_authorization_request(
            _par(redirect_uri="http://insecure.example.com/callback")
        )
        assert result.is_compliant is False

    def test_plain_pkce_rejected(self):
        result = validate_fapi_authorization_request(
            _par(code_challenge_method="plain")
        )
        assert result.violations == ["PKCE method must be 'S256', got 'plain'"]
