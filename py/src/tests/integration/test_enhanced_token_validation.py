"""Integration tests for enhanced token validation features."""

import pytest

from py_identity_model import TokenValidationConfig, validate_token
from py_identity_model.exceptions import TokenValidationException


@pytest.mark.integration
class TestEnhancedTokenValidation:
    """Test enhanced validation features against real tokens."""

    def test_leeway_with_real_token(
        self, client_credentials_token, test_config, require_https
    ):
        """Validate a real token with leeway configured."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            leeway=60,
            require_https=require_https,
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert "iss" in decoded

    def test_issuer_validation_with_real_token(
        self, client_credentials_token, test_config, issuer, require_https
    ):
        """Validate issuer against real discovery document issuer."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=issuer,
            require_https=require_https,
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer

    def test_multi_issuer_with_real_token(
        self, client_credentials_token, test_config, issuer, require_https
    ):
        """Validate token against a list of accepted issuers."""
        token = client_credentials_token.token["access_token"]
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=[issuer, "https://other-idp.example.com"],
            require_https=require_https,
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer

    def test_wrong_multi_issuer_list_still_matches_discovery(
        self, client_credentials_token, test_config, issuer, require_https
    ):
        """Config issuer list is overridden by discovery document issuer."""
        token = client_credentials_token.token["access_token"]
        # When perform_disco=True, the discovery document's issuer takes
        # precedence over the config issuer (this is correct behavior).
        config = TokenValidationConfig(
            perform_disco=True,
            issuer=["https://other.example.com"],
            require_https=require_https,
            options={"verify_aud": False, "require_aud": False},
        )

        # Succeeds because disco document issuer overrides config issuer
        decoded = validate_token(
            token,
            config,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        )
        assert decoded["iss"] == issuer


@pytest.mark.integration
class TestManualKeyEnhancedValidation:
    """Enhanced validation tests using manually-provided keys.

    These complement the discovery-based tests above by testing
    the same features with manual key configuration.
    """

    def test_leeway_with_manual_key(self, jwt_access_token, jwt_signing_key, issuer):
        """Token validation with clock skew tolerance."""
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            leeway=60,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(jwt_access_token["access_token"], config)
        assert "exp" in decoded
        assert "iat" in decoded

    def test_custom_claims_validator_with_manual_key(
        self, jwt_access_token, jwt_signing_key, issuer
    ):
        """Custom claims validator checks dct/tenants.

        Skips if provider does not inject custom claims.
        """

        def validate_descope_claims(claims: dict) -> None:
            if "dct" not in claims:
                raise ValueError("Missing dct claim")
            if "tenants" not in claims:
                raise ValueError("Missing tenants claim")
            tenant_id = claims["dct"]
            if tenant_id not in claims["tenants"]:
                raise ValueError(f"dct tenant {tenant_id} not in tenants")

        key_dict, alg = jwt_signing_key
        # First decode without validator to check for claims
        check_config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(jwt_access_token["access_token"], check_config)
        if "dct" not in decoded or "tenants" not in decoded:
            pytest.skip("Provider does not include custom dct/tenants claims")

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            claims_validator=validate_descope_claims,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(jwt_access_token["access_token"], config)
        assert decoded["dct"] == "test-tenant-1"

    def test_claims_validator_rejects_with_manual_key(
        self, jwt_access_token, jwt_signing_key, issuer
    ):
        """Claims validator raises -> TokenValidationException."""

        def reject_all(_claims: dict) -> None:
            raise ValueError("Rejected by policy")

        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            claims_validator=reject_all,
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(
            TokenValidationException,
            match="Rejected by policy",
        ):
            validate_token(jwt_access_token["access_token"], config)
