import datetime
from unittest.mock import patch

import pytest

from py_identity_model import (
    PyIdentityModelException,
    TokenValidationConfig,
    validate_token,
)
from py_identity_model.exceptions import (
    ConfigurationException,
    TokenExpiredException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)

from .conftest import DEFAULT_VALIDATION_OPTIONS as DEFAULT_OPTIONS
from .test_utils import count_upstream_fetches, expired_token_or_skip


# JWT format: three dot-separated segments
JWT_SEGMENT_SEPARATOR_COUNT = 2


def test_token_validation_expired_token(test_config, require_https):
    """Test expired token validation using cached config."""
    expired_token = expired_token_or_skip(test_config)

    # Descope session tokens use issuer format https://api.descope.com/v1/apps/{id}
    # which differs from the OIDC discovery issuer https://api.descope.com/{id}.
    # Disable issuer verification so we test expiration, not issuer mismatch.
    expired_options = {**DEFAULT_OPTIONS, "verify_iss": False}

    with pytest.raises(TokenExpiredException):
        validate_token(
            jwt=expired_token,
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=TokenValidationConfig(
                perform_disco=True,
                options=expired_options,
                require_https=require_https,
            ),
        )


def test_token_validation_succeeds(
    test_config, client_credentials_token, require_https
):
    """Test token validation using cached fixtures."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        require_https=require_https,
    )

    claims = validate_token(
        jwt=client_credentials_token.token["access_token"],
        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )
    assert claims is not None
    assert claims["iss"] is not None
    assert claims["iat"] is not None
    assert claims["exp"] is not None


def test_token_validation_with_invalid_config_throws_exception(
    test_config, client_credentials_token, require_https
):
    """Test invalid config using cached fixtures."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=False,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        require_https=require_https,
    )

    with pytest.raises(ConfigurationException):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )


def test_cache_succeeds(
    test_config, client_credentials_token, require_https, provider_caches_responses
):
    """JWKS is always cached; discovery is cached when the provider permits it."""
    assert client_credentials_token.token is not None

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        require_https=require_https,
    )

    num_validations = 5
    clear_discovery_cache()
    clear_jwks_cache()
    with count_upstream_fetches() as fetches:
        for _ in range(num_validations):
            validate_token(
                jwt=client_credentials_token.token["access_token"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

    # Proof of caching (not timing). JWKS ignores Cache-Control: no-store
    # (is_uncacheable_for_jwks) and is therefore always cached — a broken JWKS
    # cache would refetch on every validation. Discovery honors no-store, so it
    # is only cache-guaranteed when the provider's Cache-Control permits it
    # (provider_caches_responses); against a no-store provider discovery
    # re-fetches per validation by design.
    assert fetches["jwks"] == 1, (
        f"JWKS should be fetched exactly once across {num_validations} "
        f"validations, got {fetches} — JWKS caching is not in effect"
    )
    if provider_caches_responses:
        assert fetches["disco"] == 1, (
            f"discovery should be fetched exactly once across {num_validations} "
            f"validations when the provider permits caching, got {fetches}"
        )


def test_benchmark_validation(
    test_config, client_credentials_token, require_https, provider_caches_responses
):
    """Test benchmark using cached fixtures."""
    if not provider_caches_responses:
        pytest.skip(
            "Provider sends Cache-Control: no-store/no-cache; "
            "benchmark assumes caching is in effect"
        )
    assert client_credentials_token.token is not None
    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        require_https=require_https,
    )

    num_validations = 100
    clear_discovery_cache()
    clear_jwks_cache()
    start_time = datetime.datetime.now(tz=datetime.UTC)
    with count_upstream_fetches() as fetches:
        for _ in range(num_validations):
            validate_token(
                jwt=client_credentials_token.token["access_token"],
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )
    elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
    # Informational only — wall-clock is environment-dependent and is NOT the
    # caching assertion (the fetch-count check below is).
    print(f"{num_validations} validations in {elapsed_time}")

    # Proof of caching: one discovery + one JWKS fetch serve the entire loop;
    # the other validations are cache hits. A broken cache => one fetch each.
    assert fetches == {"disco": 1, "jwks": 1}, (
        f"expected exactly one discovery + one JWKS fetch across "
        f"{num_validations} validations, got {fetches} — caching is not in effect"
    )


def test_claim_validation_function_succeeds(
    test_config, client_credentials_token, require_https
):
    """Test claim validation success using cached fixtures."""
    assert client_credentials_token.token is not None

    called = []

    def validate_claims(_token: dict):
        called.append(True)

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
        require_https=require_https,
    )

    decoded_token = validate_token(
        jwt=client_credentials_token.token["access_token"],
        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
        token_validation_config=validation_config,
    )

    assert decoded_token is not None
    assert decoded_token["iss"] is not None
    assert len(called) == 1, "claims_validator should be invoked exactly once"


@pytest.mark.integration
class TestManualKeyValidation:
    """Test JWT validation with manually-provided keys.

    These tests use jwt_access_token and jwt_signing_key fixtures
    to validate tokens without auto-discovery. They work against
    any provider that returns JWT-format access tokens.
    """

    def test_validate_jwt_manual_key(self, jwt_access_token, jwt_signing_key, issuer):
        """Validate JWT with manually-provided key."""
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(jwt_access_token["access_token"], config)
        assert "iss" in decoded
        assert decoded["iss"] == issuer

    def test_validate_wrong_issuer(self, jwt_access_token, jwt_signing_key):
        """Token with wrong issuer config fails."""
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer="https://wrong-issuer.example.com",
            options={"verify_aud": False, "require_aud": False},
        )
        with pytest.raises(TokenValidationException):
            validate_token(jwt_access_token["access_token"], config)

    def test_validate_wrong_audience(self, jwt_access_token, jwt_signing_key, issuer):
        """Token with wrong audience claim is rejected."""
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            audience="https://wrong-audience.example.com",
            options={"verify_aud": True, "require_aud": True},
        )
        with pytest.raises(TokenValidationException):
            validate_token(jwt_access_token["access_token"], config)

    def test_validate_expired_token_time_patch(
        self, jwt_access_token, jwt_signing_key, issuer
    ):
        """Expired token raises TokenExpiredException.

        Patches time forward so PyJWT sees the fresh token as
        expired. Validates the exp->TokenExpiredException mapping
        end-to-end with a real provider-issued token.
        """
        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            leeway=0,
            options={
                "verify_aud": False,
                "require_aud": False,
                "verify_exp": True,
            },
        )

        far_future = datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC)
        with patch("jwt.api_jwt.datetime") as mock_dt:
            mock_dt.now.return_value = far_future
            mock_dt.timezone = datetime.timezone
            with pytest.raises(TokenExpiredException):
                validate_token(jwt_access_token["access_token"], config)

    def test_validate_auth_code_jwt_token(
        self, auth_code_result, jwt_signing_key, issuer
    ):
        """Validate JWT obtained from auth code flow."""
        token_response = auth_code_result["token_response"]
        access_token = token_response.token["access_token"]

        assert access_token.count(".") == JWT_SEGMENT_SEPARATOR_COUNT, (
            "Expected JWT but got opaque token"
        )

        key_dict, alg = jwt_signing_key
        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=[alg],
            issuer=issuer,
            options={"verify_aud": False, "require_aud": False},
        )
        decoded = validate_token(access_token, config)
        assert decoded["iss"] == issuer
        assert "sub" in decoded


def test_claim_validation_function_fails(
    test_config, client_credentials_token, require_https
):
    """Test claim validation failure using cached fixtures."""
    assert client_credentials_token.token is not None

    def validate_claims(_token: dict):
        raise PyIdentityModelException("Validation failed!")

    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        claims_validator=validate_claims,
        require_https=require_https,
    )

    with pytest.raises(TokenValidationException):
        validate_token(
            jwt=client_credentials_token.token["access_token"],
            disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
            token_validation_config=validation_config,
        )
