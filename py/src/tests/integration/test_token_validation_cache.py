"""
Tests for token validation caching behavior and multi-token scenarios.

These tests verify:
1. Cache isolation between different providers (tokens from wrong provider fail correctly)
2. Multiple tokens from the same provider work correctly with caching
3. Benchmark accuracy with pre-generated tokens
"""

import datetime

import pytest

from py_identity_model import (
    ClientCredentialsTokenRequest,
    TokenValidationConfig,
    request_client_credentials_token,
    validate_token,
)
from py_identity_model.exceptions import (
    TokenExpiredException,
    TokenValidationException,
)
from py_identity_model.sync.token_validation import (
    clear_discovery_cache,
    clear_jwks_cache,
)

from .conftest import DEFAULT_VALIDATION_OPTIONS as DEFAULT_OPTIONS
from .test_utils import (
    count_upstream_fetches,
    expired_token_or_skip,
    get_alternate_provider_expired_token,
)


@pytest.fixture
def clear_validation_caches():
    """Clear all token validation caches before and after test."""
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


@pytest.fixture
def validation_config(test_config, require_https):
    """Create standard validation config for tests."""
    return TokenValidationConfig(
        perform_disco=True,
        audience=test_config["TEST_AUDIENCE"],
        options=DEFAULT_OPTIONS,
        require_https=require_https,
    )


def generate_tokens(test_config: dict, token_endpoint: str, count: int) -> list[str]:
    """Generate multiple tokens from the provider."""
    tokens = []
    for _ in range(count):
        response = request_client_credentials_token(
            ClientCredentialsTokenRequest(
                client_id=test_config["TEST_CLIENT_ID"],
                client_secret=test_config["TEST_CLIENT_SECRET"],
                address=token_endpoint,
                scope=test_config["TEST_SCOPE"],
            )
        )
        assert response.is_successful is True, "Failed to generate token"
        assert response.token is not None
        tokens.append(response.token["access_token"])
    return tokens


@pytest.mark.usefixtures("clear_validation_caches")
class TestMultipleTokensFromSameProvider:
    """Test that multiple tokens from the same provider work correctly."""

    def test_multiple_tokens_validation_succeeds(
        self,
        test_config,
        token_endpoint,
        validation_config,
        provider_caches_responses,
    ):
        """
        Generate multiple tokens from the same provider and validate each one.

        This ensures:
        1. Each token can be validated independently
        2. Caching doesn't cause cross-token interference
        3. The cache correctly handles tokens with the same kid

        Note: Some providers (e.g., Descope) return identical tokens when
        requested within the same second and don't include a jti claim.
        """
        num_tokens = 3
        tokens = generate_tokens(test_config, token_endpoint, num_tokens)

        # Validate each token (may be duplicates for some providers). All tokens
        # share the provider and one signing key, so the JWKS cache must serve
        # every validation after the first from cache.
        clear_discovery_cache()
        clear_jwks_cache()
        validated_claims = []
        with count_upstream_fetches() as fetches:
            for i, token in enumerate(tokens):
                claims = validate_token(
                    jwt=token,
                    disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                    token_validation_config=validation_config,
                )
                assert claims is not None, f"Token {i + 1} validation failed"
                validated_claims.append(claims)

        # If provider includes jti, verify uniqueness
        if "jti" in validated_claims[0]:
            jtis = [c["jti"] for c in validated_claims]
            assert len(set(jtis)) == num_tokens, "Each token should have unique jti"

        # Caching proof (not timing). JWKS ignores no-store and is always cached,
        # so a broken JWKS cache would refetch per validation. Discovery honors
        # no-store, so it is only cache-guaranteed when the provider permits it
        # (against a no-store provider discovery re-fetches by design).
        assert fetches["jwks"] == 1, (
            f"JWKS should be fetched exactly once across {num_tokens} "
            f"validations, got {fetches} — JWKS caching is not in effect"
        )
        if provider_caches_responses:
            assert fetches["disco"] == 1, (
                f"discovery should be fetched exactly once across {num_tokens} "
                f"validations when the provider permits caching, got {fetches}"
            )


@pytest.mark.usefixtures("clear_validation_caches")
class TestCacheIsolationBetweenProviders:
    """Test that cache is properly isolated between different providers."""

    def test_wrong_provider_token_fails_validation(
        self, test_config, validation_config
    ):
        """
        Test that a token from one provider fails when validated
        against a different provider's discovery document.

        Uses an expired token from an alternate provider (loaded from .env.local)
        validated against the current provider's discovery endpoint.

        This ensures:
        1. Tokens are properly validated against the correct issuer
        2. Cache doesn't allow cross-provider token acceptance
        3. The kid mismatch causes proper rejection
        """
        alternate_provider_token = get_alternate_provider_expired_token()
        if alternate_provider_token is None:
            pytest.skip(".env.local not found - skipping cross-provider test")

        # Token from alternate provider should fail when validated against
        # current provider's JWKS because the kid won't match
        with pytest.raises(TokenValidationException) as exc_info:
            validate_token(
                jwt=alternate_provider_token,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )

        # Should fail due to kid not found in current provider's JWKS
        error_msg = str(exc_info.value).lower()
        assert "kid" in error_msg or "key" in error_msg, (
            f"Expected kid/key mismatch error, got: {exc_info.value}"
        )

    def test_expired_token_from_same_provider_fails(self, test_config, require_https):
        """
        Test that an expired token from the same provider fails with
        the correct error (expiration, not cache issues).

        This ensures the cache doesn't bypass expiration checks.
        """
        expired_token = expired_token_or_skip(test_config)

        # Descope session tokens use a different issuer format than OIDC discovery.
        # Disable issuer verification so we test expiration, not issuer mismatch.
        expired_options = {**DEFAULT_OPTIONS, "verify_iss": False}
        validation_config = TokenValidationConfig(
            perform_disco=True,
            options=expired_options,
            require_https=require_https,
        )

        with pytest.raises(TokenExpiredException):
            validate_token(
                jwt=expired_token,
                disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                token_validation_config=validation_config,
            )


@pytest.mark.usefixtures("clear_validation_caches")
class TestBenchmarkWithPreGeneratedTokens:
    """
    Benchmark tests with pre-generated tokens for accuracy.

    Pre-generating tokens ensures the benchmark measures validation
    performance, not token generation time.
    """

    def test_benchmark_with_multiple_unique_tokens(
        self,
        test_config,
        token_endpoint,
        validation_config,
        provider_caches_responses,
    ):
        """
        Benchmark validation with multiple unique tokens.

        This test:
        1. Pre-generates several unique tokens
        2. Validates each token multiple times
        3. Ensures the benchmark reflects real-world usage where
           different tokens are validated
        """
        if not provider_caches_responses:
            pytest.skip(
                "Provider sends Cache-Control: no-store/no-cache; "
                "benchmark assumes caching is in effect"
            )
        num_unique_tokens = 5
        tokens = generate_tokens(test_config, token_endpoint, num_unique_tokens)

        validations_per_token = 20
        total_validations = num_unique_tokens * validations_per_token

        clear_discovery_cache()
        clear_jwks_cache()
        start_time = datetime.datetime.now(tz=datetime.UTC)
        with count_upstream_fetches() as fetches:
            for _ in range(validations_per_token):
                for token in tokens:
                    validate_token(
                        jwt=token,
                        disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                        token_validation_config=validation_config,
                    )
        elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
        # Informational only — timing is environment-dependent and is NOT the
        # caching assertion (the fetch-count check below is).
        print(f"\n{total_validations} validations completed in {elapsed_time}")
        print(
            f"Average: {elapsed_time.total_seconds() / total_validations * 1000:.2f}ms per validation"
        )

        # Proof of caching: all num_unique_tokens tokens share one provider, so
        # the whole loop drives exactly one discovery + one JWKS fetch. A broken
        # cache would fetch on every validation.
        assert fetches == {"disco": 1, "jwks": 1}, (
            f"expected exactly one discovery + one JWKS fetch across "
            f"{total_validations} validations, got {fetches} — caching is not in effect"
        )

    def test_benchmark_single_token_repeated(
        self,
        test_config,
        client_credentials_token,
        validation_config,
        provider_caches_responses,
    ):
        """
        Benchmark validation of a single token repeated many times.

        This represents the optimal caching scenario where the same
        token is validated repeatedly (e.g., during its lifetime).
        """
        if not provider_caches_responses:
            pytest.skip(
                "Provider sends Cache-Control: no-store/no-cache; "
                "benchmark assumes caching is in effect"
            )
        token = client_credentials_token.token["access_token"]

        num_validations = 100
        clear_discovery_cache()
        clear_jwks_cache()
        start_time = datetime.datetime.now(tz=datetime.UTC)
        with count_upstream_fetches() as fetches:
            for _ in range(num_validations):
                validate_token(
                    jwt=token,
                    disco_doc_address=test_config["TEST_DISCO_ADDRESS"],
                    token_validation_config=validation_config,
                )
        elapsed_time = datetime.datetime.now(tz=datetime.UTC) - start_time
        # Informational only — timing is environment-dependent and is NOT the
        # caching assertion (the fetch-count check below is).
        print(f"\n{num_validations} validations of same token: {elapsed_time}")
        print(
            f"Average: {elapsed_time.total_seconds() / num_validations * 1000:.2f}ms per validation"
        )

        # Proof of caching: the same token validated num_validations times drives
        # exactly one discovery + one JWKS fetch; the rest are cache hits.
        assert fetches == {"disco": 1, "jwks": 1}, (
            f"expected exactly one discovery + one JWKS fetch across "
            f"{num_validations} validations, got {fetches} — caching is not in effect"
        )
