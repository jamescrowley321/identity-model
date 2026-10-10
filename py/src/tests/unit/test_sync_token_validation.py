"""
Unit tests for sync token validation.

These tests verify sync-specific token validation logic including
error handling, TTL-based JWKS caching, and signature retry on key rotation.
"""

import time
from unittest.mock import patch

import httpx
import pytest
import respx

from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    SignatureVerificationException,
    TokenValidationException,
)
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from ..constants import DISCO_URL
from ..token_validation_helpers import (
    DISCO_RESPONSE_NO_JWKS,
    DISCO_RESPONSE_WITH_JWKS,
    JWKS_FETCH_AFTER_EXPIRY,
    JWKS_FETCH_WITH_RETRY,
    generate_rsa_keypair,
    sign_jwt,
)


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return generate_rsa_keypair()


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all caches between tests."""
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


class TestSyncTokenValidation:
    """Test sync token validation functionality."""

    def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match=r"TokenValidationConfig\.key and TokenValidationConfig\.algorithms are required",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )

    @respx.mock
    def test_get_disco_response_caching(self):
        """Test that discovery response is cached."""
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        response1 = _get_disco_response(DISCO_URL)
        response2 = _get_disco_response(DISCO_URL)

        assert response1.issuer == "https://example.com"
        assert response2.issuer == "https://example.com"

    @respx.mock
    def test_missing_jwks_uri_cached_path_raises(self):
        """Test that missing jwks_uri in discovery doc raises TokenValidationException."""
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(
            TokenValidationException,
            match=r"does not contain a jwks_uri.*require_key_set",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address=DISCO_URL,
            )

    @respx.mock
    def test_missing_jwks_uri_di_path_raises(self):
        """Test that missing jwks_uri raises TokenValidationException (DI path)."""
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with (
            HTTPClient() as client,
            pytest.raises(
                TokenValidationException,
                match=r"does not contain a jwks_uri.*require_key_set",
            ),
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address=DISCO_URL,
                http_client=client,
            )

    @respx.mock
    def test_empty_string_jwks_uri_cached_path_raises(self):
        """Test that empty-string jwks_uri raises TokenValidationException."""
        disco_with_empty_jwks = {**DISCO_RESPONSE_NO_JWKS, "jwks_uri": ""}
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=disco_with_empty_jwks)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(
            TokenValidationException,
            match=r"does not contain a jwks_uri.*require_key_set",
        ):
            validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address=DISCO_URL,
            )


class TestSyncJwksCacheTTL:
    """Test TTL-based JWKS caching in sync token validation."""

    @respx.mock
    def test_jwks_cache_returns_cached_within_ttl(self, rsa_keypair):
        """JWKS is fetched once and reused within TTL."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # First call — fetches JWKS
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert jwks_route.call_count == 1

        # Second call — should use cached JWKS (no additional fetch)
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert jwks_route.call_count == 1

    @respx.mock
    def test_jwks_cache_refetches_after_ttl_expiry(self, rsa_keypair):
        """JWKS is re-fetched when TTL expires."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # First call
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert jwks_route.call_count == 1

        # Simulate TTL expiry by shifting the monotonic clock forward past
        # the default 24h JWKS TTL.
        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 86401

            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        # Should have fetched JWKS a second time
        assert jwks_route.call_count == JWKS_FETCH_AFTER_EXPIRY


class TestSyncSignatureRetry:
    """Test signature verification retry with JWKS refresh."""

    @respx.mock
    def test_signature_retry_on_key_rotation(self):
        """When signature fails with cached key, refresh JWKS and retry with new key."""
        # Key 1 (old) — will be cached initially
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "rotated-key"

        # Key 2 (new) — token is signed with this
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "rotated-key"

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "rotated-key"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # First JWKS fetch returns old key, second returns new key
        jwks_route = respx.get("https://example.com/jwks").mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # Should succeed: first attempt fails with old key, retry with new key succeeds
        decoded = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )

        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY  # initial fetch + refresh

    @respx.mock
    def test_cached_path_refreshes_jwks_when_kid_not_in_cache(self):
        """Cached JWKS lookup with a kid not in cache forces a refresh.

        OIDC OPs rotate signing keys; when a token arrives with a kid that is
        not yet in the cached JWKS, the cache is stale. The library must
        refresh JWKS without waiting for a signature failure on a key it
        does not have.
        """
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "old-kid"

        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # First fetch returns only the old kid; second fetch returns only the new kid.
        # If the library waits for signature failure to refresh, the second fetch
        # will not happen because the lookup raises before decode.
        jwks_route = respx.get("https://example.com/jwks").mock(
            side_effect=[
                httpx.Response(200, json={"keys": [old_key_dict]}),
                httpx.Response(200, json={"keys": [new_key_dict]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        # Prime the JWKS cache directly with the old kid (no validate_token, so
        # the legacy retry path can't accidentally satisfy the assertion below).
        _get_cached_jwks("https://example.com/jwks")

        decoded = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )

        assert decoded["sub"] == "user1"
        # The second fetch can ONLY have come from the new kid-miss refresh path
        # inside _discover_and_resolve_key (legacy retry never gets a chance —
        # validate_token only ran once and the kid was missing pre-decode).
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY

    @respx.mock
    def test_no_refresh_when_kid_present_in_cache(self):
        """Negative regression: when kid IS in cached JWKS, no refresh is issued.

        Pins the predicate sense in the kid-miss check. A future change that
        flipped `not any(...)` to `any(...)` would silently regress to
        refreshing JWKS on every request.
        """
        key_dict, pem = generate_rsa_keypair()
        key_dict["kid"] = "present-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "present-kid"},
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        # First call primes the cache (1 fetch).
        validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert jwks_route.call_count == 1

        for _ in range(10):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        assert jwks_route.call_count == 1, (
            f"Predicate regression: {jwks_route.call_count} fetches for 11 "
            f"validations with cached kid (expected 1)"
        )

    @respx.mock
    def test_signature_failure_still_raises_after_retry(self):
        """When signature fails with both old and new keys, exception is raised."""
        # Both keys are different from the signing key
        wrong_key1 = generate_rsa_keypair()[0]
        wrong_key1["kid"] = "wrong-key"
        wrong_key2 = generate_rsa_keypair()[0]
        wrong_key2["kid"] = "wrong-key"

        # Sign with a completely different key
        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get("https://example.com/jwks").mock(
            side_effect=[
                httpx.Response(200, json={"keys": [wrong_key1]}),
                httpx.Response(200, json={"keys": [wrong_key2]}),
            ]
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        with pytest.raises(SignatureVerificationException):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

    @respx.mock
    def test_di_path_retries_on_signature_failure(self):
        """DI (injected client) path retries JWKS fetch for key rotation support."""
        wrong_key = generate_rsa_keypair()[0]
        wrong_key["kid"] = "wrong-key"

        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        jwks_route = respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [wrong_key]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
        )

        with HTTPClient() as client, pytest.raises(SignatureVerificationException):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
                http_client=client,
            )

        # Two JWKS fetches — initial + retry for key rotation
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY
