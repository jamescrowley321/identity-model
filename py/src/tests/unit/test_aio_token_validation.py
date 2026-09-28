"""
Unit tests for async token validation.

These tests verify async-specific token validation logic including
error handling, TTL-based JWKS caching, signature retry on key rotation,
and enhanced features (leeway, multi-issuer, subject).
"""

import time
from unittest.mock import patch

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    _get_cached_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)
from py_identity_model.core.jwks_cache import _reset_env_for_testing
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import (
    ConfigurationException,
    InvalidIssuerException,
    SignatureVerificationException,
    TokenExpiredException,
    TokenValidationException,
)

from .token_validation_helpers import (
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
async def _clear_caches():
    """Clear all caches between tests.

    ``clear_*_cache`` helpers are imported from the aio module and are now
    coroutines (#405) — must be awaited.
    """
    await clear_discovery_cache()
    await clear_jwks_cache()
    yield
    await clear_discovery_cache()
    await clear_jwks_cache()


class TestAsyncTokenValidation:
    """Test async token validation functionality."""

    @pytest.mark.asyncio
    async def test_manual_validation_missing_config(self):
        """Test manual validation (perform_disco=False) with missing config."""
        validation_config = TokenValidationConfig(
            perform_disco=False,
        )

        with pytest.raises(
            ConfigurationException,
            match=r"TokenValidationConfig\.key and TokenValidationConfig\.algorithms are required",
        ):
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_jwks_uri_cached_path_raises(self):
        """Test that missing jwks_uri in discovery doc raises TokenValidationException."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_jwks_uri_di_path_raises(self):
        """Test that missing jwks_uri raises TokenValidationException (DI path)."""
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_NO_JWKS)
        )

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        async with AsyncHTTPClient() as client:
            with pytest.raises(
                TokenValidationException,
                match=r"does not contain a jwks_uri.*require_key_set",
            ):
                await validate_token(
                    jwt="fake.jwt.token",
                    token_validation_config=validation_config,
                    disco_doc_address="https://example.com/.well-known/openid-configuration",
                    http_client=client,
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_string_jwks_uri_cached_path_raises(self):
        """Test that empty-string jwks_uri raises TokenValidationException."""
        disco_with_empty_jwks = {**DISCO_RESPONSE_NO_JWKS, "jwks_uri": ""}
        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
            await validate_token(
                jwt="fake.jwt.token",
                token_validation_config=validation_config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )


class TestAsyncJwksCacheTTL:
    """Test TTL-based JWKS caching in async token validation."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_returns_cached_within_ttl(self, rsa_keypair):
        """JWKS is fetched once and reused within TTL."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        # Second call — should use cached JWKS
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_refetches_after_ttl_expiry(self, rsa_keypair):
        """JWKS is re-fetched when TTL expires."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        # Simulate TTL expiry via monotonic clock advance.
        with patch("py_identity_model.core.jwks_cache.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 86401

            await validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

        assert jwks_route.call_count == JWKS_FETCH_AFTER_EXPIRY


class TestAsyncSignatureRetry:
    """Test signature verification retry with JWKS refresh."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_retry_on_key_rotation(self):
        """When signature fails with cached key, refresh JWKS and retry with new key."""
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "rotated-key"

        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "rotated-key"

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "rotated-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
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

        decoded = await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )

        assert decoded["sub"] == "user1"
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY

    @pytest.mark.asyncio
    @respx.mock
    async def test_cached_path_refreshes_jwks_when_kid_not_in_cache(self):
        """Cached JWKS lookup with a kid not in cache forces a refresh (JWKS-004).

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

        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
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
        await _get_cached_jwks("https://example.com/jwks")

        decoded = await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )

        assert decoded["sub"] == "user1"
        # Now the second fetch can ONLY have come from the new kid-miss refresh
        # path inside _discover_and_resolve_key (legacy retry never gets a chance
        # because validate_token only ran once, and the kid was missing pre-decode).
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_refresh_when_kid_present_in_cache(self):
        """Negative regression: when kid IS in cached JWKS, no refresh is issued.

        Pins the predicate sense in the kid-miss check. A future change that
        flipped `not any(...)` to `any(...)` would silently regress to
        refreshing JWKS on every request.
        """
        key_dict, pem = generate_rsa_keypair()
        key_dict["kid"] = "present-kid"

        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
        await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://example.com/.well-known/openid-configuration",
        )
        assert jwks_route.call_count == 1

        for _ in range(10):
            await validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

        assert jwks_route.call_count == 1, (
            f"Predicate regression: {jwks_route.call_count} fetches for 11 "
            f"validations with cached kid (expected 1)"
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_failure_still_raises_after_retry(self):
        """When signature fails with both old and new keys, exception is raised."""
        wrong_key1 = generate_rsa_keypair()[0]
        wrong_key1["kid"] = "wrong-key"
        wrong_key2 = generate_rsa_keypair()[0]
        wrong_key2["kid"] = "wrong-key"

        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
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
            await validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://example.com/.well-known/openid-configuration",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_di_path_retries_on_signature_failure(self):
        """DI (injected client) path retries JWKS fetch for key rotation support."""
        wrong_key = generate_rsa_keypair()[0]
        wrong_key["kid"] = "wrong-key"

        _, signing_pem = generate_rsa_keypair()
        token = sign_jwt(
            signing_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "wrong-key"},
        )

        respx.get("https://example.com/.well-known/openid-configuration").mock(
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

        async with AsyncHTTPClient() as client:
            with pytest.raises(SignatureVerificationException):
                await validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address="https://example.com/.well-known/openid-configuration",
                    http_client=client,
                )

        # Two JWKS fetches — initial + retry for key rotation
        assert jwks_route.call_count == JWKS_FETCH_WITH_RETRY


# ============================================================================
# Async enhanced feature tests (S4: parity with sync tests)
# ============================================================================


@pytest.mark.unit
class TestAsyncLeeway:
    """Async tests for clock skew tolerance (leeway)."""

    @pytest.mark.asyncio
    async def test_expired_token_rejected_without_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
        )

        with pytest.raises(TokenExpiredException):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_expired_token_accepted_with_leeway(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {
                "sub": "user1",
                "iss": "https://test.com",
                "exp": int(time.time()) - 10,
            },
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            leeway=30,
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    async def test_leeway_zero_does_not_allow_expired(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "exp": int(time.time()) - 5},
        )

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            leeway=0,
        )

        with pytest.raises(TokenExpiredException):
            await validate_token(jwt=token, token_validation_config=config)


@pytest.mark.unit
class TestAsyncMultiIssuer:
    """Async tests for multiple issuer validation."""

    @pytest.mark.asyncio
    async def test_single_issuer_still_works(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://idp1.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer="https://idp1.com",
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["iss"] == "https://idp1.com"

    @pytest.mark.asyncio
    async def test_list_issuer_accepts_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://idp2.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer=["https://idp1.com", "https://idp2.com"],
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["iss"] == "https://idp2.com"

    @pytest.mark.asyncio
    async def test_list_issuer_rejects_non_matching(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user1", "iss": "https://evil.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            issuer=["https://idp1.com", "https://idp2.com"],
        )

        with pytest.raises(InvalidIssuerException):
            await validate_token(jwt=token, token_validation_config=config)


@pytest.mark.unit
class TestAsyncSubjectValidation:
    """Async tests for subject (sub) claim validation."""

    @pytest.mark.asyncio
    async def test_subject_matches(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="user123",
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_subject_mismatch_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "user123", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="different_user",
        )

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_subject_mismatch_does_not_leak_claim_value(self, rsa_keypair):
        """S1: Error message must NOT contain the actual sub claim value."""
        key_dict, pem = rsa_keypair
        secret_sub = "sensitive-user-id-12345"
        token = sign_jwt(pem, {"sub": secret_sub, "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="different_user",
        )

        with pytest.raises(TokenValidationException) as exc_info:
            await validate_token(jwt=token, token_validation_config=config)
        assert secret_sub not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_sub_claim_raises(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject="user123",
        )

        with pytest.raises(TokenValidationException, match="Invalid subject"):
            await validate_token(jwt=token, token_validation_config=config)

    @pytest.mark.asyncio
    async def test_subject_none_skips_validation(self, rsa_keypair):
        key_dict, pem = rsa_keypair
        token = sign_jwt(pem, {"sub": "anyone", "iss": "https://test.com"})

        config = TokenValidationConfig(
            perform_disco=False,
            key=key_dict,
            algorithms=["RS256"],
            subject=None,
        )

        decoded = await validate_token(jwt=token, token_validation_config=config)
        assert decoded["sub"] == "anyone"


class TestAsyncLruReadHitEviction:
    """Async twin of the sync LRU eviction test (#397): a read cache hit on
    the async ``_get_cached_jwks`` refreshes recency so an attacker driving
    distinct-address reads cannot evict a legitimately-hot entry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_read_hit_protects_hot_entry_from_eviction(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()
        try:
            urls = [f"https://op-{i}.example/jwks" for i in range(5)]
            key_dict = generate_rsa_keypair()[0]
            for url in urls:
                respx.get(url).mock(
                    return_value=httpx.Response(
                        200,
                        json={"keys": [key_dict]},
                        headers={"Cache-Control": "max-age=3600"},
                    )
                )

            # Fill to capacity: op-0 (oldest) .. op-3 (newest).
            for url in urls[:4]:
                await _get_cached_jwks(url)
            assert list(aio_tv._jwks_cache.keys()) == urls[:4]

            # Re-read op-0 — a cache hit (no network) that refreshes recency.
            await _get_cached_jwks(urls[0])
            assert list(aio_tv._jwks_cache.keys()) == [
                urls[1],
                urls[2],
                urls[3],
                urls[0],
            ]

            # A fifth distinct URI overflows; eviction targets op-1 (oldest
            # unread), NOT the recently-read op-0.
            await _get_cached_jwks(urls[4])
            assert urls[0] in aio_tv._jwks_cache
            assert urls[1] not in aio_tv._jwks_cache
            assert set(aio_tv._jwks_cache.keys()) == {
                urls[0],
                urls[2],
                urls[3],
                urls[4],
            }
        finally:
            _reset_env_for_testing()
