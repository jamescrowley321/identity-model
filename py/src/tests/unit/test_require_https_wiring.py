"""
Unit tests for require_https wiring in token validation.

These tests verify that TokenValidationConfig.require_https is properly
propagated to DiscoveryPolicy in both sync and async token validation,
blocking the exploit scenario where an attacker downgrades discovery
to plaintext HTTP to intercept or tamper with OIDC metadata.

Security fix for: #377
"""

import httpx
import pytest
import respx

from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.core.token_validation_logic import build_resolved_config
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    clear_discovery_cache as sync_clear_discovery_cache,
)
from py_identity_model.sync.token_validation import (
    clear_jwks_cache as sync_clear_jwks_cache,
)
from py_identity_model.sync.token_validation import (
    validate_token as sync_validate_token,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    DISCO_URL,
    generate_rsa_keypair,
    sign_jwt,
)


# HTTP discovery response — same as HTTPS but with http:// URLs
DISCO_RESPONSE_HTTP = {
    "issuer": "http://localhost:8080",
    "authorization_endpoint": "http://localhost:8080/authorize",
    "token_endpoint": "http://localhost:8080/token",
    "jwks_uri": "http://localhost:8080/jwks",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA key pair for testing."""
    return generate_rsa_keypair()


@pytest.fixture(autouse=True)
async def _clear_caches():
    """Clear all caches between tests."""
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


class TestSyncRequireHttpsWiring:
    """Test require_https propagation in sync token validation."""

    @respx.mock
    def test_require_https_default_blocks_http_discovery_cached_path(self):
        """Default require_https=True blocks HTTP discovery URL (cached path).

        Exploit scenario: attacker provides http:// discovery address to
        intercept OIDC metadata in transit and inject malicious JWKS URI.
        """
        config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
            # require_https defaults to True
        )

        with pytest.raises(TokenValidationException, match="HTTPS is required"):
            sync_validate_token(
                jwt="fake.jwt.token",
                token_validation_config=config,
                disco_doc_address="http://evil.example.com/.well-known/openid-configuration",
            )

    @respx.mock
    def test_require_https_true_blocks_http_discovery_di_path(self):
        """require_https=True blocks HTTP discovery URL (DI path).

        The injected http_client path must also enforce HTTPS policy.
        """
        config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
            require_https=True,
        )

        with (
            HTTPClient() as client,
            pytest.raises(TokenValidationException, match="HTTPS is required"),
        ):
            sync_validate_token(
                jwt="fake.jwt.token",
                token_validation_config=config,
                disco_doc_address="http://evil.example.com/.well-known/openid-configuration",
                http_client=client,
            )

    @respx.mock
    def test_require_https_false_allows_http_discovery_cached_path(self, rsa_keypair):
        """require_https=False allows HTTP discovery URL (cached path).

        Legitimate use case: local development with http://localhost.
        """
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://localhost:8080"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://localhost:8080/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_HTTP)
        )
        respx.get("http://localhost:8080/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://localhost:8080",
            require_https=False,
        )

        decoded = sync_validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="http://localhost:8080/.well-known/openid-configuration",
        )
        assert decoded["sub"] == "user1"

    @respx.mock
    def test_require_https_false_allows_http_discovery_di_path(self, rsa_keypair):
        """require_https=False allows HTTP discovery URL (DI path)."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://localhost:8080"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://localhost:8080/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_HTTP)
        )
        respx.get("http://localhost:8080/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://localhost:8080",
            require_https=False,
        )

        with HTTPClient() as client:
            decoded = sync_validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="http://localhost:8080/.well-known/openid-configuration",
                http_client=client,
            )
        assert decoded["sub"] == "user1"

    @respx.mock
    def test_https_always_works_regardless_of_require_https(self, rsa_keypair):
        """HTTPS URLs work whether require_https is True or False."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
            require_https=True,
        )

        decoded = sync_validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"

    @respx.mock
    def test_cache_poisoning_blocked_require_https_in_cache_key(self, rsa_keypair):
        """Cache with require_https=False must not bypass require_https=True.

        Exploit scenario: attacker triggers a require_https=False call first,
        poisoning the cache. A subsequent require_https=True call to the same
        address must NOT hit the poisoned cache — it must enforce HTTPS.

        Uses a non-loopback address since DiscoveryPolicy allows HTTP on
        loopback by default.
        """
        key_dict, pem = rsa_keypair

        disco_response_http = {
            "issuer": "http://external.example.com",
            "authorization_endpoint": "http://external.example.com/authorize",
            "token_endpoint": "http://external.example.com/token",
            "jwks_uri": "http://external.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://external.example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://external.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=disco_response_http)
        )
        respx.get("http://external.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Step 1: Populate cache with require_https=False
        config_permissive = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://external.example.com",
            require_https=False,
        )
        decoded = sync_validate_token(
            jwt=token,
            token_validation_config=config_permissive,
            disco_doc_address="http://external.example.com/.well-known/openid-configuration",
        )
        assert decoded["sub"] == "user1"

        # Step 2: require_https=True must still reject the HTTP address
        config_strict = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
            require_https=True,
        )
        with pytest.raises(TokenValidationException, match="HTTPS is required"):
            sync_validate_token(
                jwt="fake.jwt.token",
                token_validation_config=config_strict,
                disco_doc_address="http://external.example.com/.well-known/openid-configuration",
            )


class TestAsyncRequireHttpsWiring:
    """Test require_https propagation in async token validation."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_require_https_default_blocks_http_discovery_cached_path(self):
        """Default require_https=True blocks HTTP discovery URL (cached path).

        Exploit scenario: attacker provides http:// discovery address to
        intercept OIDC metadata in transit and inject malicious JWKS URI.
        """
        config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
        )

        with pytest.raises(TokenValidationException, match="HTTPS is required"):
            await async_validate_token(
                jwt="fake.jwt.token",
                token_validation_config=config,
                disco_doc_address="http://evil.example.com/.well-known/openid-configuration",
            )

    @pytest.mark.asyncio
    @respx.mock
    async def test_require_https_true_blocks_http_discovery_di_path(self):
        """require_https=True blocks HTTP discovery URL (DI path)."""
        config = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
            require_https=True,
        )

        async with AsyncHTTPClient() as client:
            with pytest.raises(TokenValidationException, match="HTTPS is required"):
                await async_validate_token(
                    jwt="fake.jwt.token",
                    token_validation_config=config,
                    disco_doc_address="http://evil.example.com/.well-known/openid-configuration",
                    http_client=client,
                )

    @pytest.mark.asyncio
    @respx.mock
    async def test_require_https_false_allows_http_discovery_cached_path(
        self, rsa_keypair
    ):
        """require_https=False allows HTTP discovery URL (cached path)."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://localhost:8080"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://localhost:8080/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_HTTP)
        )
        respx.get("http://localhost:8080/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://localhost:8080",
            require_https=False,
        )

        decoded = await async_validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="http://localhost:8080/.well-known/openid-configuration",
        )
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_require_https_false_allows_http_discovery_di_path(self, rsa_keypair):
        """require_https=False allows HTTP discovery URL (DI path)."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://localhost:8080"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://localhost:8080/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_HTTP)
        )
        respx.get("http://localhost:8080/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://localhost:8080",
            require_https=False,
        )

        async with AsyncHTTPClient() as client:
            decoded = await async_validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="http://localhost:8080/.well-known/openid-configuration",
                http_client=client,
            )
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_https_always_works_regardless_of_require_https(self, rsa_keypair):
        """HTTPS URLs work whether require_https is True or False."""
        key_dict, pem = rsa_keypair
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        respx.get("https://example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="https://example.com",
            require_https=True,
        )

        decoded = await async_validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address=DISCO_URL,
        )
        assert decoded["sub"] == "user1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_cache_poisoning_blocked_require_https_in_cache_key(
        self, rsa_keypair
    ):
        """Cache with require_https=False must not bypass require_https=True.

        Uses a non-loopback address since DiscoveryPolicy allows HTTP on
        loopback by default.
        """
        key_dict, pem = rsa_keypair

        disco_response_http = {
            "issuer": "http://external.example.com",
            "authorization_endpoint": "http://external.example.com/authorize",
            "token_endpoint": "http://external.example.com/token",
            "jwks_uri": "http://external.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        token = sign_jwt(
            pem,
            {"sub": "user1", "iss": "http://external.example.com"},
            headers={"kid": "test-key-1"},
        )

        respx.get("http://external.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=disco_response_http)
        )
        respx.get("http://external.example.com/jwks").mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Step 1: Populate cache with require_https=False
        config_permissive = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer="http://external.example.com",
            require_https=False,
        )
        decoded = await async_validate_token(
            jwt=token,
            token_validation_config=config_permissive,
            disco_doc_address="http://external.example.com/.well-known/openid-configuration",
        )
        assert decoded["sub"] == "user1"

        # Step 2: require_https=True must still reject the HTTP address
        config_strict = TokenValidationConfig(
            perform_disco=True,
            audience="test-audience",
            require_https=True,
        )
        with pytest.raises(TokenValidationException, match="HTTPS is required"):
            await async_validate_token(
                jwt="fake.jwt.token",
                token_validation_config=config_strict,
                disco_doc_address="http://external.example.com/.well-known/openid-configuration",
            )


class TestBuildResolvedConfigPreservesRequireHttps:
    """Verify build_resolved_config propagates require_https."""

    def test_require_https_false_preserved(self):
        """build_resolved_config must copy require_https from original config."""
        original = TokenValidationConfig(
            perform_disco=True,
            audience="aud",
            require_https=False,
        )
        resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")
        assert resolved.require_https is False

    def test_require_https_true_preserved(self):
        """build_resolved_config must copy require_https=True (default)."""
        original = TokenValidationConfig(
            perform_disco=True,
            audience="aud",
            require_https=True,
        )
        resolved = build_resolved_config(original, {"kty": "RSA"}, "RS256")
        assert resolved.require_https is True
