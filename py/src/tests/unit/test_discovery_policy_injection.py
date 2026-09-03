"""
Tests for injecting a full DiscoveryPolicy through the cached ``validate_token``
path via ``TokenValidationConfig.discovery_policy``.

Before this, the cached path only threaded the ``require_https`` bool, so a
caller needing any other policy knob (``validate_endpoints``,
``additional_endpoint_base_addresses``, ``authority``, ...) could not use the
built-in discovery/JWKS TTL cache — they had to call ``get_discovery_document``
directly and re-implement caching. These tests pin that the injected policy:

1. reaches the cached discovery/JWKS path (a document the strict default would
   reject now validates), and
2. partitions the cache by the *full* policy, so a response admitted under a
   lax policy is never served to a caller running the strict default
   (policy-bypass prevention — previously guaranteed by keying on
   ``require_https`` alone).
"""

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    clear_discovery_cache as sync_clear_discovery_cache,
)
from py_identity_model.sync.token_validation import (
    clear_jwks_cache as sync_clear_jwks_cache,
)
from py_identity_model.sync.token_validation import (
    validate_token as sync_validate_token,
)

from .token_validation_helpers import generate_rsa_keypair, sign_jwt


# Discovery document whose ``jwks_uri`` lives on a *different* authority than the
# issuer. RFC 8414 / RFC 9126 permit this, but the default policy
# (``validate_endpoints=True``) rejects it unless the CDN host is explicitly
# allow-listed via ``additional_endpoint_base_addresses``. That difference is
# what makes the injected policy observable end-to-end.
ISSUER = "https://issuer.example"
DISCO_ADDR = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = "https://keys.cdn.example/jwks"

DISCO_DOC = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": JWKS_URI,
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

# Policy that admits the cross-authority jwks_uri.
CDN_POLICY = DiscoveryPolicy(
    additional_endpoint_base_addresses=["https://keys.cdn.example"]
)

# The two disco cache keys these tests reason about: the strict default and the
# CDN-allowing policy. They MUST differ, or the cache would not be partitioned.
STRICT_KEY = (DISCO_ADDR, DiscoveryPolicy().cache_key())
CDN_KEY = (DISCO_ADDR, CDN_POLICY.cache_key())


@pytest.fixture(autouse=True)
async def _clear_caches():
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    sync_clear_discovery_cache()
    sync_clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


def _mock_endpoints(key_dict: dict) -> tuple[respx.Route, respx.Route]:
    disco_route = respx.get(DISCO_ADDR).mock(
        return_value=httpx.Response(200, json=DISCO_DOC)
    )
    jwks_route = respx.get(JWKS_URI).mock(
        return_value=httpx.Response(200, json={"keys": [key_dict]})
    )
    return disco_route, jwks_route


def _token(pem: bytes) -> str:
    return sign_jwt(
        pem,
        {"sub": "user1", "iss": ISSUER},
        headers={"kid": "test-key-1"},
    )


def test_keys_differ_by_policy():
    """Sanity guard: the strict and CDN policies produce distinct cache keys.

    If this fails the partitioning tests below are vacuous — a strict caller
    would collide onto the CDN caller's entry.
    """
    assert STRICT_KEY != CDN_KEY


class TestSyncDiscoveryPolicyInjection:
    @respx.mock
    def test_injected_policy_allows_cross_host_jwks_on_cached_path(self):
        """An injected policy reaches the cached path and is reused across calls.

        The document would fail the default strict endpoint-authority check; the
        injected ``additional_endpoint_base_addresses`` makes it pass — and the
        second call is served from the discovery cache (call_count stays 1),
        which is the whole point: no need to re-implement caching.
        """
        key_dict, pem = generate_rsa_keypair()
        disco_route, _ = _mock_endpoints(key_dict)
        token = _token(pem)

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer=ISSUER,
            discovery_policy=CDN_POLICY,
        )

        decoded = sync_validate_token(
            jwt=token, token_validation_config=config, disco_doc_address=DISCO_ADDR
        )
        assert decoded["sub"] == "user1"

        # Second call hits the cache — proves the injected policy uses the
        # built-in TTL cache rather than forcing the caller to reimplement it.
        decoded2 = sync_validate_token(
            jwt=token, token_validation_config=config, disco_doc_address=DISCO_ADDR
        )
        assert decoded2["sub"] == "user1"
        assert disco_route.call_count == 1
        assert CDN_KEY in sync_tv._disco_cache

    @respx.mock
    def test_default_policy_rejects_cross_host_jwks(self):
        """Control: without the injected policy the strict default rejects it.

        Establishes that the acceptance above is caused by the injected policy,
        not by the endpoint being permissible under the default.
        """
        key_dict, pem = generate_rsa_keypair()
        _mock_endpoints(key_dict)
        token = _token(pem)

        config = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)

        with pytest.raises(TokenValidationException, match="authority"):
            sync_validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_ADDR,
            )

    @respx.mock
    def test_cache_partitioned_by_full_policy_no_bypass(self):
        """A lax-policy cache entry must not be served to the strict default.

        Priming the cache with the CDN policy admits the cross-authority
        jwks_uri. A subsequent default-policy call for the *same address* must
        re-validate (different cache key) and reject — proving the cache key
        carries the full policy, not just ``require_https``.
        """
        key_dict, pem = generate_rsa_keypair()
        _mock_endpoints(key_dict)
        token = _token(pem)

        permissive = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer=ISSUER,
            discovery_policy=CDN_POLICY,
        )
        assert (
            sync_validate_token(
                jwt=token,
                token_validation_config=permissive,
                disco_doc_address=DISCO_ADDR,
            )["sub"]
            == "user1"
        )
        assert CDN_KEY in sync_tv._disco_cache

        strict = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)
        with pytest.raises(TokenValidationException, match="authority"):
            sync_validate_token(
                jwt=token,
                token_validation_config=strict,
                disco_doc_address=DISCO_ADDR,
            )
        # The strict caller never got the permissive entry, and its own
        # rejected (unsuccessful) response was not cached.
        assert STRICT_KEY not in sync_tv._disco_cache
        assert CDN_KEY in sync_tv._disco_cache


class TestAsyncDiscoveryPolicyInjection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_injected_policy_allows_cross_host_jwks_on_cached_path(self):
        key_dict, pem = generate_rsa_keypair()
        disco_route, _ = _mock_endpoints(key_dict)
        token = _token(pem)

        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer=ISSUER,
            discovery_policy=CDN_POLICY,
        )

        decoded = await async_validate_token(
            jwt=token, token_validation_config=config, disco_doc_address=DISCO_ADDR
        )
        assert decoded["sub"] == "user1"

        decoded2 = await async_validate_token(
            jwt=token, token_validation_config=config, disco_doc_address=DISCO_ADDR
        )
        assert decoded2["sub"] == "user1"
        assert disco_route.call_count == 1
        assert CDN_KEY in aio_tv._disco_cache

    @pytest.mark.asyncio
    @respx.mock
    async def test_cache_partitioned_by_full_policy_no_bypass(self):
        key_dict, pem = generate_rsa_keypair()
        _mock_endpoints(key_dict)
        token = _token(pem)

        permissive = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            issuer=ISSUER,
            discovery_policy=CDN_POLICY,
        )
        decoded = await async_validate_token(
            jwt=token,
            token_validation_config=permissive,
            disco_doc_address=DISCO_ADDR,
        )
        assert decoded["sub"] == "user1"
        assert CDN_KEY in aio_tv._disco_cache

        strict = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)
        with pytest.raises(TokenValidationException, match="authority"):
            await async_validate_token(
                jwt=token,
                token_validation_config=strict,
                disco_doc_address=DISCO_ADDR,
            )
        assert STRICT_KEY not in aio_tv._disco_cache
        assert CDN_KEY in aio_tv._disco_cache
