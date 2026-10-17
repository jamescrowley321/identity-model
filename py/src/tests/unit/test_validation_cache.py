"""
The discovery/JWKS caches and the kid-miss cooldown live on a
``ValidationCache`` / ``AsyncValidationCache``, not on the HTTP clients (#953).

Pins the contract:
- HTTP clients hold no cache.
- The cooldown survives short-lived clients (#945): a client built per
  request still shares the cache, so an attacker spraying random ``kid``
  values cannot drive one upstream JWKS fetch per request.
- An injected cache is isolated from the default one, and its own ``Config``
  sets the TTLs, size and cooldown. The client's ``Config`` does not.
- The process-wide defaults (cache and HTTP clients) are rebuilt in a forked
  child, never shared with the parent.
- Nothing loop-bound is shared across event loops: the default async client
  and the default async cache work, and shut down, on two loops in turn
  (#944).
"""

import asyncio
import os
import warnings

import httpx
import pytest
import respx

from py_identity_model import Config, ValidationCache, get_default_validation_cache
from py_identity_model.aio import (
    AsyncValidationCache,
    get_default_async_validation_cache,
)
from py_identity_model.aio import http_client as aio_http_client
from py_identity_model.aio.http_client import (
    close_async_http_client,
    get_default_async_http_client,
)
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.aio.token_validation import (
    validate_token as async_validate_token,
)
from py_identity_model.aio.validation_cache import (
    _reset_default_async_validation_cache,
)
from py_identity_model.core.jwks_cache import MAX_KID_MISS_COOLDOWN_SECONDS
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync.http_client import get_default_http_client
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import validate_token
from py_identity_model.sync.validation_cache import _reset_default_validation_cache

from ..constants import DISCO_URL, ISSUER
from ..token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


JWKS_URL = DISCO_RESPONSE_WITH_JWKS["jwks_uri"]
ATTACKER_REQUEST_COUNT = 10
# One fetch to prime the cache, one forced refresh for the first unknown kid;
# every later unknown kid is inside the cooldown window.
PRIME_AND_ONE_REFRESH = 2
HIGH_COOLDOWN = Config(jwks_kid_miss_cooldown=MAX_KID_MISS_COOLDOWN_SECONDS)
VALIDATION = TokenValidationConfig(perform_disco=True, audience=None, issuer=ISSUER)
CACHE_JWKS_TTL = 600.0
CLIENT_JWKS_TTL = 60.0


def _unknown_kid_tokens(count: int = ATTACKER_REQUEST_COUNT) -> list[str]:
    """Tokens whose ``kid`` names no key the provider publishes."""
    _, pem = generate_rsa_keypair()
    return [
        sign_jwt(pem, {"sub": "attacker", "iss": ISSUER}, headers={"kid": f"k-{i}"})
        for i in range(count)
    ]


def _mock_provider() -> respx.Route:
    """Mock discovery and a one-key JWKS; return the JWKS route."""
    key, _ = generate_rsa_keypair()
    key["kid"] = "provider-kid"
    respx.get(DISCO_URL).mock(
        return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
    )
    return respx.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json={"keys": [key]})
    )


@pytest.fixture
def high_cooldown_default_caches():
    """Default caches built from ``HIGH_COOLDOWN``; plain defaults restored after."""
    _reset_default_validation_cache(HIGH_COOLDOWN)
    _reset_default_async_validation_cache(HIGH_COOLDOWN)
    yield
    _reset_default_validation_cache()
    _reset_default_async_validation_cache()


class TestClientsHoldNoCache:
    def test_sync_client_has_no_caches(self):
        with HTTPClient() as client:
            assert not hasattr(client, "caches")
        assert not hasattr(get_default_http_client(), "caches")

    async def test_async_client_has_no_caches(self):
        async with AsyncHTTPClient() as client:
            assert not hasattr(client, "caches")
        assert not hasattr(get_default_async_http_client(), "caches")


class TestCooldownSurvivesShortLivedClients:
    @respx.mock
    @pytest.mark.usefixtures("high_cooldown_default_caches")
    def test_sync_client_per_request_shares_default_cooldown(self):
        jwks_route = _mock_provider()
        rejected = 0
        for token in _unknown_kid_tokens():
            with HTTPClient() as client:
                try:
                    validate_token(token, VALIDATION, DISCO_URL, http_client=client)
                except TokenValidationException:
                    rejected += 1
        assert rejected == ATTACKER_REQUEST_COUNT
        assert jwks_route.call_count == PRIME_AND_ONE_REFRESH

    @respx.mock
    @pytest.mark.usefixtures("high_cooldown_default_caches")
    async def test_async_client_per_request_shares_default_cooldown(self):
        jwks_route = _mock_provider()
        rejected = 0
        for token in _unknown_kid_tokens():
            async with AsyncHTTPClient() as client:
                try:
                    await async_validate_token(
                        token, VALIDATION, DISCO_URL, http_client=client
                    )
                except TokenValidationException:
                    rejected += 1
        assert rejected == ATTACKER_REQUEST_COUNT
        assert jwks_route.call_count == PRIME_AND_ONE_REFRESH

    @respx.mock
    def test_sync_injected_cache_shared_by_short_lived_clients(self):
        jwks_route = _mock_provider()
        cache = ValidationCache(config=HIGH_COOLDOWN)
        for token in _unknown_kid_tokens():
            with HTTPClient() as client, pytest.raises(TokenValidationException):
                validate_token(
                    token, VALIDATION, DISCO_URL, http_client=client, cache=cache
                )
        assert jwks_route.call_count == PRIME_AND_ONE_REFRESH
        assert list(cache.kid_miss_last_attempt) == [JWKS_URL]

    @respx.mock
    async def test_async_injected_cache_shared_by_short_lived_clients(self):
        jwks_route = _mock_provider()
        cache = AsyncValidationCache(config=HIGH_COOLDOWN)
        for token in _unknown_kid_tokens():
            async with AsyncHTTPClient() as client:
                with pytest.raises(TokenValidationException):
                    await async_validate_token(
                        token, VALIDATION, DISCO_URL, http_client=client, cache=cache
                    )
        assert jwks_route.call_count == PRIME_AND_ONE_REFRESH
        assert list(cache.kid_miss_last_attempt) == [JWKS_URL]


class TestInjectedCache:
    @respx.mock
    def test_sync_cache_config_sets_ttl_not_client_config(self):
        _mock_provider()
        cache = ValidationCache(config=Config(jwks_cache_ttl=CACHE_JWKS_TTL))
        [token] = _unknown_kid_tokens(count=1)
        with (
            HTTPClient(config=Config(jwks_cache_ttl=CLIENT_JWKS_TTL)) as client,
            pytest.raises(TokenValidationException),
        ):
            validate_token(
                token, VALIDATION, DISCO_URL, http_client=client, cache=cache
            )
        assert cache.jwks[JWKS_URL].ttl == CACHE_JWKS_TTL
        assert JWKS_URL not in get_default_validation_cache().jwks

    @respx.mock
    async def test_async_cache_config_sets_ttl_not_client_config(self):
        _mock_provider()
        cache = AsyncValidationCache(config=Config(jwks_cache_ttl=CACHE_JWKS_TTL))
        [token] = _unknown_kid_tokens(count=1)
        async with AsyncHTTPClient(
            config=Config(jwks_cache_ttl=CLIENT_JWKS_TTL)
        ) as client:
            with pytest.raises(TokenValidationException):
                await async_validate_token(
                    token, VALIDATION, DISCO_URL, http_client=client, cache=cache
                )
        assert cache.jwks[JWKS_URL].ttl == CACHE_JWKS_TTL
        assert JWKS_URL not in get_default_async_validation_cache().jwks

    def test_config_defaults_to_config_defaults(self):
        assert ValidationCache().config == Config()
        assert AsyncValidationCache().config == Config()

    def test_default_cache_is_one_object_per_process(self):
        assert get_default_validation_cache() is get_default_validation_cache()
        assert (
            get_default_async_validation_cache() is get_default_async_validation_cache()
        )


def _fork_and_check(check) -> int:
    """Run *check* in a forked child; return the child's exit status.

    The child exits 0 when *check* returns True, 1 when it returns False and
    2 when it raises. ``os._exit`` skips the parent's atexit handlers and
    pytest teardown in the child.
    """
    with warnings.catch_warnings():
        # Python warns on fork() in a multi-threaded process; the child only
        # runs *check* and exits.
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        try:
            code = 0 if check() else 1
        except BaseException:
            code = 2
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
class TestForkResetsDefaults:
    def test_default_cache_is_rebuilt_in_child(self):
        parent_cache = get_default_validation_cache()
        parent_cache.kid_miss_last_attempt[JWKS_URL] = 1.0
        try:

            def check() -> bool:
                child_cache = get_default_validation_cache()
                return (
                    child_cache is not parent_cache
                    and child_cache.kid_miss_last_attempt == {}
                    and get_default_validation_cache() is child_cache
                )

            assert _fork_and_check(check) == 0
            assert get_default_validation_cache() is parent_cache
        finally:
            parent_cache.kid_miss_last_attempt.clear()

    def test_default_async_cache_is_rebuilt_in_child(self):
        parent_cache = get_default_async_validation_cache()

        def check() -> bool:
            return get_default_async_validation_cache() is not parent_cache

        assert _fork_and_check(check) == 0
        assert get_default_async_validation_cache() is parent_cache

    def test_default_http_clients_are_rebuilt_in_child(self):
        parent_sync = get_default_http_client()
        parent_sync_httpx = parent_sync.client
        parent_async = get_default_async_http_client()

        def check() -> bool:
            child_sync = get_default_http_client()
            return (
                child_sync is not parent_sync
                and child_sync.client is not parent_sync_httpx
                and child_sync.config == parent_sync.config
                and get_default_async_http_client() is not parent_async
            )

        assert _fork_and_check(check) == 0
        # The child dropped the parent's clients without closing them.
        assert get_default_http_client() is parent_sync
        assert not parent_sync_httpx.is_closed


class _SlowCloseTransport(httpx.AsyncBaseTransport):
    """A transport whose ``aclose`` yields, so concurrent closes overlap."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request)

    async def aclose(self) -> None:
        await asyncio.sleep(0)


class TestTwoEventLoops:
    def test_default_async_client_closes_on_two_loops(self, monkeypatch):
        monkeypatch.setattr(
            aio_http_client,
            "build_async_httpx_client",
            lambda _config: httpx.AsyncClient(transport=_SlowCloseTransport()),
        )

        async def use_then_close() -> None:
            await get_default_async_http_client().client.get("https://example.com/")
            await asyncio.gather(close_async_http_client(), close_async_http_client())

        asyncio.run(use_then_close())
        asyncio.run(use_then_close())

    def test_default_async_cache_on_two_loops(self):
        async def validate_then_clear() -> int:
            with respx.mock:
                jwks_route = _mock_provider()
                [token] = _unknown_kid_tokens(count=1)
                results = await asyncio.gather(
                    *(
                        async_validate_token(token, VALIDATION, DISCO_URL)
                        for _ in range(3)
                    ),
                    return_exceptions=True,
                )
                assert all(isinstance(r, TokenValidationException) for r in results)
                await asyncio.gather(async_clear_jwks_cache(), async_clear_jwks_cache())
                await close_async_http_client()
                return jwks_route.call_count

        _reset_default_async_validation_cache(HIGH_COOLDOWN)
        try:
            # Each loop starts from a cleared JWKS cache: one prime, one refresh.
            assert asyncio.run(validate_then_clear()) == PRIME_AND_ONE_REFRESH
            assert asyncio.run(validate_then_clear()) == PRIME_AND_ONE_REFRESH
        finally:
            _reset_default_async_validation_cache()


ONE_HOUR_SECONDS = 3600.0


class TestJwksFallbackTtl:
    """Without ``Cache-Control``, a JWKS is kept for one hour (#953), so a key
    the provider pulls stops validating within the hour."""

    @respx.mock
    def test_sync_jwks_without_cache_control_is_kept_one_hour(self):
        _mock_provider()
        cache = ValidationCache()
        [token] = _unknown_kid_tokens(count=1)
        with pytest.raises(TokenValidationException):
            validate_token(token, VALIDATION, DISCO_URL, cache=cache)
        assert cache.jwks[JWKS_URL].ttl == ONE_HOUR_SECONDS

    @respx.mock
    async def test_async_jwks_without_cache_control_is_kept_one_hour(self):
        _mock_provider()
        cache = AsyncValidationCache()
        [token] = _unknown_kid_tokens(count=1)
        with pytest.raises(TokenValidationException):
            await async_validate_token(token, VALIDATION, DISCO_URL, cache=cache)
        assert cache.jwks[JWKS_URL].ttl == ONE_HOUR_SECONDS
