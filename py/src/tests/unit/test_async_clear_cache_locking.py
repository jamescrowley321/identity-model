"""
Proves the async ``clear_*_cache`` helpers acquire the cache write lock
before mutating state, eliminating the race where a coroutine mid-flight
in ``_refresh_jwks`` writes back *after* ``clear()`` runs and leaves the
cleared cache holding a stale entry.

Pre-fix the helpers were sync functions that called ``_cache.clear()``
without acquiring ``_*_cache_write_lock`` (the lock is an
``asyncio.Lock``, which can only be awaited). Post-fix they are async and
``async with`` the lock before clearing.

This is a breaking API change documented in the helper docstrings —
callers must now ``await``. Tests in this file pin the new contract.

See https://github.com/jamescrowley321/identity-model/issues/405
"""

from __future__ import annotations

import asyncio
import inspect

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
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.jwks_cache import DiscoCacheEntry, JwksCacheEntry
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    JsonWebKey,
    JwksResponse,
)


JWKS_URL = "https://example.com/jwks"


# ============================================================================
# Public-API breaking-change contract: these helpers are coroutines now.
# ============================================================================


class TestAsyncClearHelpersAreCoroutines:
    def test_clear_discovery_cache_is_coroutine_function(self):
        assert inspect.iscoroutinefunction(async_clear_discovery_cache)

    def test_clear_jwks_cache_is_coroutine_function(self):
        assert inspect.iscoroutinefunction(async_clear_jwks_cache)

    def test_calling_clear_discovery_without_await_returns_coroutine(self):
        """Calling the helper without ``await`` produces a coroutine object
        — useful diagnostic for users upgrading from the sync version, who
        will get a clear ``RuntimeWarning: coroutine was never awaited``."""
        coroutine = async_clear_discovery_cache()
        assert inspect.iscoroutine(coroutine)
        # Close the coroutine to suppress the never-awaited warning.
        coroutine.close()

    def test_calling_clear_jwks_without_await_returns_coroutine(self):
        coroutine = async_clear_jwks_cache()
        assert inspect.iscoroutine(coroutine)
        coroutine.close()


# ============================================================================
# Functional contract: clear actually clears, even with state present.
# ============================================================================


def _make_jwk_response(kid: str) -> JwksResponse:
    return JwksResponse(
        is_successful=True,
        keys=[JsonWebKey(kty="RSA", kid=kid, alg="RS256", use="sig", n="n", e="AQAB")],
        cache_control="max-age=3600",
    )


class TestAsyncClearActuallyClears:
    @pytest.mark.asyncio
    async def test_clear_jwks_cache_empties_cache_and_cooldown(self):
        # Prime the cache + cooldown sidecar directly so the test doesn't
        # depend on the full refresh pipeline.
        aio_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=_make_jwk_response("primed"),
            cached_at=0.0,
            ttl=3600.0,
        )
        aio_tv._kid_miss_last_attempt[JWKS_URL] = 100.0
        assert JWKS_URL in aio_tv._jwks_cache
        assert JWKS_URL in aio_tv._kid_miss_last_attempt

        await async_clear_jwks_cache()

        assert aio_tv._jwks_cache == {}
        assert aio_tv._kid_miss_last_attempt == {}

    @pytest.mark.asyncio
    async def test_clear_discovery_cache_empties_cache(self):
        cache_key = (
            "https://example.com/.well-known/openid-configuration",
            DiscoveryPolicy().cache_key(),
        )
        aio_tv._disco_cache[cache_key] = DiscoCacheEntry(
            response=DiscoveryDocumentResponse(is_successful=True),
            cached_at=0.0,
            ttl=3600.0,
        )
        assert cache_key in aio_tv._disco_cache

        await async_clear_discovery_cache()

        assert aio_tv._disco_cache == {}


# ============================================================================
# Race-condition contract: a coroutine mid-flight in _refresh_jwks must not
# leak its post-write back into a cache that was cleared while the fetch
# was in flight.
#
# We can't reliably interleave a real HTTP fetch with a clear in unit-test
# wall-clock terms, so the test uses a controlled handler that blocks on
# an event the test holds. The sequence:
#
#   1. Coroutine R starts _refresh_jwks. Fetch handler blocks on EVENT_A.
#   2. Test releases EVENT_A → handler returns response.
#   3. Test (concurrently) awaits clear_jwks_cache while R is still in the
#      post-fetch apply_jwks_cache_outcome step — the clear must wait on
#      the lock R is holding.
#
# Verifies clear waits for R's critical section, so the post-clear cache
# state is fully clear, not "cleared then R re-wrote".
# ============================================================================


class TestAsyncClearWaitsForInFlightRefresh:
    @pytest.mark.asyncio
    @respx.mock
    async def test_clear_blocks_until_in_flight_refresh_completes(self):
        """If clear_jwks_cache did NOT acquire _jwks_cache_write_lock, it
        could complete *before* the in-flight _refresh_jwks's
        apply_jwks_cache_outcome write, leaving an entry in the "cleared"
        cache. Post-fix the lock serializes them."""
        # Prime with one entry so we know it gets cleared.
        aio_tv._jwks_cache["https://op.example/primed"] = JwksCacheEntry(
            response=_make_jwk_response("primed-kid"),
            cached_at=0.0,
            ttl=3600.0,
        )

        # The handler waits on this event before responding, letting the
        # test orchestrate the "in-flight refresh" + "clear" interleave.
        proceed = asyncio.Event()

        async def slow_handler(_request: httpx.Request) -> httpx.Response:
            await proceed.wait()
            return httpx.Response(
                200,
                json={
                    "keys": [
                        {
                            "kty": "RSA",
                            "kid": "fresh-kid",
                            "alg": "RS256",
                            "use": "sig",
                            "n": "n",
                            "e": "AQAB",
                        }
                    ]
                },
            )

        respx.get(JWKS_URL).mock(side_effect=slow_handler)

        # Start the refresh coroutine — it will block waiting on `proceed`.
        refresh_task = asyncio.create_task(aio_tv._refresh_jwks(JWKS_URL))
        # Let the refresh coroutine reach the await on `proceed`.
        await asyncio.sleep(0)

        # Release the handler so the refresh completes its fetch and runs
        # apply_jwks_cache_outcome (which acquires _jwks_cache_write_lock).
        proceed.set()

        # Now concurrently clear. The clear must serialize after the
        # refresh's lock-holding critical section.
        await asyncio.gather(refresh_task, async_clear_jwks_cache())

        # Net effect: clear ran AFTER refresh's apply_outcome under the
        # same lock, so the cache is fully empty — the refresh's write is
        # not re-introduced after clear.
        assert aio_tv._jwks_cache == {}
        assert aio_tv._kid_miss_last_attempt == {}
