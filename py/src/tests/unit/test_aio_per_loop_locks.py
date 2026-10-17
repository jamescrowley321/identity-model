"""
Regression coverage for #399: the async cache locks must not bind to
whichever event loop happens to use them first.

Pre-fix: module-level ``asyncio.Lock()`` instances bound to the first
loop that called ``.acquire()`` (Python 3.10+ semantics). Test runners
or embeds that create a new loop per scope (``asyncio.new_event_loop()``,
ASGI servers with custom loop policies, uvicorn workers that recreate
loops between requests) hit:

    RuntimeError: <asyncio.locks.Lock object at 0x...> is bound to a
    different event loop

Post-fix: locks are stored in a ``WeakKeyDictionary`` keyed by the
running event loop (since #953 per cache, in ``AsyncValidationCache``) and
created lazily on first use within that loop.
Each loop sees its own independent lock set; entries are reclaimed when
a loop is garbage-collected.

These tests exercise the multi-loop scenario directly:

1. Run a validation flow on loop A.
2. Close loop A and open a fresh loop B.
3. Run the same operations on loop B without the dreaded RuntimeError.

The pre-fix code raises on step 3; the post-fix code completes both
flows cleanly.
"""

from __future__ import annotations

import asyncio
import weakref

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.validation_cache import AsyncValidationCache

from ..token_validation_helpers import disco_cache_key, jwks_cache_key


JWKS_URL = "https://issuer.example/jwks"


def _make_key() -> dict:
    # Minimal RSA JWK shape — only the *parsing* path is exercised here.
    # generate_rsa_keypair() would be heavier than necessary.
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key",
        "n": "example_n",
        "e": "AQAB",
    }


@pytest.fixture
def client() -> AsyncHTTPClient:
    """A fresh client per test.

    The client is used across several anonymous event loops, so it is not
    closed here; respx mocks the transport, so no sockets are opened.
    """
    return AsyncHTTPClient()


@pytest.fixture
def cache() -> AsyncValidationCache:
    """A fresh cache per test: its entries and per-loop lock sets start empty."""
    return AsyncValidationCache()


class TestPerLoopLocksAreIndependent:
    @respx.mock
    def test_two_event_loops_each_get_their_own_jwks_fetch_lock(
        self, client: AsyncHTTPClient, cache: AsyncValidationCache
    ) -> None:
        """A fresh loop sees a fresh lock — pre-fix this raised
        RuntimeError because the module-level lock was bound to the
        first loop's event loop."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            loop_a.run_until_complete(
                aio_tv._get_cached_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_a.close()

        # Fresh loop, fresh lock set. Pre-fix:
        #   RuntimeError: <Lock> is bound to a different event loop.
        loop_b = asyncio.new_event_loop()
        try:
            response = loop_b.run_until_complete(
                aio_tv._get_cached_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_b.close()

        assert response.is_successful is True
        assert response.keys is not None
        assert len(response.keys) == 1

    def test_per_loop_lock_storage_uses_running_loop_as_key(
        self, cache: AsyncValidationCache
    ) -> None:
        """Calling the accessor from inside a loop registers that loop
        as the key. Two distinct loops produce two distinct lock
        instances."""

        async def grab_locks():
            return (
                cache.jwks_write_lock(),
                cache.jwks_fetch_lock(jwks_cache_key(JWKS_URL)),
                cache.disco_write_lock(),
                cache.disco_fetch_lock(disco_cache_key(JWKS_URL)),
            )

        loop_a = asyncio.new_event_loop()
        try:
            locks_a = loop_a.run_until_complete(grab_locks())
        finally:
            loop_a.close()

        loop_b = asyncio.new_event_loop()
        try:
            locks_b = loop_b.run_until_complete(grab_locks())
        finally:
            loop_b.close()

        # Each lock is a separate instance per loop.
        for la, lb in zip(locks_a, locks_b, strict=True):
            assert la is not lb, (
                "Per-loop locks must be distinct across loops; pre-fix "
                "behavior would return the same module-level instance."
            )

    def test_same_loop_reuses_its_locks(self) -> None:
        """Within one loop the accessors return the same instances, so
        concurrent coroutines on that loop really serialize on them."""
        cache = AsyncValidationCache()

        async def grab_locks():
            return (
                cache.jwks_write_lock(),
                cache.jwks_fetch_lock(jwks_cache_key(JWKS_URL)),
                cache.disco_write_lock(),
                cache.disco_fetch_lock(disco_cache_key(JWKS_URL)),
            )

        async def grab_twice():
            return await grab_locks(), await grab_locks()

        loop = asyncio.new_event_loop()
        try:
            first, second = loop.run_until_complete(grab_twice())
        finally:
            loop.close()

        for lock_first, lock_second in zip(first, second, strict=True):
            assert lock_first is lock_second

    def test_two_caches_have_independent_lock_sets(self) -> None:
        """Locks live on each cache, not at module level."""
        cache_a = AsyncValidationCache()
        cache_b = AsyncValidationCache()

        async def grab_both():
            return cache_a.jwks_write_lock(), cache_b.jwks_write_lock()

        loop = asyncio.new_event_loop()
        try:
            lock_a, lock_b = loop.run_until_complete(grab_both())
        finally:
            loop.close()

        assert lock_a is not lock_b

    @respx.mock
    def test_validation_flow_works_across_distinct_loops(
        self, client: AsyncHTTPClient, cache: AsyncValidationCache
    ) -> None:
        """End-to-end smoke test: prime cache on one loop, refresh on
        another. Exercises both _get_cached_jwks and _refresh_jwks."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            loop_a.run_until_complete(
                aio_tv._get_cached_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_a.close()

        loop_b = asyncio.new_event_loop()
        try:
            response, _ = loop_b.run_until_complete(
                aio_tv._refresh_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_b.close()

        assert response.is_successful is True

    def test_closed_loop_entries_get_reclaimed(
        self, cache: AsyncValidationCache
    ) -> None:
        """A closed event loop should be removable from the
        WeakKeyDictionary. Pin this so a later refactor can't quietly
        switch to a regular dict and leak loops."""
        loop = asyncio.new_event_loop()
        ref = weakref.ref(loop)

        async def touch():
            # Register the loop in every per-loop dict.
            cache.jwks_write_lock()
            cache.jwks_fetch_lock(jwks_cache_key("x"))
            cache.disco_write_lock()
            cache.disco_fetch_lock(disco_cache_key("x"))

        try:
            loop.run_until_complete(touch())
            # Confirm registration happened.
            assert loop in cache._jwks_locks._write
            assert loop in cache._jwks_locks._fetch
            assert loop in cache._disco_locks._write
            assert loop in cache._disco_locks._fetch
        finally:
            loop.close()

        # Drop the strong reference and force GC.
        del loop
        import gc  # noqa: PLC0415

        gc.collect()

        # The weak reference should be dead — the WeakKeyDictionary lets
        # the loop be reclaimed despite our previous registrations.
        assert ref() is None, (
            "Per-loop lock storage must use WeakKeyDictionary so closed "
            "loops are reclaimed; a strong-ref dict would leak loops."
        )

    @respx.mock
    def test_refresh_jwks_works_across_loops(
        self, client: AsyncHTTPClient, cache: AsyncValidationCache
    ) -> None:
        """``_refresh_jwks`` acquires both the per-URI fetch lock AND
        the cache write lock. Both must be loop-local."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            response_a, _ = loop_a.run_until_complete(
                aio_tv._refresh_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_a.close()
        assert response_a.is_successful

        loop_b = asyncio.new_event_loop()
        try:
            response_b, _ = loop_b.run_until_complete(
                aio_tv._refresh_jwks(JWKS_URL, http_client=client, cache=cache)
            )
        finally:
            loop_b.close()
        assert response_b.is_successful

    def test_clear_jwks_cache_runs_under_fresh_loop(
        self, cache: AsyncValidationCache
    ) -> None:
        """``clear_jwks_cache`` acquires the cache write lock. Running
        it under a brand-new loop pre-fix raised RuntimeError."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(aio_tv.clear_jwks_cache(cache=cache))
        finally:
            loop.close()
        # Reaching here without RuntimeError is the assertion.

    def test_clear_discovery_cache_runs_under_fresh_loop(
        self, cache: AsyncValidationCache
    ) -> None:
        """Mirror of ``test_clear_jwks_cache_runs_under_fresh_loop`` for
        the discovery write lock."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(aio_tv.clear_discovery_cache(cache=cache))
        finally:
            loop.close()

    def test_default_cache_clear_runs_under_fresh_loops(self) -> None:
        """The library default cache (no ``cache=``) uses the same
        per-loop locks: clearing it on two fresh loops must not raise."""
        for _loop_name in ("loop_a", "loop_b"):
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(aio_tv.clear_jwks_cache())
                loop.run_until_complete(aio_tv.clear_discovery_cache())
            finally:
                loop.close()
