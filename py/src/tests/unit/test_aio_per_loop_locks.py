"""
Regression coverage for #399: ``aio/token_validation.py`` must not bind
its cache locks to whichever event loop happens to import the module
first.

Pre-fix: module-level ``asyncio.Lock()`` instances bound to the first
loop that called ``.acquire()`` (Python 3.10+ semantics). Test runners
or embeds that create a new loop per scope (``asyncio.new_event_loop()``,
ASGI servers with custom loop policies, uvicorn workers that recreate
loops between requests) hit:

    RuntimeError: <asyncio.locks.Lock object at 0x...> is bound to a
    different event loop

Post-fix: locks are stored in a ``WeakKeyDictionary`` keyed by the
running event loop and created lazily on first use within that loop.
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


def _reset_aio_lock_state() -> None:
    """Wipe the per-loop lock dicts between tests.

    The WeakKeyDictionary entries would otherwise persist for the
    lifetime of the loop, but the loops we create here are anonymous
    and discarded — manual clearing keeps state predictable for
    successive test runs.
    """
    aio_tv._disco_cache_write_locks.clear()
    aio_tv._disco_fetch_locks_by_loop.clear()
    aio_tv._jwks_cache_write_locks.clear()
    aio_tv._jwks_fetch_locks_by_loop.clear()
    aio_tv._jwks_cache.clear()
    aio_tv._kid_miss_last_attempt.clear()
    aio_tv._disco_cache.clear()


@pytest.fixture(autouse=True)
def _wipe_lock_state():
    _reset_aio_lock_state()
    yield
    _reset_aio_lock_state()


class TestPerLoopLocksAreIndependent:
    @respx.mock
    def test_two_event_loops_each_get_their_own_jwks_fetch_lock(self) -> None:
        """A fresh loop sees a fresh lock — pre-fix this raised
        RuntimeError because the module-level lock was bound to the
        first loop's event loop."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            loop_a.run_until_complete(aio_tv._get_cached_jwks(JWKS_URL))
        finally:
            loop_a.close()

        # Fresh loop, fresh lock set. Pre-fix:
        #   RuntimeError: <Lock> is bound to a different event loop.
        loop_b = asyncio.new_event_loop()
        try:
            response = loop_b.run_until_complete(aio_tv._get_cached_jwks(JWKS_URL))
        finally:
            loop_b.close()

        assert response.is_successful is True
        assert response.keys is not None
        assert len(response.keys) == 1

    def test_per_loop_lock_storage_uses_running_loop_as_key(self) -> None:
        """Calling the accessor from inside a loop registers that loop
        as the key. Two distinct loops produce two distinct lock
        instances."""

        async def grab_locks():
            return (
                aio_tv._get_jwks_cache_write_lock(),
                aio_tv._get_jwks_fetch_lock(JWKS_URL),
                aio_tv._get_disco_cache_write_lock(),
                aio_tv._get_disco_fetch_lock((JWKS_URL, ())),
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

    @respx.mock
    def test_validation_flow_works_across_distinct_loops(self) -> None:
        """End-to-end smoke test: prime cache on one loop, refresh on
        another. Exercises both _get_cached_jwks and _refresh_jwks."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            loop_a.run_until_complete(aio_tv._get_cached_jwks(JWKS_URL))
        finally:
            loop_a.close()

        loop_b = asyncio.new_event_loop()
        try:
            refreshed = loop_b.run_until_complete(aio_tv._refresh_jwks(JWKS_URL))
            # _refresh_jwks may have a tuple or single-value return depending
            # on whether #403 has been merged into this branch. Normalize.
            response = refreshed[0] if isinstance(refreshed, tuple) else refreshed
        finally:
            loop_b.close()

        assert response.is_successful is True

    def test_closed_loop_entries_get_reclaimed(self) -> None:
        """A closed event loop should be removable from the
        WeakKeyDictionary. Pin this so a later refactor can't quietly
        switch to a regular dict and leak loops."""
        loop = asyncio.new_event_loop()
        ref = weakref.ref(loop)

        async def touch():
            # Register the loop in every per-loop dict.
            aio_tv._get_jwks_cache_write_lock()
            aio_tv._get_jwks_fetch_lock("x")
            aio_tv._get_disco_cache_write_lock()
            aio_tv._get_disco_fetch_lock(("x", ()))

        try:
            loop.run_until_complete(touch())
            # Confirm registration happened.
            assert loop in aio_tv._jwks_cache_write_locks
            assert loop in aio_tv._jwks_fetch_locks_by_loop
            assert loop in aio_tv._disco_cache_write_locks
            assert loop in aio_tv._disco_fetch_locks_by_loop
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
    def test_refresh_jwks_works_across_loops(self) -> None:
        """``_refresh_jwks`` acquires both the per-URI fetch lock AND
        the cache write lock. Both must be loop-local."""
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [_make_key()]})
        )

        loop_a = asyncio.new_event_loop()
        try:
            result_a = loop_a.run_until_complete(aio_tv._refresh_jwks(JWKS_URL))
        finally:
            loop_a.close()
        response_a = result_a[0] if isinstance(result_a, tuple) else result_a
        assert response_a.is_successful

        loop_b = asyncio.new_event_loop()
        try:
            result_b = loop_b.run_until_complete(aio_tv._refresh_jwks(JWKS_URL))
        finally:
            loop_b.close()
        response_b = result_b[0] if isinstance(result_b, tuple) else result_b
        assert response_b.is_successful

    def test_clear_jwks_cache_runs_under_fresh_loop(self) -> None:
        """``clear_jwks_cache`` acquires the cache write lock. Running
        it under a brand-new loop pre-fix raised RuntimeError."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(aio_tv.clear_jwks_cache())
        finally:
            loop.close()
        # Reaching here without RuntimeError is the assertion.

    def test_clear_discovery_cache_runs_under_fresh_loop(self) -> None:
        """Mirror of ``test_clear_jwks_cache_runs_under_fresh_loop`` for
        the discovery write lock."""
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(aio_tv.clear_discovery_cache())
        finally:
            loop.close()
