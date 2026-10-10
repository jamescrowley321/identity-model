"""
Proves the cache uses per-URI locks rather than a single global lock that
serializes upstream fetches across unrelated issuers.

Pre-fix: a single ``threading.Lock`` (sync) / ``asyncio.Lock`` (async) was
held *across* the upstream HTTP fetch in ``_get_cached_jwks`` /
``_get_disco_response`` / ``_refresh_jwks``. A request fetching JWKS from
``https://idp-a/jwks`` blocked every other request fetching JWKS from any
*other* address until the first request's network round-trip completed.

In a multi-tenant FastAPI app with multiple issuers and a slow upstream
(or one with a momentary glitch) this serialized the entire process on the
slowest fetch, regardless of which issuer the slowness affected.

Post-fix: the cache uses cache-aside with per-URI lock striping (32
stripes). Fetches for distinct URIs run in parallel; only fetches for the
*same* URI serialize, which is the actual single-flight contract.

The tests use a slow handler (sleep) to prove parallelism by wall-clock
total time. We allow a slack margin for scheduling jitter, but the
serialized vs. parallel times differ by ~2x — well outside any noise.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time

import httpx
import pytest
import respx

from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.token_validation import (
    _get_cached_jwks as async_get_cached_jwks,
)
from py_identity_model.aio.token_validation import (
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)

from ..token_validation_helpers import generate_rsa_keypair


@pytest.fixture(autouse=True)
async def _clear_caches():
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


@pytest.fixture
def _distinct_lock_per_uri(monkeypatch):
    """Force each distinct URI to get its own fetch lock for the duration
    of the test, side-stepping ``PYTHONHASHSEED``-driven stripe collisions.

    Runtime stripe selection is ``hash(uri) % 32``. CPython's randomized
    string hashing means two distinct URIs collide on the same stripe with
    probability ~1/32 ≈ 3.1% per process — enough to flake any parallelism
    test that picks two URIs and asserts they run concurrently. Without
    this fixture, the test depends on luck of the hash seed; with it, the
    test is deterministic.

    Applied at the class level via ``pytestmark`` on every class whose
    tests assert distinct-URI parallelism (see #398). Single-URI tests in
    the same class technically don't need it — the fixture is a no-op for
    them — but applying class-wide guarantees future parallelism tests
    added to the class can't accidentally omit it.

    The runtime concern (production fetches for distinct URIs serializing
    on a stripe collision) is the same root cause but explicitly out of
    scope for #398. A follow-up may bump stripe count or switch to a
    ``WeakValueDictionary`` keyed by URI; this fixture only addresses the
    test-side flake.
    """
    sync_locks: dict[str, threading.Lock] = {}
    aio_locks: dict[str, asyncio.Lock] = {}

    def _sync_per_uri(uri: str) -> threading.Lock:
        if uri not in sync_locks:
            sync_locks[uri] = threading.Lock()
        return sync_locks[uri]

    def _aio_per_uri(uri: str) -> asyncio.Lock:
        if uri not in aio_locks:
            aio_locks[uri] = asyncio.Lock()
        return aio_locks[uri]

    monkeypatch.setattr(sync_tv, "_get_jwks_fetch_lock", _sync_per_uri)
    monkeypatch.setattr(aio_tv, "_get_jwks_fetch_lock", _aio_per_uri)


# Per-fetch sleep. Long enough that serialized vs parallel differ by a
# clear margin even with thread scheduling jitter, short enough to keep
# the suite fast.
FETCH_DELAY_SECONDS = 0.4
# Total elapsed must be < 2x delay (parallel) and clearly < the serial
# floor of 2x delay. The threshold lets one full delay fit but rejects two.
PARALLEL_MAX_ELAPSED = FETCH_DELAY_SECONDS * 1.6


def _make_jwks_payload() -> dict:
    key_dict, _ = generate_rsa_keypair()
    return {"keys": [key_dict]}


def _build_slow_handler(payload: dict):
    """Return a respx side_effect that sleeps before responding."""

    def handler(_request: httpx.Request) -> httpx.Response:
        time.sleep(FETCH_DELAY_SECONDS)
        return httpx.Response(200, json=payload)

    return handler


def _build_slow_async_handler(payload: dict):
    async def handler(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(FETCH_DELAY_SECONDS)
        return httpx.Response(200, json=payload)

    return handler


# ============================================================================
# Sync: distinct URIs fetch in parallel (no global serialization)
# ============================================================================


@pytest.mark.usefixtures("_distinct_lock_per_uri")
class TestSyncDistinctUrisParallelizeFetches:
    """Distinct-URI parallelism, sync. Class-level fixture defends every
    test in this class against the ``PYTHONHASHSEED`` flake described in
    #398, including any future tests added below the existing two.
    """

    @respx.mock
    def test_two_distinct_uris_fetch_in_parallel(self):
        url_a = "https://op-a.example/jwks"
        url_b = "https://op-b.example/jwks"
        respx.get(url_a).mock(side_effect=_build_slow_handler(_make_jwks_payload()))
        respx.get(url_b).mock(side_effect=_build_slow_handler(_make_jwks_payload()))

        # Sync the start of both threads via a barrier so we measure
        # actual concurrent fetch behavior, not staggered start jitter.
        barrier = threading.Barrier(2)

        def fetch(url: str) -> None:
            barrier.wait()
            _get_cached_jwks(url)

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(fetch, url_a), pool.submit(fetch, url_b)]
            for f in futures:
                f.result()
        elapsed = time.monotonic() - start

        # Pre-fix would have serialized to ~2x FETCH_DELAY_SECONDS.
        assert elapsed < PARALLEL_MAX_ELAPSED, (
            f"Distinct-URI fetches serialized: elapsed {elapsed:.2f}s, "
            f"expected < {PARALLEL_MAX_ELAPSED:.2f}s. The cache must use "
            "per-URI locking, not a single global lock."
        )

    @respx.mock
    def test_same_uri_still_single_flight(self):
        """The fix must not regress single-flight semantics: two concurrent
        requests for the *same* URI must coalesce into one upstream fetch."""
        url = "https://op-shared.example/jwks"
        route = respx.get(url).mock(
            side_effect=_build_slow_handler(_make_jwks_payload())
        )

        barrier = threading.Barrier(5)

        def fetch() -> None:
            barrier.wait()
            _get_cached_jwks(url)

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(fetch) for _ in range(5)]
            for f in futures:
                f.result()

        # Single-flight: 5 concurrent same-URI requests → 1 upstream fetch.
        assert route.call_count == 1


# ============================================================================
# Async: distinct URIs fetch in parallel
# ============================================================================


@pytest.mark.usefixtures("_distinct_lock_per_uri")
class TestAsyncDistinctUrisParallelizeFetches:
    """Async mirror — see ``TestSyncDistinctUrisParallelizeFetches``."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_two_distinct_uris_fetch_in_parallel_async(self):
        url_a = "https://op-a.example/jwks"
        url_b = "https://op-b.example/jwks"
        respx.get(url_a).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )
        respx.get(url_b).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )

        start = time.monotonic()
        await asyncio.gather(
            async_get_cached_jwks(url_a),
            async_get_cached_jwks(url_b),
        )
        elapsed = time.monotonic() - start

        assert elapsed < PARALLEL_MAX_ELAPSED, (
            f"Distinct-URI async fetches serialized: elapsed {elapsed:.2f}s, "
            f"expected < {PARALLEL_MAX_ELAPSED:.2f}s. The async cache must "
            "use per-URI locks, not a single asyncio.Lock held across await."
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_same_uri_still_single_flight_async(self):
        url = "https://op-shared.example/jwks"
        route = respx.get(url).mock(
            side_effect=_build_slow_async_handler(_make_jwks_payload())
        )

        await asyncio.gather(*(async_get_cached_jwks(url) for _ in range(5)))
        assert route.call_count == 1


# ============================================================================
# Pins the methodology: when two URIs share a stripe (forced via
# monkeypatch, simulating the ``PYTHONHASHSEED`` collision that motivated
# the ``_distinct_lock_per_uri`` fixture), the parallel-fetch test
# methodology MUST be able to detect serialization. Otherwise the
# parallelism tests above could be silently passing for the wrong reason.
#
# This test does NOT use the fixture: it forces every URI to share a
# single lock, which is precisely the worst-case stripe-collision
# scenario the fixture defends against in the other tests.
# ============================================================================


class TestSharedLockProducesSerialization:
    """Negative-direction check: confirms the timing methodology detects
    serialization. Without this, a hypothetical regression that made the
    cache silently serialize everything could slip past the parallel
    tests above if they happened to also stop measuring concurrency
    correctly.
    """

    @respx.mock
    def test_sync_shared_lock_serializes(self, monkeypatch):
        shared_lock = threading.Lock()
        monkeypatch.setattr(sync_tv, "_get_jwks_fetch_lock", lambda _uri: shared_lock)

        url_a = "https://op-a.example/jwks"
        url_b = "https://op-b.example/jwks"
        respx.get(url_a).mock(side_effect=_build_slow_handler(_make_jwks_payload()))
        respx.get(url_b).mock(side_effect=_build_slow_handler(_make_jwks_payload()))

        barrier = threading.Barrier(2)

        def fetch(url: str) -> None:
            barrier.wait()
            _get_cached_jwks(url)

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(fetch, url_a), pool.submit(fetch, url_b)]
            for f in futures:
                f.result()
        elapsed = time.monotonic() - start

        # With a single shared lock, the two fetches MUST serialize.
        # Elapsed must be at least ~2x the single-fetch delay.
        assert elapsed >= FETCH_DELAY_SECONDS * 1.8, (
            f"Methodology check failed: elapsed {elapsed:.2f}s should have "
            f"been ≥ {FETCH_DELAY_SECONDS * 1.8:.2f}s when a shared lock "
            "serializes both fetches."
        )
