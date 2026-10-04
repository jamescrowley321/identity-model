# ruff: noqa: PLR2004
"""Unit tests for the per-process cache observability counters.

Covers :class:`CacheCounters` in isolation (every ``record_*`` method,
``snapshot`` detachment, ``reset``, thread-safety smoke) and its integration
with the async discovery/JWKS cache paths, asserting exact hit/miss/refresh
transitions across warm/cold/refresh scenarios.
"""

import threading

import httpx
import pytest
import respx

from py_identity_model import CacheCounters, get_cache_counters
from py_identity_model.aio.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.core.cache_metrics import CACHE_COUNTERS

from ..constants import DISCO_URL
from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
)


# ============================================================================
# CacheCounters in isolation
# ============================================================================


class TestCacheCountersUnit:
    """Exercise every CacheCounters method without any cache I/O."""

    def test_starts_at_zero(self):
        counters = CacheCounters()
        assert counters.snapshot() == {
            "disco_hits": 0,
            "disco_misses": 0,
            "jwks_hits": 0,
            "jwks_misses": 0,
            "jwks_refreshes": 0,
        }

    def test_record_disco_hit(self):
        counters = CacheCounters()
        counters.record_disco_hit()
        counters.record_disco_hit()
        assert counters.snapshot()["disco_hits"] == 2

    def test_record_disco_miss(self):
        counters = CacheCounters()
        counters.record_disco_miss()
        assert counters.snapshot()["disco_misses"] == 1

    def test_record_jwks_hit(self):
        counters = CacheCounters()
        counters.record_jwks_hit()
        counters.record_jwks_hit()
        counters.record_jwks_hit()
        assert counters.snapshot()["jwks_hits"] == 3

    def test_record_jwks_miss(self):
        counters = CacheCounters()
        counters.record_jwks_miss()
        assert counters.snapshot()["jwks_misses"] == 1

    def test_record_jwks_refresh(self):
        counters = CacheCounters()
        counters.record_jwks_refresh()
        counters.record_jwks_refresh()
        assert counters.snapshot()["jwks_refreshes"] == 2

    def test_each_counter_is_independent(self):
        counters = CacheCounters()
        counters.record_disco_hit()
        counters.record_disco_miss()
        counters.record_jwks_hit()
        counters.record_jwks_miss()
        counters.record_jwks_refresh()
        assert counters.snapshot() == {
            "disco_hits": 1,
            "disco_misses": 1,
            "jwks_hits": 1,
            "jwks_misses": 1,
            "jwks_refreshes": 1,
        }

    def test_snapshot_is_detached_copy(self):
        counters = CacheCounters()
        counters.record_disco_hit()
        snap = counters.snapshot()
        # Mutating the snapshot must not touch the live counters...
        snap["disco_hits"] = 999
        assert counters.snapshot()["disco_hits"] == 1
        # ...and the live counters advancing must not touch an old snapshot.
        counters.record_disco_hit()
        assert snap["disco_hits"] == 999

    def test_reset_zeros_every_counter(self):
        counters = CacheCounters()
        counters.record_disco_hit()
        counters.record_disco_miss()
        counters.record_jwks_hit()
        counters.record_jwks_miss()
        counters.record_jwks_refresh()
        counters.reset()
        assert counters.snapshot() == {
            "disco_hits": 0,
            "disco_misses": 0,
            "jwks_hits": 0,
            "jwks_misses": 0,
            "jwks_refreshes": 0,
        }

    def test_concurrent_increments_are_not_lost(self):
        """Thread-safety smoke: N threads each incrementing must total N*loops."""
        counters = CacheCounters()
        threads_count = 8
        per_thread = 1000

        def worker():
            for _ in range(per_thread):
                counters.record_jwks_hit()

        threads = [threading.Thread(target=worker) for _ in range(threads_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counters.snapshot()["jwks_hits"] == threads_count * per_thread


class TestCacheCountersSingleton:
    """The module singleton is shared and reachable from the public surface."""

    def test_get_cache_counters_returns_singleton(self):
        assert get_cache_counters() is CACHE_COUNTERS
        assert get_cache_counters() is get_cache_counters()

    def test_singleton_is_a_cache_counters(self):
        assert isinstance(get_cache_counters(), CacheCounters)


# ============================================================================
# Integration with the async cache paths
# ============================================================================

JWKS_URL = "https://example.com/jwks"


@pytest.fixture
async def _clean_cache_state():
    """Reset caches and counters around each async integration test."""
    await clear_discovery_cache()
    await clear_jwks_cache()
    get_cache_counters().reset()
    yield
    await clear_discovery_cache()
    await clear_jwks_cache()
    get_cache_counters().reset()


@pytest.mark.usefixtures("_clean_cache_state")
class TestCacheCountersIntegration:
    """Drive the real async cache functions and assert exact counter moves."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_miss_then_hit(self):
        route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # First call: cold cache → upstream fetch → one miss, no hits.
        await _get_disco_response(DISCO_URL)
        snap = get_cache_counters().snapshot()
        assert snap["disco_misses"] == 1
        assert snap["disco_hits"] == 0

        # Second call: fresh entry → hit, no additional upstream fetch.
        await _get_disco_response(DISCO_URL)
        snap = get_cache_counters().snapshot()
        assert snap["disco_misses"] == 1
        assert snap["disco_hits"] == 1
        assert route.call_count == 1  # the hit did NOT hit the network

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_miss_then_hit(self):
        key_dict, _pem = generate_rsa_keypair()
        route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        await _get_cached_jwks(JWKS_URL)
        snap = get_cache_counters().snapshot()
        assert snap["jwks_misses"] == 1
        assert snap["jwks_hits"] == 0

        await _get_cached_jwks(JWKS_URL)
        snap = get_cache_counters().snapshot()
        assert snap["jwks_misses"] == 1
        assert snap["jwks_hits"] == 1
        assert route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_counts_upstream_fetch(self):
        key_dict, _pem = generate_rsa_keypair()
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache (miss), then force a refresh (key rotation).
        await _get_cached_jwks(JWKS_URL)
        assert get_cache_counters().snapshot()["jwks_refreshes"] == 0

        await _refresh_jwks(JWKS_URL)
        snap = get_cache_counters().snapshot()
        assert snap["jwks_refreshes"] == 1
        # A refresh is an upstream re-fetch, not a hit.
        assert snap["jwks_hits"] == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_failed_upstream_fetch_counts_as_miss(self):
        """A 503 from upstream is a real round trip → it MUST count as a miss.

        Guards against the regression where gating the counter on
        ``response.is_successful`` silently dropped 429/5xx fetches, making an
        upstream outage read as zero upstream volume (design §5 metric).
        """
        route = respx.get(DISCO_URL).mock(return_value=httpx.Response(503))

        result = await _get_disco_response(DISCO_URL)
        snap = get_cache_counters().snapshot()

        assert result.is_successful is False
        assert route.called  # a real network round trip happened (with retries)
        assert snap["disco_misses"] == 1  # one logical fetch, counted once
        assert snap["disco_hits"] == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_failed_upstream_fetch_counts_as_miss(self):
        """A 429 JWKS fetch is a real round trip → counted as a miss."""
        route = respx.get(JWKS_URL).mock(return_value=httpx.Response(429))

        result = await _get_cached_jwks(JWKS_URL)
        snap = get_cache_counters().snapshot()

        assert result.is_successful is False
        assert route.called  # a real network round trip happened (with retries)
        assert snap["jwks_misses"] == 1  # one logical fetch, counted once
        assert snap["jwks_hits"] == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_failed_refresh_counts_as_refresh(self):
        """A refresh whose upstream GET returns 5xx is still an upstream re-fetch."""
        key_dict, _pem = generate_rsa_keypair()
        route = respx.get(JWKS_URL).mock(
            side_effect=[
                httpx.Response(200, json={"keys": [key_dict]}),
                httpx.Response(502),
            ]
        )

        await _get_cached_jwks(JWKS_URL)  # prime (miss)
        get_cache_counters().reset()

        await _refresh_jwks(JWKS_URL)  # forced re-fetch → 502
        snap = get_cache_counters().snapshot()

        assert route.call_count == 2
        assert snap["jwks_refreshes"] == 1  # counted despite the 502
