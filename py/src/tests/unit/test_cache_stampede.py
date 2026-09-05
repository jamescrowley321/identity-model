"""
Security tests for cache stampede prevention (#378).

Verifies that concurrent cache misses (TTL expiry) result in a single HTTP
fetch rather than N parallel fetches (thundering herd).
"""

import asyncio
from collections.abc import Callable
import logging
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
    _get_disco_response as async_get_disco_response,
)
from py_identity_model.aio.token_validation import (
    _refresh_jwks as async_refresh_jwks,
)
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
from py_identity_model.core.jwks_cache import DiscoCacheEntry, JwksCacheEntry
from py_identity_model.core.models import TokenValidationConfig
from py_identity_model.exceptions import TokenValidationException
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
    validate_token,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
    sign_jwt,
)


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/jwks"
# Second element of the disco cache key for the default (strict) policy.
_STRICT_DISCO_KEY = DiscoveryPolicy().cache_key()

# Expected fetch counts: 1 initial prime + 1 single-flight refresh after expiry
FETCH_AFTER_EXPIRY = 2


@pytest.fixture(autouse=True)
async def _clear_caches():
    """Clear all caches between tests."""
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    await async_clear_discovery_cache()
    await async_clear_jwks_cache()


class TestSyncDiscoCacheStampede:
    """Verify sync discovery cache prevents thundering herd on TTL expiry."""

    @respx.mock
    def test_disco_cache_stampede_blocked(self):
        """Multiple threads hitting expired cache produce only 1 HTTP fetch."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        barrier = threading.Barrier(5, timeout=5)
        results: list[object] = [None] * 5
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                results[idx] = _get_disco_response(DISCO_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        # All 5 threads should have gotten a result
        assert all(r is not None for r in results)
        # Only 1 HTTP fetch should have occurred (single-flight)
        assert disco_route.call_count == 1


class TestSyncJwksCacheStampede:
    """Verify sync JWKS cache prevents thundering herd on TTL expiry."""

    @respx.mock
    def test_jwks_cache_stampede_blocked(self):
        """Multiple threads hitting expired JWKS cache produce only 1 HTTP fetch."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        barrier = threading.Barrier(5, timeout=5)
        results: list[object] = [None] * 5
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                results[idx] = _get_cached_jwks(JWKS_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        assert all(r is not None for r in results)
        assert jwks_route.call_count == 1


class TestSyncStampedeAfterExpiry:
    """Verify stampede prevention after TTL expiry."""

    @respx.mock
    def test_jwks_stampede_after_expiry_blocked(self):
        """After TTL expires, concurrent fetches produce only 1 new HTTP request."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime cache, then expire it by backdating cached_at
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Expire the entry by setting cached_at far in the past
        sync_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=sync_tv._jwks_cache[JWKS_URL].response,
            cached_at=time.monotonic() - 86401,
            ttl=86400.0,
        )

        barrier = threading.Barrier(5, timeout=5)
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                _get_cached_jwks(JWKS_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        # 1 initial + 1 refresh (NOT 1 + 5)
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY

    @respx.mock
    def test_disco_stampede_after_expiry_blocked(self):
        """After disco TTL expires, concurrent fetches produce only 1 new request."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # Prime cache, then expire it
        _get_disco_response(DISCO_URL)
        assert disco_route.call_count == 1

        cache_key = (DISCO_URL, _STRICT_DISCO_KEY)
        sync_tv._disco_cache[cache_key] = DiscoCacheEntry(
            response=sync_tv._disco_cache[cache_key].response,
            cached_at=time.monotonic() - 3601,
            ttl=3600.0,
        )

        barrier = threading.Barrier(5, timeout=5)
        errors: list[Exception | None] = [None] * 5

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                _get_disco_response(DISCO_URL)
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for err in errors:
            assert err is None, f"Thread raised: {err}"

        assert disco_route.call_count == FETCH_AFTER_EXPIRY


class TestAsyncDiscoCacheStampede:
    """Verify async discovery cache prevents thundering herd on TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_cache_stampede_blocked_async(self):
        """Multiple coroutines hitting expired cache produce only 1 HTTP fetch."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        results = await asyncio.gather(
            *[async_get_disco_response(DISCO_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert disco_route.call_count == 1


class TestAsyncJwksCacheStampede:
    """Verify async JWKS cache prevents thundering herd on TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_cache_stampede_blocked_async(self):
        """Multiple coroutines hitting expired JWKS cache produce only 1 HTTP fetch."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        results = await asyncio.gather(
            *[async_get_cached_jwks(JWKS_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert jwks_route.call_count == 1


class TestAsyncStampedeAfterExpiry:
    """Verify async stampede prevention after TTL expiry."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_stampede_after_expiry_blocked_async(self):
        """After TTL expires, concurrent async fetches produce only 1 new request."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime cache
        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Expire the entry
        aio_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=aio_tv._jwks_cache[JWKS_URL].response,
            cached_at=time.monotonic() - 86401,
            ttl=86400.0,
        )

        results = await asyncio.gather(
            *[async_get_cached_jwks(JWKS_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        # 1 initial + 1 refresh (NOT 1 + 5)
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_stampede_after_expiry_blocked_async(self):
        """After disco TTL expires, concurrent async fetches produce only 1 new request."""
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )

        # Prime cache
        await async_get_disco_response(DISCO_URL)
        assert disco_route.call_count == 1

        # Expire the entry
        cache_key = (DISCO_URL, _STRICT_DISCO_KEY)
        aio_tv._disco_cache[cache_key] = DiscoCacheEntry(
            response=aio_tv._disco_cache[cache_key].response,
            cached_at=time.monotonic() - 3601,
            ttl=3600.0,
        )

        results = await asyncio.gather(
            *[async_get_disco_response(DISCO_URL) for _ in range(5)]
        )

        assert all(r is not None for r in results)
        assert disco_route.call_count == FETCH_AFTER_EXPIRY


class TestSyncRefreshJwksFreshnessGuard:
    """Verify _refresh_jwks skips fetch when another thread already refreshed."""

    @respx.mock
    def test_refresh_skips_fetch_when_already_fresh(self):
        """If cache was refreshed while waiting on lock, return cached entry."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Manually set cached_at to a future time to simulate another thread
        # having just refreshed the cache
        entry = sync_tv._jwks_cache[JWKS_URL]
        sync_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=entry.response,
            cached_at=time.monotonic() + 100,
            ttl=entry.ttl,
        )

        # _refresh_jwks should see the fresh entry and skip the HTTP fetch
        result, from_retained_cache = _refresh_jwks(JWKS_URL)
        assert result is not None
        # The freshness-guard short-circuit returns the cached entry without
        # touching upstream, so this is not the #403 empty-fallback path.
        assert from_retained_cache is False
        # No new fetch — still just the 1 from priming
        assert jwks_route.call_count == 1

    @respx.mock
    def test_refresh_fetches_when_cache_stale(self):
        """Normal refresh path: fetch when cache is stale."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Call _refresh_jwks — cached_at is in the past relative to request_time
        result, from_retained_cache = _refresh_jwks(JWKS_URL)
        assert result is not None
        assert from_retained_cache is False
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY


class TestAsyncRefreshJwksFreshnessGuard:
    """Verify async _refresh_jwks skips fetch when another coroutine already refreshed."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_skips_fetch_when_already_fresh_async(self):
        """If cache was refreshed while waiting on lock, return cached entry."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        # Prime the cache
        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        # Set cached_at to future time to simulate another coroutine refresh
        entry = aio_tv._jwks_cache[JWKS_URL]
        aio_tv._jwks_cache[JWKS_URL] = JwksCacheEntry(
            response=entry.response,
            cached_at=time.monotonic() + 100,
            ttl=entry.ttl,
        )

        result, from_retained_cache = await async_refresh_jwks(JWKS_URL)
        assert result is not None
        assert from_retained_cache is False
        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_fetches_when_cache_stale_async(self):
        """Normal refresh path: fetch when cache is stale."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json={"keys": [key_dict]})
        )

        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        result, from_retained_cache = await async_refresh_jwks(JWKS_URL)
        assert result is not None
        assert from_retained_cache is False
        assert jwks_route.call_count == FETCH_AFTER_EXPIRY


# ============================================================================
# Kid-miss stampede (PR #390): pre-decode refresh path must single-flight
# ============================================================================
#
# The fix in #390 adds a pre-decode JWKS refresh when the JWT's `kid` is not
# in the cached JWKS. Without protection, N concurrent requests with an
# unknown kid would each issue their own JWKS fetch (thundering herd against
# the OP's JWKS endpoint, and an unauthenticated amplification vector since
# the JWT header is not yet trust-validated).
#
# Protection comes from two layers already in the code:
#   1. `_get_cached_jwks` and `_refresh_jwks` share `_jwks_cache_lock`. While
#      task A holds the lock during its fetch, tasks B..N block at
#      `_get_cached_jwks` and read the freshly-refreshed cache when A releases.
#      Most concurrent tasks therefore never even enter `_refresh_jwks`.
#   2. The single-flight guard inside `_refresh_jwks`
#      (`cached_at >= request_time`) catches the residual race where multiple
#      tasks captured `request_time` before the first fetch completed.
#
# These tests pin both layers in place so a future change cannot quietly
# regress the kid-miss path into an N-fetch fan-out.

# 1 prime fetch + 1 single-flight refresh on rotation = 2 fetches, regardless
# of how many concurrent validators arrive with the unknown kid.
KID_MISS_FETCH_BUDGET = 2


def _make_rotating_jwks_handler(
    old_keys_response: dict, new_keys_response: dict
) -> tuple[list[int], Callable[[httpx.Request], httpx.Response]]:
    """Return (call_log, handler). First call returns old_keys; rest return new_keys."""
    call_log: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        call_log.append(1)
        if len(call_log) == 1:
            return httpx.Response(200, json=old_keys_response)
        return httpx.Response(200, json=new_keys_response)

    return call_log, handler


class TestAsyncKidMissStampede:
    """Concurrent kid-miss validations must produce a single refresh fetch."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_n_concurrent_unknown_kid_triggers_single_refresh(self):
        """N concurrent validate_token calls with the same unknown kid → 2 fetches total."""
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        _, jwks_handler = _make_rotating_jwks_handler(
            old_keys_response={"keys": [old_key_dict]},
            new_keys_response={"keys": [new_key_dict]},
        )
        jwks_route = respx.get(JWKS_URL).mock(side_effect=jwks_handler)

        # Prime cache with old kid via direct cache access (no validation needed).
        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        N = 25
        results = await asyncio.gather(
            *[
                async_validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
                for _ in range(N)
            ]
        )

        assert len(results) == N
        for decoded in results:
            assert decoded["sub"] == "user1"
        # Stampede protection: only 1 prime + 1 refresh, NOT 1 + N.
        assert jwks_route.call_count == KID_MISS_FETCH_BUDGET, (
            f"Stampede: {jwks_route.call_count} fetches for {N} concurrent kid-miss "
            f"validations (expected {KID_MISS_FETCH_BUDGET})"
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_n_concurrent_distinct_unknown_kids_triggers_single_refresh(self):
        """N concurrent calls with N distinct unknown kids still single-flight by jwks_uri.

        The single-flight key is jwks_uri, not kid. Even if every concurrent
        request has a different unknown kid, only one refresh fetch should
        occur. The first refresh populates the cache; subsequent tasks read
        the fresh cache (and may then raise per-key errors if their kid still
        isn't present, which is acceptable — what we're guarding here is the
        outbound fetch count).
        """
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "old-kid"

        # New JWKS contains every kid the rotated batch might use.
        new_keys = []
        new_pems: dict[str, bytes] = {}
        N = 10
        for i in range(N):
            kd, pem = generate_rsa_keypair()
            kd["kid"] = f"new-kid-{i}"
            new_keys.append(kd)
            new_pems[f"new-kid-{i}"] = pem

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        _, jwks_handler = _make_rotating_jwks_handler(
            old_keys_response={"keys": [old_key_dict]},
            new_keys_response={"keys": new_keys},
        )
        jwks_route = respx.get(JWKS_URL).mock(side_effect=jwks_handler)

        await async_get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        async def _validate(i: int) -> dict:
            kid = f"new-kid-{i}"
            tok = sign_jwt(
                new_pems[kid],
                {"sub": f"user{i}", "iss": "https://example.com"},
                headers={"kid": kid},
            )
            return await async_validate_token(
                jwt=tok,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )

        results = await asyncio.gather(*[_validate(i) for i in range(N)])

        assert {r["sub"] for r in results} == {f"user{i}" for i in range(N)}
        assert jwks_route.call_count == KID_MISS_FETCH_BUDGET, (
            f"Stampede: {jwks_route.call_count} fetches for {N} concurrent distinct "
            f"unknown kids (expected {KID_MISS_FETCH_BUDGET})"
        )


class TestSyncKidMissStampede:
    """Concurrent kid-miss validations from threads must produce a single refresh fetch."""

    @respx.mock
    def test_n_concurrent_unknown_kid_triggers_single_refresh_sync(self):
        """N threads concurrently validating tokens with the same unknown kid → 2 fetches."""
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "old-kid"
        new_key_dict, new_pem = generate_rsa_keypair()
        new_key_dict["kid"] = "new-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        _, jwks_handler = _make_rotating_jwks_handler(
            old_keys_response={"keys": [old_key_dict]},
            new_keys_response={"keys": [new_key_dict]},
        )
        jwks_route = respx.get(JWKS_URL).mock(side_effect=jwks_handler)

        # Prime cache.
        _get_cached_jwks(JWKS_URL)
        assert jwks_route.call_count == 1

        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "new-kid"},
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        N = 25
        barrier = threading.Barrier(N, timeout=10)
        results: list[dict | None] = [None] * N
        errors: list[Exception | None] = [None] * N

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                results[idx] = validate_token(
                    jwt=token,
                    token_validation_config=config,
                    disco_doc_address=DISCO_URL,
                )
            except Exception as exc:
                errors[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        for err in errors:
            assert err is None, f"Worker raised: {err}"
        for r in results:
            assert r is not None
            assert r["sub"] == "user1"
        assert jwks_route.call_count == KID_MISS_FETCH_BUDGET, (
            f"Stampede: {jwks_route.call_count} fetches for {N} concurrent kid-miss "
            f"validations (expected {KID_MISS_FETCH_BUDGET})"
        )


# ============================================================================
# Diagnostic on still-missing kid after refresh (PR #390 hardening)
# ============================================================================


class TestSyncStillMissingDiagnostic:
    """A successful refresh that doesn't help should leave a diagnostic log."""

    @respx.mock
    def test_warning_logged_when_kid_still_absent_after_refresh(self, caplog):
        """If refresh succeeds but the kid is still not in JWKS, log a warning."""
        old_key_dict = generate_rsa_keypair()[0]
        old_key_dict["kid"] = "old-kid"
        # Refreshed JWKS has a different kid — still doesn't help the request.
        other_key_dict = generate_rsa_keypair()[0]
        other_key_dict["kid"] = "some-other-kid"

        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)
        )
        _, jwks_handler = _make_rotating_jwks_handler(
            old_keys_response={"keys": [old_key_dict]},
            new_keys_response={"keys": [other_key_dict]},
        )
        respx.get(JWKS_URL).mock(side_effect=jwks_handler)

        _get_cached_jwks(JWKS_URL)

        new_pem = generate_rsa_keypair()[1]
        token = sign_jwt(
            new_pem,
            {"sub": "user1", "iss": "https://example.com"},
            headers={"kid": "still-not-here"},
        )
        config = TokenValidationConfig(
            perform_disco=True, audience=None, issuer="https://example.com"
        )

        with (
            caplog.at_level(logging.WARNING),
            pytest.raises(TokenValidationException),
        ):
            validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address=DISCO_URL,
            )
        assert any("still absent" in rec.message.lower() for rec in caplog.records), (
            f"Expected 'still absent' warning, got: {[r.message for r in caplog.records]}"
        )
