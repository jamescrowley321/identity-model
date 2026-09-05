"""
Tests for HTTP cache header semantics in JWKS and discovery caches.

Discovery responses retain strict RFC 7234 semantics: ``no-store`` and
``no-cache`` skip the cache. JWKS responses, per issue #396 and
:func:`is_uncacheable_for_jwks`, ignore those directives because JWKS
is public key material; strict honoring self-DoSes the upstream issuer
at production traffic levels.

Covered behaviors:
1. Failed JWKS/discovery responses are not cached.
2. JWKS no-store / no-cache responses ARE cached (new policy).
3. Discovery no-store / no-cache responses are NOT cached (strict).
4. JWKS refresh with uncacheable response writes the new entry,
   never leaves the cache empty.
"""

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
    clear_discovery_cache as async_clear_discovery_cache,
)
from py_identity_model.aio.token_validation import (
    clear_jwks_cache as async_clear_jwks_cache,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import (
    DISCO_RESPONSE_WITH_JWKS,
    generate_rsa_keypair,
)


DISCO_URL = "https://example.com/.well-known/openid-configuration"
JWKS_URL = "https://example.com/jwks"
# Second element of the disco cache key for the default (strict) policy — the
# discovery cache keys on ``(address, policy.cache_key())``.
_STRICT_DISCO_KEY = DiscoveryPolicy().cache_key()


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


# ============================================================================
# Failed responses must not be cached
# ============================================================================


class TestSyncFailedResponseNotCached:
    @respx.mock
    def test_jwks_failure_then_success_refetches(self):
        """A transient JWKS failure must not poison the cache.

        Uses 404 to bypass the HTTP client's built-in 5xx retry behavior
        and isolate the cache-layer policy: ``is_successful=False`` must
        never be cached, regardless of the upstream status code.
        """
        key_dict = generate_rsa_keypair()[0]
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json={"keys": [key_dict]})

        respx.get(JWKS_URL).mock(side_effect=handler)

        failed = _get_cached_jwks(JWKS_URL)
        assert failed.is_successful is False
        assert JWKS_URL not in sync_tv._jwks_cache

        # Next call must re-fetch and succeed.
        success = _get_cached_jwks(JWKS_URL)
        assert success.is_successful is True
        assert JWKS_URL in sync_tv._jwks_cache
        assert len(call_log) == 2  # noqa: PLR2004

    @respx.mock
    def test_disco_failure_then_success_refetches(self):
        """A transient discovery failure must not poison the cache."""
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)

        respx.get(DISCO_URL).mock(side_effect=handler)

        failed = _get_disco_response(DISCO_URL)
        assert failed.is_successful is False
        assert (DISCO_URL, _STRICT_DISCO_KEY) not in sync_tv._disco_cache

        success = _get_disco_response(DISCO_URL)
        assert success.is_successful is True
        assert (DISCO_URL, _STRICT_DISCO_KEY) in sync_tv._disco_cache
        assert len(call_log) == 2  # noqa: PLR2004


class TestAsyncFailedResponseNotCached:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_failure_then_success_refetches_async(self):
        key_dict = generate_rsa_keypair()[0]
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json={"keys": [key_dict]})

        respx.get(JWKS_URL).mock(side_effect=handler)

        failed = await async_get_cached_jwks(JWKS_URL)
        assert failed.is_successful is False
        assert JWKS_URL not in aio_tv._jwks_cache

        success = await async_get_cached_jwks(JWKS_URL)
        assert success.is_successful is True
        assert JWKS_URL in aio_tv._jwks_cache
        assert len(call_log) == 2  # noqa: PLR2004

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_failure_then_success_refetches_async(self):
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=DISCO_RESPONSE_WITH_JWKS)

        respx.get(DISCO_URL).mock(side_effect=handler)

        failed = await async_get_disco_response(DISCO_URL)
        assert failed.is_successful is False
        assert (DISCO_URL, _STRICT_DISCO_KEY) not in aio_tv._disco_cache

        success = await async_get_disco_response(DISCO_URL)
        assert success.is_successful is True
        assert (DISCO_URL, _STRICT_DISCO_KEY) in aio_tv._disco_cache
        assert len(call_log) == 2  # noqa: PLR2004


# ============================================================================
# Cache-Control: no-store — never cached
# ============================================================================


class TestSyncNoStoreCachedForJwks:
    @respx.mock
    def test_jwks_no_store_still_cached(self):
        """no-store on JWKS is ignored; response is cached. See #396."""
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-store, max-age=600"},
            )
        )

        response = _get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert response.keys is not None
        assert JWKS_URL in sync_tv._jwks_cache

    @respx.mock
    def test_disco_no_store_skips_cache(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-store"},
            )
        )

        response = _get_disco_response(DISCO_URL)
        assert response.is_successful is True
        assert (DISCO_URL, _STRICT_DISCO_KEY) not in sync_tv._disco_cache


class TestAsyncNoStoreCachedForJwks:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_no_store_still_cached_async(self):
        """no-store on JWKS is ignored; response is cached. See #396."""
        key_dict = generate_rsa_keypair()[0]
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-store, max-age=600"},
            )
        )

        response = await async_get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert JWKS_URL in aio_tv._jwks_cache

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_no_store_skips_cache_async(self):
        respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-store"},
            )
        )

        response = await async_get_disco_response(DISCO_URL)
        assert response.is_successful is True
        assert (DISCO_URL, _STRICT_DISCO_KEY) not in aio_tv._disco_cache


# ============================================================================
# Cache-Control: no-cache — always re-fetch
# ============================================================================


class TestSyncNoCacheCachedForJwks:
    @respx.mock
    def test_jwks_no_cache_serves_from_cache(self):
        """no-cache on JWKS is ignored; subsequent calls hit cache. See #396."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-cache, max-age=600"},
            )
        )

        for _ in range(3):
            response = _get_cached_jwks(JWKS_URL)
            assert response.is_successful is True

        assert JWKS_URL in sync_tv._jwks_cache
        assert jwks_route.call_count == 1

    @respx.mock
    def test_disco_no_cache_refetches_each_call(self):
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-cache"},
            )
        )

        for _ in range(3):
            response = _get_disco_response(DISCO_URL)
            assert response.is_successful is True

        assert (DISCO_URL, _STRICT_DISCO_KEY) not in sync_tv._disco_cache
        assert disco_route.call_count == 3  # noqa: PLR2004


class TestAsyncNoCacheCachedForJwks:
    @pytest.mark.asyncio
    @respx.mock
    async def test_jwks_no_cache_serves_from_cache_async(self):
        """no-cache on JWKS is ignored; subsequent calls hit cache. See #396."""
        key_dict = generate_rsa_keypair()[0]
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key_dict]},
                headers={"Cache-Control": "no-cache, max-age=600"},
            )
        )

        for _ in range(3):
            response = await async_get_cached_jwks(JWKS_URL)
            assert response.is_successful is True

        assert JWKS_URL in aio_tv._jwks_cache
        assert jwks_route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_disco_no_cache_refetches_each_call_async(self):
        disco_route = respx.get(DISCO_URL).mock(
            return_value=httpx.Response(
                200,
                json=DISCO_RESPONSE_WITH_JWKS,
                headers={"Cache-Control": "no-cache"},
            )
        )

        for _ in range(3):
            await async_get_disco_response(DISCO_URL)

        assert (DISCO_URL, _STRICT_DISCO_KEY) not in aio_tv._disco_cache
        assert disco_route.call_count == 3  # noqa: PLR2004


# ============================================================================
# Refresh under uncacheable response: with the JWKS-specific cache policy
# (#396), the cache is REPLACED with the new keys rather than popped. This
# eliminates the kid-miss → refresh → re-fetch loop the old pop-on-uncacheable
# behavior introduced, without leaving stale keys live (the response keys
# are fresh by definition).
# ============================================================================


def _key_with_kid(kid: str) -> dict:
    key_dict, _ = generate_rsa_keypair()
    return {**key_dict, "kid": kid}


def _kids(response) -> set[str]:
    return {k.kid for k in (response.keys or [])}


REFRESH_UNCACHEABLE_TEST_CASES = [
    pytest.param("no-store", id="no-store"),
    pytest.param("no-cache", id="no-cache"),
    pytest.param("no-store, max-age=3600", id="no-store-with-max-age"),
    pytest.param("no-cache, max-age=3600", id="no-cache-with-max-age"),
]


class TestSyncRefreshReplacesStaleOnUncacheable:
    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    def test_refresh_writes_new_entry_when_response_uncacheable(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("old-kid")
        new_key = _key_with_kid("new-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": [new_key]},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = _get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"old-kid"}

        refreshed, from_retained_cache = sync_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is True
        # Fresh response is returned to the caller …
        assert _kids(refreshed) == {"new-kid"}
        # … and the cache is updated with the new key (not popped).
        # See #396: pop-on-uncacheable caused the kid-miss-refresh-loop
        # this branch was meant to prevent.
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"new-kid"}
        # Real refresh (not an empty-fallback) — see #403 contract.
        assert from_retained_cache is False

    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    def test_disco_pops_expired_entry_when_response_uncacheable(
        self, uncacheable_header: str
    ):
        """Disco has no _refresh equivalent, but expired entries still need
        the pop semantics: when re-fetching past TTL yields an uncacheable
        response, the expired entry must not linger in the dict (memory
        hygiene + cleanliness for the cache-size bound landing in a
        follow-up commit)."""
        rotated_disco = {
            **DISCO_RESPONSE_WITH_JWKS,
            "issuer": "https://rotated.example",
        }
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json=DISCO_RESPONSE_WITH_JWKS,
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json=rotated_disco,
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(DISCO_URL).mock(side_effect=handler)

        primed = _get_disco_response(DISCO_URL)
        assert primed.is_successful is True
        cache_key = (DISCO_URL, _STRICT_DISCO_KEY)
        assert cache_key in sync_tv._disco_cache

        # Manually expire the entry without removing it — this is the state
        # the cache lands in when the entry's TTL elapses naturally. Backdate
        # cached_at past the TTL boundary on the monotonic clock (post-#400
        # the cache compares ages via time.monotonic, not time.time, so a
        # literal 0.0 is just process-startup time and may still be fresh in
        # short-running tests).
        stale_entry = sync_tv._disco_cache[cache_key]
        sync_tv._disco_cache[cache_key] = type(stale_entry)(
            response=stale_entry.response,
            cached_at=time.monotonic() - stale_entry.ttl - 1,
            ttl=stale_entry.ttl,
        )

        _get_disco_response(DISCO_URL)
        # The expired entry must be popped, not left as dead weight.
        assert cache_key not in sync_tv._disco_cache


class TestAsyncRefreshReplacesStaleOnUncacheable:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("uncacheable_header", REFRESH_UNCACHEABLE_TEST_CASES)
    @respx.mock
    async def test_refresh_writes_new_entry_when_response_uncacheable_async(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("old-kid")
        new_key = _key_with_kid("new-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": [new_key]},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = await async_get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"old-kid"}

        refreshed, from_retained_cache = await aio_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is True
        assert _kids(refreshed) == {"new-kid"}
        # Cache updated with new key, not popped (see #396).
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"new-kid"}
        # Real refresh (not an empty-fallback) — see #403 contract.
        assert from_retained_cache is False


# ============================================================================
# Empty-keys responses must never replace a populated cache entry, and must
# not be stored from a fresh fetch either. An empty ``keys: []`` from the
# provider is treated as a transient upstream blip — never a valid replacement.
# Without this guard, a transient empty-200 response from the OP poisons the
# cache for up to 24h, breaking every token validation in the deployment.
# ============================================================================


class TestSyncEmptyKeysNotCached:
    @respx.mock
    def test_refresh_with_empty_keys_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        primed = _get_cached_jwks(JWKS_URL)
        assert primed.is_successful is True

        refreshed, from_retained_cache = sync_tv._refresh_jwks(JWKS_URL)
        # #403: when upstream returns 200 with empty keys, _refresh_jwks
        # surfaces the retained cache entry to the caller (not the empty
        # response) so the in-flight validation has usable keys. The
        # cache itself is also retained.
        assert refreshed.is_successful is True
        assert _kids(refreshed) == {"retained-kid"}
        assert from_retained_cache is True
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @respx.mock
    def test_initial_fetch_with_empty_keys_not_cached(self):
        respx.get(JWKS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )
        )

        response = _get_cached_jwks(JWKS_URL)
        assert response.is_successful is True
        assert response.keys == []
        # Empty-keys responses are never stored, so a subsequent call must
        # re-fetch rather than serve a poisoned entry.
        assert JWKS_URL not in sync_tv._jwks_cache


class TestAsyncEmptyKeysNotCached:
    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_with_empty_keys_retains_existing_entry_async(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": "max-age=3600"},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        refreshed, from_retained_cache = await aio_tv._refresh_jwks(JWKS_URL)
        # See sync counterpart — #403 fallback: retained cache surfaced.
        assert refreshed.is_successful is True
        assert _kids(refreshed) == {"retained-kid"}
        assert from_retained_cache is True
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}


# ============================================================================
# Empty-keys + uncacheable header joint case. The dataclass-level invariant
# is "empty keys never replaces working keys" — checking the empty-keys
# branch *before* the uncacheable branch ensures a malformed
# ``200 {"keys": []}`` paired with ``Cache-Control: no-cache`` does not pop
# the working entry on a transient empty-body blip combined with a header
# bug. Without this ordering, the cache is silently emptied by a single
# bad-response coincidence.
# ============================================================================


class TestEmptyKeysWithUncacheableHeaderRetains:
    @respx.mock
    @pytest.mark.parametrize(
        "uncacheable_header", ["no-store", "no-cache", "no-store, max-age=300"]
    )
    def test_sync_empty_keys_with_uncacheable_header_retains(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        _get_cached_jwks(JWKS_URL)
        # Return is now a tuple — discard both halves; the test pins cache
        # state, not what _refresh_jwks surfaces to the caller.
        sync_tv._refresh_jwks(JWKS_URL)
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @pytest.mark.asyncio
    @respx.mock
    @pytest.mark.parametrize(
        "uncacheable_header", ["no-store", "no-cache", "no-store, max-age=300"]
    )
    async def test_async_empty_keys_with_uncacheable_header_retains(
        self, uncacheable_header: str
    ):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(
                200,
                json={"keys": []},
                headers={"Cache-Control": uncacheable_header},
            )

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        # Return is now a tuple — discard both halves; the test pins cache
        # state, not what _refresh_jwks surfaces to the caller.
        await aio_tv._refresh_jwks(JWKS_URL)
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}


# ============================================================================
# Network errors must never replace a populated cache entry (retain-on-error,
# mirroring jose4j's setRetainCacheOnErrorDuration semantics). Combined with
# the existing "failed responses not cached" tests above, this proves the
# full failure-mode matrix: success+cacheable=write, success+uncacheable=pop,
# success+empty=retain, failed=retain.
# ============================================================================


class TestRetainOnError:
    @respx.mock
    def test_sync_refresh_failure_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(404, text="not found")

        respx.get(JWKS_URL).mock(side_effect=handler)

        _get_cached_jwks(JWKS_URL)
        refreshed, from_retained_cache = sync_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is False
        # Failed refresh does not trigger the empty-keys fallback.
        assert from_retained_cache is False
        assert JWKS_URL in sync_tv._jwks_cache
        assert _kids(sync_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}

    @pytest.mark.asyncio
    @respx.mock
    async def test_async_refresh_failure_retains_existing_entry(self):
        old_key = _key_with_kid("retained-kid")
        call_log: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            call_log.append(1)
            if len(call_log) == 1:
                return httpx.Response(
                    200,
                    json={"keys": [old_key]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            return httpx.Response(404, text="not found")

        respx.get(JWKS_URL).mock(side_effect=handler)

        await async_get_cached_jwks(JWKS_URL)
        refreshed, from_retained_cache = await aio_tv._refresh_jwks(JWKS_URL)
        assert refreshed.is_successful is False
        # Failed refresh does not trigger the empty-keys fallback.
        assert from_retained_cache is False
        assert JWKS_URL in aio_tv._jwks_cache
        assert _kids(aio_tv._jwks_cache[JWKS_URL].response) == {"retained-kid"}
