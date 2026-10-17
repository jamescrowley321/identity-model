"""Fail-closed controls for the validation caches (#753, #953).

A ``ValidationCache`` / ``AsyncValidationCache`` holds the discovery cache,
JWKS cache and kid-miss cooldown state; the HTTP client only sends requests.
These paths are security-gated (``tools/mutation_security.py``); this module
pins what a regression in them could silently break:

* **Routing.** Every upstream fetch, including the forced JWKS refreshes on a
  kid miss and on a signature failure, goes through the client the caller
  passed, and every cache write lands in the cache the caller passed.
  Falling back to the library default client would fetch with another
  ``Config`` (CA bundle, timeouts, size limits); falling back to the default
  cache would fill (and read) another cache. The injected clients below
  answer from an ``httpx.MockTransport`` while ``respx`` (which does not
  intercept a ``MockTransport``) rejects every request the default client
  makes, and the default cache must stay empty.
* **Cooldown bookkeeping.** A refresh that absorbs a rotation drops the URI's
  kid-miss stamp, and an evicted URI drops its stamp (bounded sidecar).
* **Single-flight and the cache hits.** A cache miss waits on the URI's
  fetch lock; a fresh hit takes no lock, and both it and a hit found under
  the lock refresh LRU recency (#397).
* **TTL.** A provider's ``Cache-Control: max-age`` sets the entry TTL ahead
  of the cache's ``Config`` default.
* **Refresh coalescing.** A kid-miss refresh that waited on the fetch lock
  while another refresh replaced the stale entry returns that entry instead
  of fetching again, and an entry written at the waiter's own lock-time
  instant counts as fresh.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
import threading
import time
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import httpx
import pytest
import respx

from py_identity_model import Config
from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.managed_client import AsyncHTTPClient
from py_identity_model.aio.validation_cache import (
    AsyncValidationCache,
    get_default_async_validation_cache,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.jwks_cache import (
    DiscoCacheEntry,
    JwksCacheEntry,
    apply_disco_cache_outcome,
    apply_jwks_cache_outcome,
)
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    JwksResponse,
    TokenValidationConfig,
)
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.validation_cache import (
    ValidationCache,
    get_default_validation_cache,
)

from ..token_validation_helpers import (
    DEFAULT_TRUST_SCOPE,
    disco_cache_key,
    generate_rsa_keypair,
    jwks_cache_key,
    sign_jwt,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from py_identity_model.core.trust_scope import TrustScope


pytestmark = pytest.mark.unit

DISCO_PATH = "/.well-known/openid-configuration"
JWKS_PATH = "/jwks"
KID = "rotating-kid"
# Origins to pick from when a test needs a URI whose fetch-lock stripe differs
# from the stripe of ``None`` (what a mutated lock key would take). Lock
# stripes hash the key, and str hashes vary per process.
CANDIDATE_ORIGINS = [f"https://op{n}.example" for n in range(8)]
# A mutated (unblocked) fetch completes well inside this; the correct code
# stays blocked for all of it.
BLOCKED_WAIT_SECONDS = 0.5
# cooldown 0: every stamp has expired, so a refresh is always allowed and the
# only thing the tests observe is whether the stamp is dropped afterwards.
NO_COOLDOWN = Config(jwks_kid_miss_cooldown=0)
_NO_KEY: Any = None

_SIGNING_KEY, _SIGNING_PEM = generate_rsa_keypair()
_OTHER_KEY, _ = generate_rsa_keypair()


def _with_kid(key: dict, kid: str) -> dict:
    return {**key, "kid": kid}


def _validation_config(origin: str) -> TokenValidationConfig:
    return TokenValidationConfig(perform_disco=True, audience=None, issuer=origin)


class _Upstream:
    """An OP behind an ``httpx.MockTransport``: serves a discovery document
    for any origin and the queued JWKS bodies in order (the last repeats)."""

    def __init__(self, jwks_bodies: list[list[dict]]) -> None:
        self._jwks_bodies = list(jwks_bodies)
        self.requests: list[str] = []
        self.fetched = threading.Event()

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        self.fetched.set()
        origin = f"{request.url.scheme}://{request.url.host}"
        if request.url.path == DISCO_PATH:
            return httpx.Response(200, json=_disco_doc(origin))
        if request.url.path == JWKS_PATH:
            body = self._jwks_bodies[0]
            if len(self._jwks_bodies) > 1:
                self._jwks_bodies.pop(0)
            return httpx.Response(200, json={"keys": body})
        return httpx.Response(404)

    @contextmanager
    def client(self) -> Iterator[HTTPClient]:
        transport = httpx.MockTransport(self.handler)
        with httpx.Client(transport=transport) as http:
            yield HTTPClient(http)

    @asynccontextmanager
    async def async_client(self) -> AsyncIterator[AsyncHTTPClient]:
        transport = httpx.MockTransport(self.handler)
        async with httpx.AsyncClient(transport=transport) as http:
            yield AsyncHTTPClient(http)


def _disco_doc(origin: str) -> dict:
    return {
        "issuer": origin,
        "jwks_uri": f"{origin}{JWKS_PATH}",
        "authorization_endpoint": f"{origin}/authorize",
        "token_endpoint": f"{origin}/token",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


def _token(origin: str) -> str:
    return sign_jwt(_SIGNING_PEM, {"sub": "user1", "iss": origin}, headers={"kid": KID})


def _disco_key(
    origin: str, scope: TrustScope = DEFAULT_TRUST_SCOPE
) -> tuple[TrustScope, str, tuple]:
    return disco_cache_key(f"{origin}{DISCO_PATH}", scope=scope)


def _fresh_jwks_entry() -> JwksCacheEntry:
    return JwksCacheEntry(
        response=JwksResponse(is_successful=True, keys=[jwks_from_dict(_OTHER_KEY)]),
        cached_at=time.monotonic(),
        ttl=1e9,
    )


def _fresh_disco_entry(origin: str) -> DiscoCacheEntry:
    return DiscoCacheEntry(
        response=DiscoveryDocumentResponse(is_successful=True, issuer=origin),
        cached_at=time.monotonic(),
        ttl=1e9,
    )


def _origin_off_the_none_stripe(lock_for: Any, none_lock: object) -> str:
    """First candidate origin whose fetch lock is not the ``None`` key's."""
    for origin in CANDIDATE_ORIGINS:
        if lock_for(origin) is not none_lock:
            return origin
    raise AssertionError("every candidate origin shares the None lock stripe")


@pytest.fixture(autouse=True)
def _empty_default_caches():
    """Tests assert the default cache stays empty; start it so."""
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()
    yield
    sync_tv.clear_discovery_cache()
    sync_tv.clear_jwks_cache()


@pytest.fixture
async def empty_default_async_caches():
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()
    yield
    await aio_tv.clear_discovery_cache()
    await aio_tv.clear_jwks_cache()


# ============================================================================
# Routing + cooldown bookkeeping on the forced refreshes
# ============================================================================

ORIGIN = CANDIDATE_ORIGINS[0]
JWKS_URI = f"{ORIGIN}{JWKS_PATH}"
ROTATION_REQUESTS = [f"{ORIGIN}{DISCO_PATH}", JWKS_URI, JWKS_URI]
# The cached JWKS lacks the token's kid; the refresh publishes it.
KID_MISS_BODIES = [[_with_kid(_OTHER_KEY, "old-kid")], [_with_kid(_SIGNING_KEY, KID)]]
# The cached JWKS has the token's kid under another key; the refresh fixes it.
SIGNATURE_FAILURE_BODIES = [
    [_with_kid(_OTHER_KEY, KID)],
    [_with_kid(_SIGNING_KEY, KID)],
]


class TestSyncRefreshThroughInjectedClient:
    @respx.mock
    @pytest.mark.parametrize(
        "bodies",
        [KID_MISS_BODIES, SIGNATURE_FAILURE_BODIES],
        ids=["kid_miss", "signature_failure"],
    )
    def test_refresh_uses_injected_client_and_clears_stamp(self, bodies):
        upstream = _Upstream(bodies)
        with upstream.client() as client:
            cache = ValidationCache(config=NO_COOLDOWN)
            cache.kid_miss_last_attempt[JWKS_URI] = time.monotonic()

            claims = sync_tv.validate_token(
                _token(ORIGIN),
                _validation_config(ORIGIN),
                f"{ORIGIN}{DISCO_PATH}",
                http_client=client,
                cache=cache,
            )

            assert claims["sub"] == "user1"
            assert upstream.requests == ROTATION_REQUESTS
            assert cache.kid_miss_last_attempt == {}
            assert list(cache.jwks) == [jwks_cache_key(JWKS_URI, client.trust_scope)]
        assert dict(get_default_validation_cache().jwks) == {}


class TestAsyncRefreshThroughInjectedClient:
    @respx.mock
    @pytest.mark.usefixtures("empty_default_async_caches")
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bodies",
        [KID_MISS_BODIES, SIGNATURE_FAILURE_BODIES],
        ids=["kid_miss", "signature_failure"],
    )
    async def test_refresh_uses_injected_client_and_clears_stamp(self, bodies):
        upstream = _Upstream(bodies)
        async with upstream.async_client() as client:
            cache = AsyncValidationCache(config=NO_COOLDOWN)
            cache.kid_miss_last_attempt[JWKS_URI] = time.monotonic()

            claims = await aio_tv.validate_token(
                _token(ORIGIN),
                _validation_config(ORIGIN),
                f"{ORIGIN}{DISCO_PATH}",
                http_client=client,
                cache=cache,
            )

            assert claims["sub"] == "user1"
            assert upstream.requests == ROTATION_REQUESTS
            assert cache.kid_miss_last_attempt == {}
            assert list(cache.jwks) == [jwks_cache_key(JWKS_URI, client.trust_scope)]
        assert dict(get_default_async_validation_cache().jwks) == {}


# ============================================================================
# Kid-miss refresh coalescing
# ============================================================================

COALESCED_REQUESTS = [JWKS_URI, f"{ORIGIN}{DISCO_PATH}", JWKS_URI]
FROZEN_NOW = 1000.0


def _frozen_clock() -> Any:
    return Mock(monotonic=Mock(return_value=FROZEN_NOW))


class TestSyncKidMissRefreshCoalescing:
    def test_waiter_returns_the_refresh_that_replaced_its_stale_entry(
        self, monkeypatch
    ):
        """Another refresh completes while this kid-miss refresh waits on
        the fetch lock: the waiter uses it and makes no upstream request."""
        upstream = _Upstream(KID_MISS_BODIES)
        with upstream.client() as client:
            cache = ValidationCache()
            sync_tv._get_cached_jwks(JWKS_URI, DiscoveryPolicy(), client, cache)
            real_lock_for = cache.jwks_fetch_lock
            raced: list[str] = []

            def lock_after_another_refresh(
                cache_key: tuple[TrustScope, str],
            ) -> threading.Lock:
                _scope, uri = cache_key
                if not raced:
                    raced.append(uri)
                    sync_tv._refresh_jwks(uri, DiscoveryPolicy(), client, cache)
                return real_lock_for(cache_key)

            monkeypatch.setattr(cache, "jwks_fetch_lock", lock_after_another_refresh)

            claims = sync_tv.validate_token(
                _token(ORIGIN),
                _validation_config(ORIGIN),
                f"{ORIGIN}{DISCO_PATH}",
                http_client=client,
                cache=cache,
            )

            assert claims["sub"] == "user1"
            assert raced == [JWKS_URI]
            assert upstream.requests == COALESCED_REQUESTS

    def test_entry_cached_at_the_lock_instant_is_fresh(self, monkeypatch):
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        with upstream.client() as client:
            cache = ValidationCache()
            entry = _fresh_jwks_entry()
            cache.jwks[jwks_cache_key(JWKS_URI, client.trust_scope)] = JwksCacheEntry(
                response=entry.response, cached_at=FROZEN_NOW, ttl=entry.ttl
            )
            monkeypatch.setattr(sync_tv, "time", _frozen_clock())

            response, from_retained = sync_tv._refresh_jwks(
                JWKS_URI, DiscoveryPolicy(), client, cache
            )

            assert response is entry.response
            assert from_retained is False
            assert upstream.requests == []


class TestAsyncKidMissRefreshCoalescing:
    @pytest.mark.asyncio
    async def test_waiter_returns_the_refresh_that_replaced_its_stale_entry(
        self, monkeypatch
    ):
        upstream = _Upstream(KID_MISS_BODIES)
        async with upstream.async_client() as client:
            cache = AsyncValidationCache()
            await aio_tv._get_cached_jwks(JWKS_URI, DiscoveryPolicy(), client, cache)
            real_lock_for = cache.jwks_fetch_lock
            raced: list[str] = []

            @asynccontextmanager
            async def lock_after_another_refresh(
                cache_key: tuple[TrustScope, str],
            ) -> AsyncIterator[None]:
                _scope, uri = cache_key
                if not raced:
                    raced.append(uri)
                    await aio_tv._refresh_jwks(uri, DiscoveryPolicy(), client, cache)
                async with real_lock_for(cache_key):
                    yield

            monkeypatch.setattr(cache, "jwks_fetch_lock", lock_after_another_refresh)

            claims = await aio_tv.validate_token(
                _token(ORIGIN),
                _validation_config(ORIGIN),
                f"{ORIGIN}{DISCO_PATH}",
                http_client=client,
                cache=cache,
            )

            assert claims["sub"] == "user1"
            assert raced == [JWKS_URI]
            assert upstream.requests == COALESCED_REQUESTS

    @pytest.mark.asyncio
    async def test_entry_cached_at_the_lock_instant_is_fresh(self, monkeypatch):
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        async with upstream.async_client() as client:
            cache = AsyncValidationCache()
            entry = _fresh_jwks_entry()
            cache.jwks[jwks_cache_key(JWKS_URI, client.trust_scope)] = JwksCacheEntry(
                response=entry.response, cached_at=FROZEN_NOW, ttl=entry.ttl
            )
            monkeypatch.setattr(aio_tv, "time", _frozen_clock())

            response, from_retained = await aio_tv._refresh_jwks(
                JWKS_URI, DiscoveryPolicy(), client, cache
            )

            assert response is entry.response
            assert from_retained is False
            assert upstream.requests == []


# ============================================================================
# Cooldown sidecar on eviction by a forced refresh
# ============================================================================

OLD_URI = f"{CANDIDATE_ORIGINS[1]}{JWKS_PATH}"
NEW_URI = f"{CANDIDATE_ORIGINS[2]}{JWKS_PATH}"
SINGLE_ENTRY = Config(cache_max_entries=1)


class TestSyncRefreshEviction:
    @pytest.mark.parametrize("stamped", [True, False], ids=["stamped", "unstamped"])
    def test_refresh_eviction_drops_the_stamp(self, stamped):
        """The URI a refresh evicts loses its stamp, and an evicted URI that
        never had one is not an error."""
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        with upstream.client() as client:
            cache = ValidationCache(config=SINGLE_ENTRY)
            cache.jwks[jwks_cache_key(OLD_URI, client.trust_scope)] = (
                _fresh_jwks_entry()
            )
            if stamped:
                cache.kid_miss_last_attempt[OLD_URI] = time.monotonic()

            response, from_retained = sync_tv._refresh_jwks(
                NEW_URI, DiscoveryPolicy(), client, cache
            )

            assert (response.is_successful, from_retained) == (True, False)
            assert list(cache.jwks) == [jwks_cache_key(NEW_URI, client.trust_scope)]
            assert cache.kid_miss_last_attempt == {}


class TestAsyncRefreshEviction:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("stamped", [True, False], ids=["stamped", "unstamped"])
    async def test_refresh_eviction_drops_the_stamp(self, stamped):
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        async with upstream.async_client() as client:
            cache = AsyncValidationCache(config=SINGLE_ENTRY)
            cache.jwks[jwks_cache_key(OLD_URI, client.trust_scope)] = (
                _fresh_jwks_entry()
            )
            if stamped:
                cache.kid_miss_last_attempt[OLD_URI] = time.monotonic()

            response, from_retained = await aio_tv._refresh_jwks(
                NEW_URI, DiscoveryPolicy(), client, cache
            )

            assert (response.is_successful, from_retained) == (True, False)
            assert list(cache.jwks) == [jwks_cache_key(NEW_URI, client.trust_scope)]
            assert cache.kid_miss_last_attempt == {}


# ============================================================================
# Lock-free hit + LRU recency (sync)
# ============================================================================


class TestSyncLockFreeHit:
    """A fresh hit returns while another thread holds the URI's fetch lock (it
    takes no lock) and moves the entry to the most-recently-used end."""

    @staticmethod
    def _call_while_locked(lock: threading.Lock, call: Any) -> list[Any]:
        results: list[Any] = []
        with lock:
            worker = threading.Thread(target=lambda: results.append(call()))
            worker.start()
            worker.join(BLOCKED_WAIT_SECONDS)
            returned_while_locked = not worker.is_alive()
        worker.join()
        assert returned_while_locked
        return results

    def test_disco_hit_takes_no_lock_and_refreshes_recency(self):
        hot, other = CANDIDATE_ORIGINS[0], CANDIDATE_ORIGINS[1]
        with HTTPClient() as client:
            cache = ValidationCache()
            cache.disco[_disco_key(hot)] = hot_entry = _fresh_disco_entry(hot)
            cache.disco[_disco_key(other)] = _fresh_disco_entry(other)

            results = self._call_while_locked(
                cache.disco_fetch_lock(_disco_key(hot)),
                lambda: sync_tv._get_disco_response(
                    f"{hot}{DISCO_PATH}", DiscoveryPolicy(), client, cache
                ),
            )

            assert results == [hot_entry.response]
            assert list(cache.disco) == [_disco_key(other), _disco_key(hot)]

    def test_jwks_hit_takes_no_lock_and_refreshes_recency(self):
        hot = f"{CANDIDATE_ORIGINS[0]}{JWKS_PATH}"
        other = f"{CANDIDATE_ORIGINS[1]}{JWKS_PATH}"
        with HTTPClient() as client:
            cache = ValidationCache()
            cache.jwks[jwks_cache_key(hot)] = hot_entry = _fresh_jwks_entry()
            cache.jwks[jwks_cache_key(other)] = _fresh_jwks_entry()

            results = self._call_while_locked(
                cache.jwks_fetch_lock(jwks_cache_key(hot)),
                lambda: sync_tv._get_cached_jwks(hot, DiscoveryPolicy(), client, cache),
            )

            assert results == [hot_entry.response]
            assert list(cache.jwks) == [jwks_cache_key(other), jwks_cache_key(hot)]


class TestSyncDoubleCheckedHit:
    """A hit found under the fetch lock (another thread populated the entry
    while this one waited) is served without a fetch and moves the entry to
    the most-recently-used end. ``is_cache_expired`` reports the entry stale
    on the lock-free check and fresh on the re-check, the state a concurrent
    populate leaves behind."""

    @respx.mock
    def test_disco_double_checked_hit_refreshes_recency(self, monkeypatch):
        hot, other = CANDIDATE_ORIGINS[0], CANDIDATE_ORIGINS[1]
        monkeypatch.setattr(
            sync_tv, "is_cache_expired", Mock(side_effect=[True, False])
        )
        with HTTPClient() as client:
            cache = ValidationCache()
            cache.disco[_disco_key(hot)] = hot_entry = _fresh_disco_entry(hot)
            cache.disco[_disco_key(other)] = _fresh_disco_entry(other)

            result = sync_tv._get_disco_response(
                f"{hot}{DISCO_PATH}", DiscoveryPolicy(), client, cache
            )

            assert result is hot_entry.response
            assert list(cache.disco) == [_disco_key(other), _disco_key(hot)]

    @respx.mock
    def test_jwks_double_checked_hit_refreshes_recency(self, monkeypatch):
        hot = f"{CANDIDATE_ORIGINS[0]}{JWKS_PATH}"
        other = f"{CANDIDATE_ORIGINS[1]}{JWKS_PATH}"
        monkeypatch.setattr(
            sync_tv, "is_cache_expired", Mock(side_effect=[True, False])
        )
        with HTTPClient() as client:
            cache = ValidationCache()
            cache.jwks[jwks_cache_key(hot)] = hot_entry = _fresh_jwks_entry()
            cache.jwks[jwks_cache_key(other)] = _fresh_jwks_entry()

            result = sync_tv._get_cached_jwks(hot, DiscoveryPolicy(), client, cache)

            assert result is hot_entry.response
            assert list(cache.jwks) == [jwks_cache_key(other), jwks_cache_key(hot)]


# ============================================================================
# Single-flight: a miss waits on its URI's fetch lock
# ============================================================================


class TestSyncMissWaitsOnFetchLock:
    @staticmethod
    def _assert_blocked_until_released(
        lock: threading.Lock, upstream: _Upstream, call: Any
    ) -> None:
        with lock:
            worker = threading.Thread(target=call)
            worker.start()
            fetched_while_locked = upstream.fetched.wait(BLOCKED_WAIT_SECONDS)
        worker.join()
        assert fetched_while_locked is False
        assert len(upstream.requests) == 1

    def test_disco_miss_waits_on_the_address_lock(self):
        upstream = _Upstream([[]])
        with upstream.client() as client:
            cache = ValidationCache()
            origin = _origin_off_the_none_stripe(
                lambda o: cache.disco_fetch_lock(_disco_key(o, client.trust_scope)),
                cache.disco_fetch_lock(_NO_KEY),
            )
            self._assert_blocked_until_released(
                cache.disco_fetch_lock(_disco_key(origin, client.trust_scope)),
                upstream,
                lambda: sync_tv._get_disco_response(
                    f"{origin}{DISCO_PATH}", DiscoveryPolicy(), client, cache
                ),
            )

    def test_refresh_waits_on_the_uri_lock(self):
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        with upstream.client() as client:
            cache = ValidationCache()
            origin = _origin_off_the_none_stripe(
                lambda o: cache.jwks_fetch_lock(
                    jwks_cache_key(f"{o}{JWKS_PATH}", client.trust_scope)
                ),
                cache.jwks_fetch_lock(_NO_KEY),
            )
            uri = f"{origin}{JWKS_PATH}"
            self._assert_blocked_until_released(
                cache.jwks_fetch_lock(jwks_cache_key(uri, client.trust_scope)),
                upstream,
                lambda: sync_tv._refresh_jwks(uri, DiscoveryPolicy(), client, cache),
            )


class TestAsyncMissWaitsOnFetchLock:
    @staticmethod
    async def _assert_blocked_until_released(
        lock: asyncio.Lock, upstream: _Upstream, call: Any
    ) -> None:
        async with lock:
            task = asyncio.ensure_future(call())
            done, _ = await asyncio.wait({task}, timeout=BLOCKED_WAIT_SECONDS)
            fetched_while_locked = list(upstream.requests)
        await task
        assert (done, fetched_while_locked) == (set(), [])
        assert len(upstream.requests) == 1

    @pytest.mark.asyncio
    async def test_disco_miss_waits_on_the_address_lock(self):
        upstream = _Upstream([[]])
        async with upstream.async_client() as client:
            cache = AsyncValidationCache()
            origin = _origin_off_the_none_stripe(
                lambda o: cache.disco_fetch_lock(_disco_key(o, client.trust_scope)),
                cache.disco_fetch_lock(_NO_KEY),
            )
            await self._assert_blocked_until_released(
                cache.disco_fetch_lock(_disco_key(origin, client.trust_scope)),
                upstream,
                lambda: aio_tv._get_disco_response(
                    f"{origin}{DISCO_PATH}", DiscoveryPolicy(), client, cache
                ),
            )

    @pytest.mark.asyncio
    async def test_refresh_waits_on_the_uri_lock(self):
        upstream = _Upstream([[_with_kid(_SIGNING_KEY, KID)]])
        async with upstream.async_client() as client:
            cache = AsyncValidationCache()
            origin = _origin_off_the_none_stripe(
                lambda o: cache.jwks_fetch_lock(
                    jwks_cache_key(f"{o}{JWKS_PATH}", client.trust_scope)
                ),
                cache.jwks_fetch_lock(_NO_KEY),
            )
            uri = f"{origin}{JWKS_PATH}"
            await self._assert_blocked_until_released(
                cache.jwks_fetch_lock(jwks_cache_key(uri, client.trust_scope)),
                upstream,
                lambda: aio_tv._refresh_jwks(uri, DiscoveryPolicy(), client, cache),
            )


# ============================================================================
# Cache-Control max-age beats the Config default TTL
# ============================================================================

PROVIDER_MAX_AGE = 600
CONFIG_TTL = 3600


class TestProviderMaxAgeSetsTtl:
    def test_jwks_entry_ttl_follows_max_age(self):
        cache: dict[tuple[TrustScope, str], JwksCacheEntry] = {}
        response = JwksResponse(
            is_successful=True,
            keys=[jwks_from_dict(_SIGNING_KEY)],
            cache_control=f"max-age={PROVIDER_MAX_AGE}",
        )

        apply_jwks_cache_outcome(
            cache,
            jwks_cache_key(JWKS_URI),
            response,
            0.0,
            Config(jwks_cache_ttl=CONFIG_TTL),
        )

        assert cache[jwks_cache_key(JWKS_URI)].ttl == PROVIDER_MAX_AGE

    def test_disco_entry_ttl_follows_max_age(self):
        cache: dict[tuple[TrustScope, str, tuple], DiscoCacheEntry] = {}
        response = DiscoveryDocumentResponse(
            is_successful=True,
            issuer=ORIGIN,
            cache_control=f"max-age={PROVIDER_MAX_AGE}",
        )

        apply_disco_cache_outcome(
            cache,
            _disco_key(ORIGIN),
            response,
            0.0,
            Config(discovery_cache_ttl=CONFIG_TTL),
        )

        assert cache[_disco_key(ORIGIN)].ttl == PROVIDER_MAX_AGE
