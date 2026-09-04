"""Fail-closed controls for the async cache fetch paths (T299).

T299 instrumented the three module-level singleton cache functions in
``py_identity_model.aio.token_validation`` with observability counters:
``_get_disco_response``, ``_get_cached_jwks`` and ``_refresh_jwks``. These are
security-gated (``tools/mutation_security.py``). This module pins the
security-relevant behaviour of those functions so a regression cannot silently:

* drop the HTTPS scheme enforcement (policy default flip / ``policy=None`` /
  dropped ``policy`` kwarg) — an SSRF / HTTPS->HTTP downgrade,
* stop threading the caller's ``require_https`` through to ``get_jwks`` — a
  legitimate ``require_https=False`` fetch would break,
* drop the ``cooldown`` sidecar cleanup on eviction — an unbounded-growth
  memory leak keyed by attacker-controlled URIs,
* lose the double-checked-lock cache hit / LRU-recency refresh — cache-stampede
  and hot-entry-eviction regressions (#397),
* break the empty-keys retained-cache fallback (``and``->``or``) or the
  refresh coalescing guard (``>=``->``>``).

The double-checked-hit branch is normally only reachable under concurrency
(one coroutine populates the entry while another waits on the fetch lock). We
reach it deterministically instead by stubbing ``is_cache_expired`` to report
the pre-seeded entry as *expired* on the lock-free fast-path check and *fresh*
on the under-lock re-check — exactly the state a concurrent populate produces.
"""

import time
from unittest.mock import Mock

import httpx
import pytest
import respx

from py_identity_model import get_cache_counters
from py_identity_model.aio import token_validation as aio_tv
from py_identity_model.aio.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    _refresh_jwks,
    clear_discovery_cache,
    clear_jwks_cache,
)
from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.jwks_cache import (
    DiscoCacheEntry,
    JwksCacheEntry,
    _reset_env_for_testing,
)
from py_identity_model.core.models import (
    DiscoveryDocumentResponse,
    JwksResponse,
)
from py_identity_model.core.parsers import jwks_from_dict
from py_identity_model.exceptions import ConfigurationException

from ..unit.token_validation_helpers import generate_rsa_keypair


pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
async def _clean_state():
    """Reset all shared module-global cache state + counters between tests."""
    await clear_discovery_cache()
    await clear_jwks_cache()
    aio_tv._kid_miss_last_attempt.clear()
    get_cache_counters().reset()
    _reset_env_for_testing()
    yield
    await clear_discovery_cache()
    await clear_jwks_cache()
    aio_tv._kid_miss_last_attempt.clear()
    get_cache_counters().reset()
    _reset_env_for_testing()


# Generate ONE RSA keypair for the whole module. These tests exercise cache /
# counter / single-flight behaviour and never verify a signature, so the key
# content is irrelevant — any valid JWK works. Generating per-test would add
# ~15 RSA-2048 keygens of CPU contention under ``-n auto``, which is enough to
# slow the wall-clock-sensitive kid-miss-cooldown tests past their 5s window.
_KEY_DICT, _ = generate_rsa_keypair()


def _jwk():
    return jwks_from_dict(_KEY_DICT)


def _jwks_resp(keys):
    return JwksResponse(is_successful=True, keys=keys)


def _disco_resp(issuer="https://opx.example"):
    return DiscoveryDocumentResponse(is_successful=True, issuer=issuer)


# ---------------------------------------------------------------------------
# Scheme enforcement (SSRF / HTTPS->HTTP downgrade)
# ---------------------------------------------------------------------------


class TestSchemeEnforcement:
    """A plaintext ``http://`` JWKS endpoint must be rejected under the default
    (``require_https`` omitted) policy, and only fetched when the caller
    explicitly relaxes the policy — pinning the ``require_https`` default and
    the policy thread-through against flip / ``None`` / dropped-kwarg mutants."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_cached_jwks_default_rejects_plaintext_http(self):
        route = respx.get("http://op.example/jwks").mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_KEY_DICT]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        # Default require_https=True -> plaintext non-loopback HTTP is rejected
        # by the pre-flight scheme check inside get_jwks BEFORE any network I/O.
        result = await _get_cached_jwks("http://op.example/jwks")
        assert result.is_successful is False
        assert route.call_count == 0
        # Fail-closed observability: a scheme-rejected request issues zero
        # upstream work, so it MUST NOT bump the upstream-fetch miss counter
        # (else an attacker inflates the miss rate with forged http:// URIs).
        assert get_cache_counters().snapshot()["jwks_misses"] == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_refresh_default_rejects_plaintext_http(self):
        route = respx.get("http://op.example/jwks").mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_KEY_DICT]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        response, from_retained = await _refresh_jwks("http://op.example/jwks")
        assert response.is_successful is False
        assert from_retained is False
        assert route.call_count == 0
        # Fail-closed: a scheme-rejected refresh does zero upstream work, so the
        # refresh (upstream re-fetch) counter MUST NOT increment.
        assert get_cache_counters().snapshot()["jwks_refreshes"] == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_disco_default_rejects_plaintext_http(self):
        route = respx.get("http://op.example/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json={"issuer": "http://op.example"})
        )
        # Default require_https=True -> plaintext non-loopback HTTP disco is
        # rejected by the pre-flight scheme check BEFORE any network I/O.
        result = await _get_disco_response(
            "http://op.example/.well-known/openid-configuration"
        )
        assert result.is_successful is False
        assert route.call_count == 0
        # Fail-closed: a scheme-rejected disco request does zero upstream work,
        # so the disco miss (upstream-fetch) counter MUST NOT increment.
        assert get_cache_counters().snapshot()["disco_misses"] == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_refresh_threads_require_https_false_allows_http(self):
        key = _KEY_DICT
        route = respx.get("http://op.example/jwks").mock(
            return_value=httpx.Response(
                200,
                json={"keys": [key]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        # Caller explicitly opts out of HTTPS; the policy MUST be threaded
        # through to get_jwks (not dropped/None, which would re-impose the
        # strict default and reject this legitimate fetch).
        response, _ = await _refresh_jwks(
            "http://op.example/jwks", DiscoveryPolicy(require_https=False)
        )
        assert response.is_successful is True
        assert response.keys
        assert route.call_count == 1
        # An upstream fetch WAS issued, so the refresh counter increments.
        assert get_cache_counters().snapshot()["jwks_refreshes"] == 1


# ---------------------------------------------------------------------------
# Cooldown sidecar eviction (unbounded-growth / memory leak)
# ---------------------------------------------------------------------------


class TestCooldownSidecarEviction:
    """When the JWKS cache evicts an entry, its ``_kid_miss_last_attempt``
    cooldown sidecar entry must be evicted too. Dropping the ``cooldown`` kwarg
    (or passing ``None``) leaks the sidecar unboundedly under attacker-driven
    distinct-URI churn even though the cache itself is bounded."""

    def _seed(self, monkeypatch, old_uri):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "1")
        _reset_env_for_testing()
        aio_tv._jwks_cache[old_uri] = JwksCacheEntry(
            response=_jwks_resp([_jwk()]),
            cached_at=time.monotonic(),
            ttl=1e9,
        )
        aio_tv._kid_miss_last_attempt[old_uri] = 123.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_cached_jwks_eviction_clears_cooldown(self, monkeypatch):
        old_uri = "https://old.example/jwks"
        new_uri = "https://new.example/jwks"
        self._seed(monkeypatch, old_uri)
        respx.get(new_uri).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_KEY_DICT]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        await _get_cached_jwks(new_uri)
        # old_uri was evicted (max=1); its cooldown sidecar entry must be gone.
        assert old_uri not in aio_tv._jwks_cache
        assert old_uri not in aio_tv._kid_miss_last_attempt

    @respx.mock
    @pytest.mark.asyncio
    async def test_refresh_eviction_clears_cooldown(self, monkeypatch):
        old_uri = "https://old.example/jwks"
        new_uri = "https://new.example/jwks"
        self._seed(monkeypatch, old_uri)
        respx.get(new_uri).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_KEY_DICT]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        await _refresh_jwks(new_uri)
        assert old_uri not in aio_tv._jwks_cache
        assert old_uri not in aio_tv._kid_miss_last_attempt


# ---------------------------------------------------------------------------
# _refresh_jwks empty-keys fallback + coalescing guard
# ---------------------------------------------------------------------------


class TestRefreshSemantics:
    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_refresh_does_not_falsely_fall_back(self):
        """``and``->``or`` guard: a retained entry with EMPTY keys must NOT be
        surfaced as a fallback. Only a retained entry with real keys does.

        Original: ``retained is not None and retained.response.keys`` -> the
        empty retained entry is falsy -> no fallback -> returns the empty
        upstream response with ``from_retained=False``. The mutated ``or`` would
        fall back and mislabel it ``from_retained=True``.
        """
        uri = "https://op.example/jwks"
        aio_tv._jwks_cache[uri] = JwksCacheEntry(
            response=_jwks_resp([]),  # retained but EMPTY
            cached_at=time.monotonic() - 1000.0,  # old -> not coalesced
            ttl=1e9,
        )
        respx.get(uri).mock(return_value=httpx.Response(200, json={"keys": []}))

        response, from_retained = await _refresh_jwks(uri)
        assert from_retained is False
        assert (response.keys or []) == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_refresh_coalesces_on_equal_timestamp(self, monkeypatch):
        """``>=``->``>`` guard: when a concurrent refresh already wrote an entry
        whose ``cached_at`` equals this refresh's ``request_time`` (captured
        inside the lock), this call must coalesce and return WITHOUT issuing an
        upstream fetch. Forcing ``time.monotonic()`` to the entry's exact
        ``cached_at`` exercises the boundary the ``>=`` protects."""
        uri = "https://op.example/jwks"
        seeded = _jwks_resp([_jwk()])
        fixed_t = 5000.0
        aio_tv._jwks_cache[uri] = JwksCacheEntry(
            response=seeded, cached_at=fixed_t, ttl=1e9
        )
        route = respx.get(uri).mock(
            return_value=httpx.Response(
                200,
                json={"keys": [_KEY_DICT]},
                headers={"Cache-Control": "max-age=3600"},
            )
        )
        monkeypatch.setattr(aio_tv.time, "monotonic", lambda: fixed_t)

        response, from_retained = await _refresh_jwks(uri)
        assert response is seeded
        assert from_retained is False
        assert route.call_count == 0


# ---------------------------------------------------------------------------
# Discovery required-address error message
# ---------------------------------------------------------------------------


class TestDiscoRequiredAddress:
    @pytest.mark.asyncio
    async def test_none_address_raises_with_actionable_message(self):
        with pytest.raises(ConfigurationException) as exc:
            await _get_disco_response(None)
        assert (
            str(exc.value) == "disco_doc_address is required when perform_disco is True"
        )


# ---------------------------------------------------------------------------
# Double-checked-lock hit + LRU recency (cache stampede / hot-entry eviction)
# ---------------------------------------------------------------------------


def _expired_then_fresh():
    """is_cache_expired stub: True on the fast-path check (entry looks stale),
    False on the under-lock re-check (entry is fresh) — the exact state a
    concurrent populate leaves for the second coroutine."""
    return Mock(side_effect=[True, False])


class TestDoubleCheckedLockAndLru:
    @respx.mock
    @pytest.mark.asyncio
    async def test_disco_double_checked_hit_refreshes_recency(self, monkeypatch):
        """The under-lock double-checked hit returns the cached response with NO
        upstream fetch and refreshes LRU recency (moves the key to MRU).

        Kills: under-lock ``entry=None`` / ``get(None)`` (would re-fetch),
        ``touch_cache_entry`` arg mutations that raise, and the no-op
        ``touch(cache, None)`` (recency would not move).
        """
        addr_x = "https://opx.example/.well-known/openid-configuration"
        addr_y = "https://opy.example/.well-known/openid-configuration"
        key_x = (addr_x, DiscoveryPolicy().cache_key())
        key_y = (addr_y, DiscoveryPolicy().cache_key())
        resp_x = _disco_resp("https://opx.example")
        # Seed order: x (oldest) then y (newest).
        aio_tv._disco_cache[key_x] = DiscoCacheEntry(
            response=resp_x, cached_at=time.monotonic(), ttl=1e9
        )
        aio_tv._disco_cache[key_y] = DiscoCacheEntry(
            response=_disco_resp("https://opy.example"),
            cached_at=time.monotonic(),
            ttl=1e9,
        )
        route = respx.get(addr_x).mock(
            return_value=httpx.Response(200, json={"issuer": "https://opx.example"})
        )
        monkeypatch.setattr(aio_tv, "is_cache_expired", _expired_then_fresh())

        result = await _get_disco_response(addr_x)

        assert result is resp_x  # served from cache, exact object
        assert route.call_count == 0  # no upstream fetch
        # x moved to MRU (end); y is now the LRU-first entry.
        assert list(aio_tv._disco_cache.keys()) == [key_y, key_x]

    @respx.mock
    @pytest.mark.asyncio
    async def test_disco_fast_path_hit_refreshes_recency(self, monkeypatch):
        """The lock-free fast-path hit refreshes LRU recency. Kills the
        fast-path ``touch(cache, None)`` no-op (hot entry would not move and
        an attacker reading distinct addresses could evict it)."""
        addr_x = "https://opx.example/.well-known/openid-configuration"
        addr_y = "https://opy.example/.well-known/openid-configuration"
        key_x = (addr_x, DiscoveryPolicy().cache_key())
        key_y = (addr_y, DiscoveryPolicy().cache_key())
        resp_x = _disco_resp("https://opx.example")
        aio_tv._disco_cache[key_x] = DiscoCacheEntry(
            response=resp_x, cached_at=time.monotonic(), ttl=1e9
        )
        aio_tv._disco_cache[key_y] = DiscoCacheEntry(
            response=_disco_resp("https://opy.example"),
            cached_at=time.monotonic(),
            ttl=1e9,
        )
        route = respx.get(addr_x).mock(
            return_value=httpx.Response(200, json={"issuer": "https://opx.example"})
        )
        # Fresh on the fast path -> fast-path hit taken.
        monkeypatch.setattr(aio_tv, "is_cache_expired", Mock(side_effect=[False]))

        result = await _get_disco_response(addr_x)

        assert result is resp_x
        assert route.call_count == 0
        assert list(aio_tv._disco_cache.keys()) == [key_y, key_x]

    @respx.mock
    @pytest.mark.asyncio
    async def test_jwks_double_checked_hit_refreshes_recency(self, monkeypatch):
        """Async twin of the disco double-checked-hit test for
        ``_get_cached_jwks`` — kills the no-op ``touch(cache, None)`` on the
        under-lock double-checked-hit branch."""
        uri_x = "https://opx.example/jwks"
        uri_y = "https://opy.example/jwks"
        resp_x = _jwks_resp([_jwk()])
        aio_tv._jwks_cache[uri_x] = JwksCacheEntry(
            response=resp_x, cached_at=time.monotonic(), ttl=1e9
        )
        aio_tv._jwks_cache[uri_y] = JwksCacheEntry(
            response=_jwks_resp([_jwk()]), cached_at=time.monotonic(), ttl=1e9
        )
        route = respx.get(uri_x).mock(
            return_value=httpx.Response(200, json={"keys": []})
        )
        monkeypatch.setattr(aio_tv, "is_cache_expired", _expired_then_fresh())

        result = await _get_cached_jwks(uri_x)

        assert result is resp_x
        assert route.call_count == 0
        assert list(aio_tv._jwks_cache.keys()) == [uri_y, uri_x]
