"""
Proves the JWKS/discovery cache rejects unsafe env config and bounds memory.

Two pre-existing structural bugs the cache primitive shipped with:

1. **Env-provided TTL was not clamped.** ``JWKS_CACHE_TTL=0`` silently
   disabled the cache (every entry instantly expired → refetch on every
   validation → DoS amplifier). ``JWKS_CACHE_TTL=2592000`` silently
   disabled the documented 24h ceiling on key-rotation latency. Garbage
   values raised ``ValueError`` at first cache access — process crash on
   bad config rather than fail-fast at import.

2. **Cache dicts grew without bound.** Any deployment with caller-influenced
   ``disco_doc_address`` (multi-tenant gateways, attacker-supplied issuer
   headers) could grow the dict forever. At ~5KB per entry, a few thousand
   unique addresses leaked tens of MB.

These tests pin the fixes:
- TTL env values clamped to [MIN, MAX]; garbage falls back to default.
- Cache size capped at ``JWKS_CACHE_MAX_ENTRIES`` (default 64).
- LRU eviction targets the least recently *used* entry, not the newest or a
  random one.
- Re-storing a URI (refresh) moves it to "newest" so subsequent eviction
  doesn't target a just-refreshed entry.
- A read cache hit refreshes recency (``touch_cache_entry``) so an attacker
  driving distinct-address reads cannot evict a legitimately-hot entry (#397).
"""

from collections import OrderedDict
import time

import httpx
import pytest
import respx

from py_identity_model.core.discovery_policy import DiscoveryPolicy
from py_identity_model.core.jwks_cache import (
    DEFAULT_DISCO_CACHE_TTL_SECONDS,
    DEFAULT_JWKS_CACHE_TTL_SECONDS,
    DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    DEFAULT_MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL_SECONDS,
    MAX_KID_MISS_COOLDOWN_SECONDS,
    MIN_CACHE_TTL_SECONDS,
    MIN_KID_MISS_COOLDOWN_SECONDS,
    JwksCacheEntry,
    _enforce_size_limit,
    _reset_env_for_testing,
    apply_jwks_cache_outcome,
    get_kid_miss_cooldown,
    get_max_cache_entries,
    resolve_disco_ttl,
    resolve_ttl,
    touch_cache_entry,
)
from py_identity_model.core.models import JsonWebKey, JwksResponse
from py_identity_model.sync import token_validation as sync_tv
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    clear_discovery_cache,
    clear_jwks_cache,
)

from .token_validation_helpers import generate_rsa_keypair


@pytest.fixture(autouse=True)
def _reset_state():
    clear_discovery_cache()
    clear_jwks_cache()
    _reset_env_for_testing()
    yield
    clear_discovery_cache()
    clear_jwks_cache()
    _reset_env_for_testing()


# ============================================================================
# TTL env clamping: zero, negative, overflow, and garbage must not break
# the documented invariants.
# ============================================================================

JWKS_TTL_CLAMP_CASES = [
    pytest.param("0", MIN_CACHE_TTL_SECONDS, id="zero-clamped-to-min"),
    pytest.param("-5", MIN_CACHE_TTL_SECONDS, id="negative-clamped-to-min"),
    pytest.param("30", MIN_CACHE_TTL_SECONDS, id="below-min-clamped-up"),
    pytest.param("60", MIN_CACHE_TTL_SECONDS, id="at-min-preserved"),
    pytest.param("3600", 3600.0, id="middle-passthrough"),
    pytest.param("86400", MAX_CACHE_TTL_SECONDS, id="at-max-preserved"),
    pytest.param("999999", MAX_CACHE_TTL_SECONDS, id="above-max-clamped-down"),
    pytest.param("2592000", MAX_CACHE_TTL_SECONDS, id="month-clamped-down"),
]


class TestEnvTtlClamping:
    @pytest.mark.parametrize(("env_value", "expected"), JWKS_TTL_CLAMP_CASES)
    def test_jwks_ttl_env_clamped(self, env_value, expected, monkeypatch):
        """resolve_ttl(None) reads the env path; values outside [MIN, MAX]
        must be clamped to the documented bounds, not honored raw."""
        monkeypatch.setenv("JWKS_CACHE_TTL", env_value)
        _reset_env_for_testing()
        assert resolve_ttl(None) == expected

    @pytest.mark.parametrize(("env_value", "expected"), JWKS_TTL_CLAMP_CASES)
    def test_disco_ttl_env_clamped(self, env_value, expected, monkeypatch):
        monkeypatch.setenv("DISCO_CACHE_TTL", env_value)
        _reset_env_for_testing()
        assert resolve_disco_ttl(None) == expected

    def test_garbage_jwks_ttl_falls_back_to_default(self, monkeypatch):
        """Malformed env must not crash the process; a warning + default is
        the correct fail-safe."""
        monkeypatch.setenv("JWKS_CACHE_TTL", "60s")
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_empty_jwks_ttl_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_TTL", "")
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_garbage_disco_ttl_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DISCO_CACHE_TTL", "not-a-number")
        _reset_env_for_testing()
        assert resolve_disco_ttl(None) == DEFAULT_DISCO_CACHE_TTL_SECONDS

    def test_unset_jwks_ttl_uses_default(self, monkeypatch):
        monkeypatch.delenv("JWKS_CACHE_TTL", raising=False)
        _reset_env_for_testing()
        assert resolve_ttl(None) == DEFAULT_JWKS_CACHE_TTL_SECONDS


# ============================================================================
# KID_MISS_REFRESH_COOLDOWN env parsing must apply the same fail-safe pattern
# as JWKS_CACHE_TTL — without it, ``=abc`` crashes every kid-miss caller,
# ``=nan`` makes the cooldown permanent (``now-last >= nan`` is False forever),
# and ``=999999`` silently sets a multi-day cooldown that exceeds the
# documented rotation-latency expectation.
# ============================================================================


COOLDOWN_CLAMP_CASES = [
    pytest.param(
        "0", MIN_KID_MISS_COOLDOWN_SECONDS, id="zero-explicit-opt-out-honored"
    ),
    pytest.param("-5", MIN_KID_MISS_COOLDOWN_SECONDS, id="negative-clamped-to-min"),
    pytest.param("1", 1.0, id="middle-passthrough"),
    pytest.param("3600", MAX_KID_MISS_COOLDOWN_SECONDS, id="at-max-preserved"),
    pytest.param("999999", MAX_KID_MISS_COOLDOWN_SECONDS, id="above-max-clamped-down"),
]


class TestKidMissCooldownEnvParsing:
    @pytest.mark.parametrize(("env_value", "expected"), COOLDOWN_CLAMP_CASES)
    def test_cooldown_env_clamped(self, env_value, expected, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", env_value)
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == expected

    def test_garbage_falls_back_to_default(self, monkeypatch):
        """``=abc`` must not crash with ValueError at first kid-miss caller."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "abc")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_units_suffix_falls_back_to_default(self, monkeypatch):
        """``=5s`` is plausible operator config and must fail safe."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "5s")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_nan_falls_back_to_default(self, monkeypatch):
        """``=nan`` must not produce a permanent cooldown — the comparison
        ``now - last >= nan`` is False forever, silently disabling refresh."""
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "nan")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_infinity_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "inf")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_empty_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("KID_MISS_REFRESH_COOLDOWN", "")
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS

    def test_unset_uses_default(self, monkeypatch):
        monkeypatch.delenv("KID_MISS_REFRESH_COOLDOWN", raising=False)
        _reset_env_for_testing()
        assert get_kid_miss_cooldown() == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS


# ============================================================================
# Bounded cache: size capped, FIFO eviction targets oldest entry.
# ============================================================================


def _make_jwks_response(kid: str) -> JwksResponse:
    """Build a successful, cacheable JWKS response carrying a single key."""
    key_dict, _ = generate_rsa_keypair()
    key_dict["kid"] = kid
    jwk = JsonWebKey(
        kty=key_dict["kty"],
        kid=key_dict["kid"],
        alg=key_dict["alg"],
        use=key_dict["use"],
        n=key_dict["n"],
        e=key_dict["e"],
    )
    return JwksResponse(
        is_successful=True,
        keys=[jwk],
        cache_control="max-age=3600",
    )


class TestBoundedCacheSize:
    def test_max_entries_env_override(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "8")
        _reset_env_for_testing()
        assert get_max_cache_entries() == 8  # noqa: PLR2004

    def test_max_entries_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("JWKS_CACHE_MAX_ENTRIES", raising=False)
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_max_entries_falls_back_on_garbage(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "abc")
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_max_entries_falls_back_on_non_positive(self, monkeypatch):
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "0")
        _reset_env_for_testing()
        assert get_max_cache_entries() == DEFAULT_MAX_CACHE_ENTRIES

    def test_jwks_cache_size_capped_under_overflow(self, monkeypatch):
        """Insert max+5 distinct URIs into the cache via the apply helper —
        post-insert the cache holds exactly ``max`` entries."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "5")
        _reset_env_for_testing()
        cache: dict[str, JwksCacheEntry] = {}

        for i in range(10):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=f"https://op-{i}.example/jwks",
                response=_make_jwks_response(f"kid-{i}"),
                now=time.monotonic(),
            )

        assert len(cache) == 5  # noqa: PLR2004
        # FIFO eviction: the *oldest* 5 inserts are gone, *newest* 5 remain.
        remaining_uris = set(cache.keys())
        expected_uris = {f"https://op-{i}.example/jwks" for i in range(5, 10)}
        assert remaining_uris == expected_uris

    def test_refresh_of_existing_uri_does_not_count_as_new_entry(self, monkeypatch):
        """Re-storing a URI must move it to the end of insertion order so
        a subsequent overflow doesn't immediately evict a just-refreshed
        entry. This is the difference between OK-FIFO and broken-FIFO."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "3")
        _reset_env_for_testing()
        cache: dict[str, JwksCacheEntry] = {}

        # Fill to capacity in known order.
        for i in range(3):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=f"https://op-{i}.example/jwks",
                response=_make_jwks_response(f"kid-{i}"),
                now=time.monotonic(),
            )
        assert list(cache.keys()) == [
            "https://op-0.example/jwks",
            "https://op-1.example/jwks",
            "https://op-2.example/jwks",
        ]

        # Refresh op-0 (the oldest). It should move to the newest position.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri="https://op-0.example/jwks",
            response=_make_jwks_response("kid-0-rotated"),
            now=time.monotonic(),
        )
        assert list(cache.keys()) == [
            "https://op-1.example/jwks",
            "https://op-2.example/jwks",
            "https://op-0.example/jwks",
        ]

        # Add a fourth distinct URI. Eviction should now target op-1 (the
        # oldest non-refreshed), not the just-refreshed op-0.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri="https://op-3.example/jwks",
            response=_make_jwks_response("kid-3"),
            now=time.monotonic(),
        )
        assert set(cache.keys()) == {
            "https://op-2.example/jwks",
            "https://op-0.example/jwks",
            "https://op-3.example/jwks",
        }

    @respx.mock
    def test_end_to_end_jwks_cache_capped(self, monkeypatch):
        """End-to-end via _get_cached_jwks: hammering N+5 unique URIs from
        the real call site enforces the same bound as the apply helper
        directly. Catches any path that bypasses _enforce_size_limit."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()

        urls_to_visit = [f"https://op-{i}.example/jwks" for i in range(9)]
        key_dict, _ = generate_rsa_keypair()
        for url in urls_to_visit:
            respx.get(url).mock(
                return_value=httpx.Response(
                    200,
                    json={"keys": [key_dict]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            )

        for url in urls_to_visit:
            response = _get_cached_jwks(url)
            assert response.is_successful is True

        assert len(sync_tv._jwks_cache) == 4  # noqa: PLR2004
        # Newest four URIs are the survivors.
        assert set(sync_tv._jwks_cache.keys()) == set(urls_to_visit[-4:])


# ============================================================================
# LRU eviction: a read cache hit refreshes recency so an attacker driving
# distinct-address reads cannot evict a legitimately-hot entry (#397).
# ============================================================================


class TestLruReadHitEviction:
    def test_touch_cache_entry_moves_key_to_most_recent(self):
        """The shared helper reorders an OrderedDict so the touched key sorts
        last (most-recently-used); ``_enforce_size_limit`` then evicts what
        sorts first. Deterministic — OrderedDict order is access/insertion
        order, independent of PYTHONHASHSEED."""
        cache: OrderedDict[str, int] = OrderedDict((f"k{i}", i) for i in range(3))
        assert list(cache.keys()) == ["k0", "k1", "k2"]

        touch_cache_entry(cache, "k0")
        assert list(cache.keys()) == ["k1", "k2", "k0"]

    def test_touch_cache_entry_absent_key_is_noop(self):
        """The read hot-path does a lock-free ``.get()`` then touches under the
        write lock; the entry may have been evicted in between, so touching an
        absent key must be a silent no-op, not a KeyError."""
        cache: OrderedDict[str, int] = OrderedDict((("k0", 0), ("k1", 1)))
        touch_cache_entry(cache, "missing")
        assert list(cache.keys()) == ["k0", "k1"]

    def test_lru_evicts_least_recently_used_not_least_recently_inserted(
        self, monkeypatch
    ):
        """After a touch, ``_enforce_size_limit`` evicts the untouched-oldest
        entry, proving eviction is by *use* not by *insertion* (tuple keys,
        mirroring the discovery cache)."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()
        cache: OrderedDict[tuple[str, bool], int] = OrderedDict()
        for i in range(4):
            cache[(f"https://op-{i}.example", True)] = i

        # op-0 is oldest by insertion; a read hit touches it to most-recent.
        touch_cache_entry(cache, ("https://op-0.example", True))
        # A fifth distinct address arrives (attacker-controlled tenant).
        cache[("https://op-4.example", True)] = 4

        evicted = _enforce_size_limit(cache)
        # LRU evicts op-1 (oldest *untouched*), NOT the recently-read op-0.
        assert evicted == [("https://op-1.example", True)]
        assert ("https://op-0.example", True) in cache

    @respx.mock
    def test_read_hit_protects_hot_entry_from_eviction(self, monkeypatch):
        """End-to-end via ``_get_cached_jwks``: an attacker driving distinct
        JWKS-URI reads must NOT evict a JWKS entry that was just read.

        Fill the cache to capacity, re-read the oldest-by-insertion entry (a
        cache hit → LRU touch), then push one more distinct URI. FIFO would
        evict the just-read entry; LRU evicts the oldest *unread* one."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()

        urls = [f"https://op-{i}.example/jwks" for i in range(5)]
        key_dict, _ = generate_rsa_keypair()
        for url in urls:
            respx.get(url).mock(
                return_value=httpx.Response(
                    200,
                    json={"keys": [key_dict]},
                    headers={"Cache-Control": "max-age=3600"},
                )
            )

        # Fill to capacity: op-0 (oldest) .. op-3 (newest).
        for url in urls[:4]:
            _get_cached_jwks(url)
        assert list(sync_tv._jwks_cache.keys()) == urls[:4]

        # Re-read op-0 — a cache hit (no network) that must refresh recency.
        _get_cached_jwks(urls[0])
        assert list(sync_tv._jwks_cache.keys()) == [
            urls[1],
            urls[2],
            urls[3],
            urls[0],
        ]

        # A fifth distinct URI overflows the cache; eviction targets op-1
        # (oldest unread), NOT the recently-read op-0.
        _get_cached_jwks(urls[4])
        assert urls[0] in sync_tv._jwks_cache
        assert urls[1] not in sync_tv._jwks_cache
        assert set(sync_tv._jwks_cache.keys()) == {urls[0], urls[2], urls[3], urls[4]}

    @respx.mock
    def test_read_hit_protects_hot_disco_entry_from_eviction(self, monkeypatch):
        """The discovery cache is LRU too (#397 calls out "same for the
        discovery cache"). End-to-end via ``_get_disco_response``: an attacker
        driving distinct ``disco_doc_address`` reads must NOT evict a discovery
        entry that was just read.

        Mirrors the JWKS end-to-end test but through the disco read path, so a
        regression that adds the read-hit touch to only one of the two caches is
        caught. The cache key is ``(address, policy.cache_key())`` — a tuple,
        exactly the shape a multi-tenant gateway attacker influences."""
        monkeypatch.setenv("JWKS_CACHE_MAX_ENTRIES", "4")
        _reset_env_for_testing()

        bases = [f"https://op-{i}.example" for i in range(5)]
        addresses = [f"{b}/.well-known/openid-configuration" for b in bases]
        for base, address in zip(bases, addresses, strict=True):
            respx.get(address).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "issuer": base,
                        "authorization_endpoint": f"{base}/authorize",
                        "token_endpoint": f"{base}/token",
                        "jwks_uri": f"{base}/jwks",
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    },
                )
            )

        keys = [(addr, DiscoveryPolicy().cache_key()) for addr in addresses]

        # Fill to capacity: op-0 (oldest) .. op-3 (newest).
        for address in addresses[:4]:
            _get_disco_response(address)
        assert list(sync_tv._disco_cache.keys()) == keys[:4]

        # Re-read op-0 — a cache hit (no network) that must refresh recency.
        _get_disco_response(addresses[0])
        assert list(sync_tv._disco_cache.keys()) == [
            keys[1],
            keys[2],
            keys[3],
            keys[0],
        ]

        # A fifth distinct address overflows the cache; eviction targets op-1
        # (oldest unread), NOT the recently-read op-0.
        _get_disco_response(addresses[4])
        assert keys[0] in sync_tv._disco_cache
        assert keys[1] not in sync_tv._disco_cache
        assert set(sync_tv._disco_cache.keys()) == {keys[0], keys[2], keys[3], keys[4]}
