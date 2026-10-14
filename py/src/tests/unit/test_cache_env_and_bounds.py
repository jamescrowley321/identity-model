"""
Proves the JWKS/discovery cache rejects unsafe config and bounds memory.

Two pre-existing structural bugs the cache primitive shipped with:

1. **Configured TTL was not bounded.** A TTL of ``0`` silently disabled the
   cache (every entry instantly expired → refetch on every validation → DoS
   amplifier). A month-long TTL silently disabled the documented 24h ceiling
   on key-rotation latency. The same applied to the kid-miss cooldown
   (``nan`` made it permanent, a huge value exceeded the rotation-latency
   expectation).

2. **Cache dicts grew without bound.** Any deployment with caller-influenced
   ``disco_doc_address`` (multi-tenant gateways, attacker-supplied issuer
   headers) could grow the dict forever. At ~5KB per entry, a few thousand
   unique addresses leaked tens of MB.

Settings now come from :class:`~py_identity_model.Config`, which is validated
on creation. These tests pin the fixes:
- TTL and cooldown values outside [MIN, MAX] (or non-finite / non-numeric) are
  rejected with ``ConfigError``; in-range values are used as configured.
- Each client's cache size is capped at ``Config.cache_max_entries``
  (default 64).
- LRU eviction targets the least recently *used* entry, not the newest or a
  random one.
- Re-storing a URI (refresh) moves it to "newest" so subsequent eviction
  doesn't target a just-refreshed entry.
- A read cache hit refreshes recency (``touch_cache_entry``) so an attacker
  driving distinct-address reads cannot evict a legitimately-hot entry (#397).
"""

from collections import OrderedDict
from collections.abc import Iterator
import math
import time

import httpx
import pytest
import respx

from py_identity_model import Config, ConfigError
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
    apply_jwks_cache_outcome,
    resolve_disco_ttl,
    resolve_ttl,
    touch_cache_entry,
)
from py_identity_model.core.models import JsonWebKey, JwksResponse
from py_identity_model.sync.managed_client import HTTPClient
from py_identity_model.sync.token_validation import (
    _get_cached_jwks,
    _get_disco_response,
    clear_discovery_cache,
    clear_jwks_cache,
)

from ..token_validation_helpers import generate_rsa_keypair


MID_TTL_SECONDS = 3600.0
MID_COOLDOWN_SECONDS = 1.0
SMALL_MAX_ENTRIES = 8
OVERFLOW_MAX_ENTRIES = 5
REFRESH_MAX_ENTRIES = 3
E2E_MAX_ENTRIES = 4
OVERFLOW_EXTRA = 5


@pytest.fixture(autouse=True)
def _reset_state():
    clear_discovery_cache()
    clear_jwks_cache()
    yield
    clear_discovery_cache()
    clear_jwks_cache()


@pytest.fixture
def small_cache_client() -> Iterator[HTTPClient]:
    """An injected client whose caches hold at most ``E2E_MAX_ENTRIES``."""
    with HTTPClient(config=Config(cache_max_entries=E2E_MAX_ENTRIES)) as client:
        yield client


def _setting_names(err: ConfigError) -> list[str]:
    return [issue.setting for issue in err.issues]


# ============================================================================
# TTL bounds: zero, negative, overflow, and garbage must not break the
# documented invariants. Config rejects them instead of silently honoring.
# ============================================================================

TTL_SETTINGS = ["jwks_cache_ttl", "discovery_cache_ttl"]

TTL_REJECTED_CASES = [
    pytest.param(0.0, id="zero"),
    pytest.param(-5.0, id="negative"),
    pytest.param(MIN_CACHE_TTL_SECONDS - 30, id="below-min"),
    pytest.param(MAX_CACHE_TTL_SECONDS + 1, id="above-max"),
    pytest.param(30 * MAX_CACHE_TTL_SECONDS, id="month"),
    pytest.param(math.nan, id="nan"),
    pytest.param(math.inf, id="inf"),
    pytest.param("60s", id="string-with-units"),
    pytest.param("", id="empty-string"),
]

TTL_ACCEPTED_CASES = [
    pytest.param(MIN_CACHE_TTL_SECONDS, id="at-min"),
    pytest.param(MID_TTL_SECONDS, id="middle"),
    pytest.param(MAX_CACHE_TTL_SECONDS, id="at-max"),
]


class TestConfigTtlBounds:
    @pytest.mark.parametrize("setting", TTL_SETTINGS)
    @pytest.mark.parametrize("value", TTL_REJECTED_CASES)
    def test_out_of_range_ttl_rejected(self, setting, value):
        """Values outside [MIN, MAX] or not finite numbers must fail fast at
        Config creation, never be honored raw by the cache."""
        with pytest.raises(ConfigError) as exc_info:
            Config(**{setting: value})
        assert _setting_names(exc_info.value) == [setting]

    @pytest.mark.parametrize("value", TTL_ACCEPTED_CASES)
    def test_jwks_ttl_in_range_used_without_max_age(self, value):
        """resolve_ttl with no Cache-Control falls back to the configured TTL."""
        config = Config(jwks_cache_ttl=value)
        assert resolve_ttl(None, config.jwks_cache_ttl) == value

    @pytest.mark.parametrize("value", TTL_ACCEPTED_CASES)
    def test_disco_ttl_in_range_used_without_max_age(self, value):
        config = Config(discovery_cache_ttl=value)
        assert resolve_disco_ttl(None, config.discovery_cache_ttl) == value

    def test_default_jwks_ttl(self):
        assert Config().jwks_cache_ttl == DEFAULT_JWKS_CACHE_TTL_SECONDS

    def test_default_disco_ttl(self):
        assert Config().discovery_cache_ttl == DEFAULT_DISCO_CACHE_TTL_SECONDS

    def test_configured_jwks_ttl_applied_to_cache_entry(self):
        """A response without max-age is stored with ``Config.jwks_cache_ttl``."""
        uri = "https://op.example/jwks"
        cache: dict[str, JwksCacheEntry] = {}
        response = _make_jwks_response("kid-ttl", cache_control=None)
        apply_jwks_cache_outcome(
            cache,
            uri,
            response,
            time.monotonic(),
            Config(jwks_cache_ttl=MID_TTL_SECONDS),
        )
        assert cache[uri].ttl == MID_TTL_SECONDS


# ============================================================================
# Kid-miss cooldown must apply the same fail-safe pattern as the TTLs —
# without it, garbage crashes every kid-miss caller, ``nan`` makes the
# cooldown permanent (``now-last >= nan`` is False forever), and a huge value
# silently sets a multi-day cooldown that exceeds the documented
# rotation-latency expectation.
# ============================================================================


COOLDOWN_REJECTED_CASES = [
    pytest.param(-5.0, id="negative"),
    pytest.param(MAX_KID_MISS_COOLDOWN_SECONDS + 1, id="above-max"),
    pytest.param(999999.0, id="far-above-max"),
    pytest.param(math.nan, id="nan"),
    pytest.param(math.inf, id="inf"),
    pytest.param("abc", id="garbage-string"),
    pytest.param("5s", id="string-with-units"),
    pytest.param("", id="empty-string"),
]

COOLDOWN_ACCEPTED_CASES = [
    pytest.param(MIN_KID_MISS_COOLDOWN_SECONDS, id="zero-explicit-opt-out-honored"),
    pytest.param(MID_COOLDOWN_SECONDS, id="middle"),
    pytest.param(MAX_KID_MISS_COOLDOWN_SECONDS, id="at-max"),
]


class TestKidMissCooldownConfig:
    @pytest.mark.parametrize("value", COOLDOWN_REJECTED_CASES)
    def test_invalid_cooldown_rejected(self, value):
        with pytest.raises(ConfigError) as exc_info:
            Config(jwks_kid_miss_cooldown=value)
        assert _setting_names(exc_info.value) == ["jwks_kid_miss_cooldown"]

    @pytest.mark.parametrize("value", COOLDOWN_ACCEPTED_CASES)
    def test_in_range_cooldown_reaches_client(self, value):
        with HTTPClient(config=Config(jwks_kid_miss_cooldown=value)) as client:
            assert client.config.jwks_kid_miss_cooldown == value

    def test_default_cooldown(self):
        assert (
            Config().jwks_kid_miss_cooldown == DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS
        )


# ============================================================================
# Bounded cache: size capped, FIFO eviction targets oldest entry.
# ============================================================================


def _make_jwks_response(
    kid: str, cache_control: str | None = "max-age=3600"
) -> JwksResponse:
    """Build a successful JWKS response carrying a single key."""
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
        cache_control=cache_control,
    )


def _op_uri(i: int) -> str:
    return f"https://op-{i}.example/jwks"


class TestBoundedCacheSize:
    def test_max_entries_from_config(self):
        assert (
            Config(cache_max_entries=SMALL_MAX_ENTRIES).cache_max_entries
            == SMALL_MAX_ENTRIES
        )

    def test_max_entries_default(self):
        assert Config().cache_max_entries == DEFAULT_MAX_CACHE_ENTRIES

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(0, id="zero"),
            pytest.param(-1, id="negative"),
            pytest.param("abc", id="garbage-string"),
            pytest.param(1.5, id="non-integer"),
        ],
    )
    def test_invalid_max_entries_rejected(self, value):
        with pytest.raises(ConfigError) as exc_info:
            Config(cache_max_entries=value)
        assert _setting_names(exc_info.value) == ["cache_max_entries"]

    def test_jwks_cache_size_capped_under_overflow(self):
        """Insert max+5 distinct URIs into the cache via the apply helper —
        post-insert the cache holds exactly ``max`` entries."""
        config = Config(cache_max_entries=OVERFLOW_MAX_ENTRIES)
        cache: dict[str, JwksCacheEntry] = {}
        total = OVERFLOW_MAX_ENTRIES + OVERFLOW_EXTRA

        for i in range(total):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=_op_uri(i),
                response=_make_jwks_response(f"kid-{i}"),
                now=time.monotonic(),
                config=config,
            )

        # LRU eviction: the *oldest* inserts are gone, *newest* ones remain.
        assert set(cache.keys()) == {_op_uri(i) for i in range(OVERFLOW_EXTRA, total)}

    def test_overflow_returns_evicted_uris(self):
        """apply_jwks_cache_outcome reports the URIs that left the cache so the
        caller can drop their kid-miss cooldown stamps."""
        config = Config(cache_max_entries=REFRESH_MAX_ENTRIES)
        cache: dict[str, JwksCacheEntry] = {}
        evicted: list[str] = []
        for i in range(REFRESH_MAX_ENTRIES + 1):
            evicted += apply_jwks_cache_outcome(
                cache,
                _op_uri(i),
                _make_jwks_response(f"kid-{i}"),
                time.monotonic(),
                config,
            )
        assert evicted == [_op_uri(0)]

    def test_refresh_of_existing_uri_does_not_count_as_new_entry(self):
        """Re-storing a URI must move it to the end of insertion order so
        a subsequent overflow doesn't immediately evict a just-refreshed
        entry."""
        config = Config(cache_max_entries=REFRESH_MAX_ENTRIES)
        cache: dict[str, JwksCacheEntry] = {}

        # Fill to capacity in known order.
        for i in range(REFRESH_MAX_ENTRIES):
            apply_jwks_cache_outcome(
                cache,
                jwks_uri=_op_uri(i),
                response=_make_jwks_response(f"kid-{i}"),
                now=time.monotonic(),
                config=config,
            )
        assert list(cache.keys()) == [_op_uri(0), _op_uri(1), _op_uri(2)]

        # Refresh op-0 (the oldest). It should move to the newest position.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri=_op_uri(0),
            response=_make_jwks_response("kid-0-rotated"),
            now=time.monotonic(),
            config=config,
        )
        assert list(cache.keys()) == [_op_uri(1), _op_uri(2), _op_uri(0)]

        # Add a fourth distinct URI. Eviction should now target op-1 (the
        # oldest non-refreshed), not the just-refreshed op-0.
        apply_jwks_cache_outcome(
            cache,
            jwks_uri=_op_uri(3),
            response=_make_jwks_response("kid-3"),
            now=time.monotonic(),
            config=config,
        )
        assert set(cache.keys()) == {_op_uri(2), _op_uri(0), _op_uri(3)}

    @respx.mock
    def test_end_to_end_jwks_cache_capped(self, small_cache_client):
        """End-to-end via _get_cached_jwks on an injected client: hammering
        N+5 unique URIs from the real call site enforces the client's
        ``cache_max_entries``. Catches any path that bypasses
        _enforce_size_limit."""
        urls_to_visit = [_op_uri(i) for i in range(E2E_MAX_ENTRIES + OVERFLOW_EXTRA)]
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
            response = _get_cached_jwks(url, http_client=small_cache_client)
            assert response.is_successful is True

        # Newest URIs are the survivors.
        assert set(small_cache_client.caches.jwks.keys()) == set(
            urls_to_visit[-E2E_MAX_ENTRIES:]
        )

    @respx.mock
    def test_caches_are_per_client(self, small_cache_client):
        """A bounded injected client's eviction never touches another
        client's cache — each client owns its caches."""
        key_dict, _ = generate_rsa_keypair()
        url = _op_uri(0)
        respx.get(url).mock(return_value=httpx.Response(200, json={"keys": [key_dict]}))
        with HTTPClient(config=Config()) as other:
            _get_cached_jwks(url, http_client=other)
            assert list(other.caches.jwks.keys()) == [url]
            assert list(small_cache_client.caches.jwks.keys()) == []


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

    def test_lru_evicts_least_recently_used_not_least_recently_inserted(self):
        """After a touch, ``_enforce_size_limit`` evicts the untouched-oldest
        entry, proving eviction is by *use* not by *insertion* (tuple keys,
        mirroring the discovery cache)."""
        cache: OrderedDict[tuple[str, bool], int] = OrderedDict()
        for i in range(E2E_MAX_ENTRIES):
            cache[(f"https://op-{i}.example", True)] = i

        # op-0 is oldest by insertion; a read hit touches it to most-recent.
        touch_cache_entry(cache, ("https://op-0.example", True))
        # A fifth distinct address arrives (attacker-controlled tenant).
        cache[("https://op-4.example", True)] = 4

        evicted = _enforce_size_limit(cache, E2E_MAX_ENTRIES)
        # LRU evicts op-1 (oldest *untouched*), NOT the recently-read op-0.
        assert evicted == [("https://op-1.example", True)]
        assert ("https://op-0.example", True) in cache

    @respx.mock
    def test_read_hit_protects_hot_entry_from_eviction(self, small_cache_client):
        """End-to-end via ``_get_cached_jwks``: an attacker driving distinct
        JWKS-URI reads must NOT evict a JWKS entry that was just read.

        Fill the cache to capacity, re-read the oldest-by-insertion entry (a
        cache hit → LRU touch), then push one more distinct URI. FIFO would
        evict the just-read entry; LRU evicts the oldest *unread* one."""
        cache = small_cache_client.caches.jwks
        urls = [f"https://op-{i}.example/jwks" for i in range(E2E_MAX_ENTRIES + 1)]
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
        for url in urls[:E2E_MAX_ENTRIES]:
            _get_cached_jwks(url, http_client=small_cache_client)
        assert list(cache.keys()) == urls[:E2E_MAX_ENTRIES]

        # Re-read op-0 — a cache hit (no network) that must refresh recency.
        _get_cached_jwks(urls[0], http_client=small_cache_client)
        assert list(cache.keys()) == [
            urls[1],
            urls[2],
            urls[3],
            urls[0],
        ]

        # A fifth distinct URI overflows the cache; eviction targets op-1
        # (oldest unread), NOT the recently-read op-0.
        _get_cached_jwks(urls[4], http_client=small_cache_client)
        assert urls[0] in cache
        assert urls[1] not in cache
        assert set(cache.keys()) == {urls[0], urls[2], urls[3], urls[4]}

    @respx.mock
    def test_read_hit_protects_hot_disco_entry_from_eviction(self, small_cache_client):
        """The discovery cache is LRU too (#397 calls out "same for the
        discovery cache"). End-to-end via ``_get_disco_response``: an attacker
        driving distinct ``disco_doc_address`` reads must NOT evict a discovery
        entry that was just read.

        Mirrors the JWKS end-to-end test but through the disco read path, so a
        regression that adds the read-hit touch to only one of the two caches is
        caught. The cache key is ``(address, policy.cache_key())`` — a tuple,
        exactly the shape a multi-tenant gateway attacker influences."""
        cache = small_cache_client.caches.disco
        bases = [f"https://op-{i}.example" for i in range(E2E_MAX_ENTRIES + 1)]
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
        for address in addresses[:E2E_MAX_ENTRIES]:
            _get_disco_response(address, http_client=small_cache_client)
        assert list(cache.keys()) == keys[:E2E_MAX_ENTRIES]

        # Re-read op-0 — a cache hit (no network) that must refresh recency.
        _get_disco_response(addresses[0], http_client=small_cache_client)
        assert list(cache.keys()) == [
            keys[1],
            keys[2],
            keys[3],
            keys[0],
        ]

        # A fifth distinct address overflows the cache; eviction targets op-1
        # (oldest unread), NOT the recently-read op-0.
        _get_disco_response(addresses[4], http_client=small_cache_client)
        assert keys[0] in cache
        assert keys[1] not in cache
        assert set(cache.keys()) == {keys[0], keys[2], keys[3], keys[4]}
