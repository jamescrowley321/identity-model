"""
JWKS and discovery cache TTL configuration and cache entry logic.

This module provides TTL-based caching for JWKS and discovery responses,
supporting automatic cache expiry and forced refresh on key rotation (RFC 7517 §5).

JWKS TTL resolution order:
1. ``Cache-Control: max-age=N`` from the provider's JWKS HTTP response
2. ``Config.jwks_cache_ttl`` (default: 86400, 24 hours)

Discovery TTL resolution order:
1. ``Cache-Control: max-age=N`` from the provider's discovery HTTP response
2. ``Config.discovery_cache_ttl`` (default: 3600, 1 hour)

Cache size and the kid-miss cooldown also come from the client's
:class:`~py_identity_model.core.config.Config`. Nothing here reads the
environment.

The provider's cache header is preferred because providers set ``max-age``
based on their key rotation schedule (e.g., Google uses ``max-age=19800``).
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import threading
import time
from typing import TYPE_CHECKING

from ..logging_config import logger


if TYPE_CHECKING:
    from collections import OrderedDict

    from ..core.config import Config
    from ..core.models import DiscoveryDocumentResponse, JwksResponse

DEFAULT_JWKS_CACHE_TTL_SECONDS: float = 86400.0  # 24 hours
DEFAULT_DISCO_CACHE_TTL_SECONDS: float = 3600.0  # 1 hour
MIN_CACHE_TTL_SECONDS: float = 60.0
MAX_CACHE_TTL_SECONDS: float = 86400.0

# Cooldown bounds. 0 is permitted as an explicit opt-out for environments that
# accept the DoS amplification risk in exchange for instant rotation. 3600s
# (1h) is a soft ceiling — beyond that, rotation latency exceeds the documented
# expectation that a real key rotation propagates "within one cooldown window."
MIN_KID_MISS_COOLDOWN_SECONDS: float = 0.0
MAX_KID_MISS_COOLDOWN_SECONDS: float = 3600.0

# Minimum gap between forced JWKS refreshes for the *same* jwks_uri when the
# incoming JWT's kid is not in the cached set. Bounds the DoS amplification
# factor an unauthenticated attacker can drive by spamming JWTs with random
# kids: under sustained load at most ⌈window / cooldown⌉ requests reach the
# upstream JWKS endpoint per window. The cached keys remain usable inside the
# window — the cooldown only short-circuits the refresh attempt, not the
# lookup, so legitimate already-cached kids continue to validate normally.
# Mirrors Microsoft IdentityModel's RefreshInterval (default 5 minutes) and
# Auth0's node-jwks-rsa rateLimit (default 10 req/min); 5s is the conservative
# floor between those two — small enough that a real rotation propagates
# within one cooldown window per process.
DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS: float = 5.0

# Caps the number of distinct (jwks_uri) or (disco_address, require_https)
# entries each of a client's caches holds (``Config.cache_max_entries``).
# Bounds an unbounded-growth attack where attacker-controlled discovery
# addresses (multi-tenant gateways, attacker-supplied issuer headers) accumulate cache entries forever — at
# ~5KB per DiscoveryDocumentResponse, a few thousand unique entries is tens
# of MB of memory leak. Default 64 covers any realistic multi-IdP deployment
# while keeping worst-case memory bounded. Eviction is LRU by access order:
# the cache is an ``OrderedDict`` whose entries are moved to the end on every
# read hit (see ``touch_cache_entry``) and on every write, so the least
# *recently used* entry sorts first and is evicted first. FIFO would let an
# attacker who controls the discovery address (multi-tenant gateway,
# attacker-supplied issuer header) evict a legitimately-hot JWKS entry merely
# by reading distinct addresses in insertion order (issue #397).
DEFAULT_MAX_CACHE_ENTRIES: int = 64

_MAX_AGE_RE = re.compile(r"max-age=(\d+)", re.IGNORECASE)
_NO_STORE_RE = re.compile(r"\bno-store\b", re.IGNORECASE)
_NO_CACHE_RE = re.compile(r"\bno-cache\b", re.IGNORECASE)


# Serializes ALL structural mutation of every client's JWKS and discovery
# ``OrderedDict``s — the read-hit reorder (:func:`touch_cache_entry`), the write
# reinsert/pop (:func:`apply_jwks_cache_outcome` / :func:`apply_disco_cache_outcome`),
# and the eviction scan (:func:`_enforce_size_limit`) — against each other.
#
# A single *process-wide* lock is used deliberately rather than the callers'
# per-domain locks: the sync path guards writes with a per-client
# ``threading.Lock`` while the async path uses a lock keyed per event loop, and
# one client's cache objects are shared by every thread and loop using it. A per-loop async lock
# cannot serialize a mutation on loop A against the eviction scan on loop B (nor
# against a sync thread), so without this lock a read-hit ``move_to_end`` or a
# write reinsert on one loop could race ``next(iter(cache))``/``pop`` on another
# — evicting the wrong (possibly hot) entry or raising ``RuntimeError:
# OrderedDict mutated during iteration``, and a concurrent write ``pop`` could
# turn a read-hit ``move_to_end`` into a ``KeyError``. Holding this lock around
# every structural mutation closes those cross-loop/cross-thread races (#397).
#
# It is reentrant so a write can hold it across its reinsert *and* the nested
# :func:`_enforce_size_limit` call. It is always acquired last (inside any
# caller-held write lock), never wraps I/O, and guards only O(1)/O(overflow)
# dict operations, so it adds no deadlock risk and negligible contention.
_CACHE_STRUCTURE_LOCK = threading.RLock()


def touch_cache_entry(cache: OrderedDict, key: object) -> None:
    """Refresh an entry's LRU recency by moving it to the end (most-recent).

    Called on read cache hits so a fresh lookup counts as "recently used" and
    is therefore evicted last. ``next(iter(cache))`` in :func:`_enforce_size_limit`
    then always points at the *least recently used* entry rather than the
    least recently *inserted* one — the FIFO→LRU switch that closes #397.

    No-op when ``key`` is absent: the entry may have been evicted between the
    lock-free ``.get()`` on the read hot-path and this call, so ``move_to_end``
    would otherwise raise ``KeyError``.

    Self-serializing: the reorder runs under the process-wide
    ``_CACHE_STRUCTURE_LOCK`` so it cannot race :func:`_enforce_size_limit`'s
    eviction iteration on any thread or event loop. Callers therefore need not
    (and should not) hold a write lock solely to call this — that would only add
    contention to the read hot-path.
    """
    with _CACHE_STRUCTURE_LOCK:
        if key in cache:
            cache.move_to_end(key)


def clear_cache_locked(cache: dict) -> None:
    """Empty a shared cache under ``_CACHE_STRUCTURE_LOCK``.

    ``clear_jwks_cache`` / ``clear_discovery_cache`` hold their per-domain write
    lock, but that lock is per-event-loop on the async side while the client's
    cache is shared by every loop and thread — so it does not serialize the structural ``clear()`` against
    a read-hit :func:`touch_cache_entry` or the eviction scan in
    :func:`_enforce_size_limit` running on another loop/thread. Routing the
    ``clear()`` through this leaf lock keeps the "every structural mutation
    holds the structure lock" invariant intact (#397): a concurrent ``clear()``
    can no longer race ``next(iter(cache))`` (``RuntimeError``) or ``move_to_end``
    (``KeyError``). Sidecar dicts (e.g. the kid-miss cooldown map) are cleared
    separately by the caller — they are never touched under the structure lock.
    """
    with _CACHE_STRUCTURE_LOCK:
        cache.clear()


def _enforce_size_limit(cache: dict, max_size: int) -> list:
    """Evict least-recently-used entries until the cache fits.

    With an ``OrderedDict`` reordered on every read hit (see
    :func:`touch_cache_entry`) and every write, ``next(iter(cache))`` is the
    least recently *used* entry, so this evicts LRU rather than FIFO.

    The eviction scan holds ``_CACHE_STRUCTURE_LOCK`` so it is mutually
    exclusive with concurrent read-hit reorders across all threads and event
    loops — otherwise a ``move_to_end`` on another loop could shift the order
    mid-scan and evict a recently-used entry (#397).

    Returns the list of evicted keys (in eviction order, LRU first) so
    callers can clean up sidecar state keyed by the same identifiers — e.g.,
    the client's kid-miss cooldown map, which would
    otherwise grow unbounded even though the JWKS cache itself is bounded.
    """
    evicted: list = []
    with _CACHE_STRUCTURE_LOCK:
        while len(cache) > max_size:
            oldest_key = next(iter(cache))
            cache.pop(oldest_key)
            evicted.append(oldest_key)
            logger.debug(
                "Cache size %d exceeds max %d; evicted least-recently-used entry",
                len(cache) + 1,
                max_size,
            )
    return evicted


def should_attempt_kid_miss_refresh(
    last_attempts: dict[str, float],
    jwks_uri: str,
    has_cached_keys: bool,
    now: float,
    cooldown: float,
) -> bool:
    """Gate the kid-miss forced refresh to bound DoS amplification.

    Returns True (proceed with refresh) when:
    - We have no cached keys to fall back on (the cache cannot be a cause of
      the kid miss — refusing here would brick token validation), OR
    - The cooldown has elapsed since the last attempted refresh for this URI.

    Returns False (skip refresh, let find_key_by_kid fail naturally) when a
    recent kid-miss refresh for this URI did not produce the requested kid
    and the cached keys are non-empty. The caller will hit the no-matching-kid
    error path with cached keys still usable for already-known kids.

    The state is keyed by ``jwks_uri`` so an attacker spamming kids against
    one OP cannot suppress legitimate refreshes for a different OP.
    ``cooldown`` is the client's ``Config.jwks_kid_miss_cooldown``; 0
    disables it.
    """
    if not has_cached_keys:
        return True
    last = last_attempts.get(jwks_uri)
    if last is None:
        return True
    return (now - last) >= cooldown


def is_uncacheable(cache_control: str | None) -> bool:
    """Return True when Cache-Control forbids caching the response.

    Honors RFC 7234 §5.2.2.5 (``no-store``) and §5.2.2.4 (``no-cache``).
    ``no-cache`` requires revalidation before use; the simplest correct
    behavior is to skip caching so the next call re-fetches.

    Used for response types whose contents are per-user or sensitive
    (token responses, discovery documents). For JWKS, see
    :func:`is_uncacheable_for_jwks` — JWKS responses contain public
    signing keys, and strict ``no-cache``/``no-store`` honoring causes
    a self-DoS against the upstream issuer at any meaningful traffic
    level (see issue #396).
    """
    if not cache_control:
        return False
    return bool(
        _NO_STORE_RE.search(cache_control) or _NO_CACHE_RE.search(cache_control)
    )


def is_uncacheable_for_jwks(cache_control: str | None) -> bool:  # noqa: ARG001
    """Return True only when JWKS caching is genuinely forbidden.

    JWKS responses contain *public* signing keys that the issuer
    publishes for every relying party to fetch and reuse. The standard
    Cache-Control directives are interpreted accordingly:

    - ``no-cache`` (RFC 7234 §5.2.2.4): means "revalidate before use,"
      not "do not cache." A strict implementation would issue ETag /
      If-None-Match conditional GETs. As a practical compromise, we
      cache for the resolved TTL (``max-age`` if present, else the
      configured floor). This is the dominant industry behavior — see
      e.g. Auth0, Keycloak, and ``jose`` adapters.

    - ``no-store`` (RFC 7234 §5.2.2.5): means "MUST NOT store." On
      sensitive responses (tokens, user data) this matters. On JWKS —
      public material the issuer publicly advertises — the directive
      provides no confidentiality benefit and creates an operational
      hazard: at 100 token validations / second, strictly honoring
      ``no-store`` produces 100 JWKS fetches / second against the
      issuer, which self-DoSes the upstream and the relying party in
      short order. We deliberately ignore ``no-store`` on JWKS.

    Always returns False today. The function exists as the call site so
    the policy is documented and overridable in one place if a future
    ``max-age=0`` honoring path is added.

    Refs:
        - Issue #396 (security: jwks-cache C-4 — ``no-cache`` providers
          fetch JWKS on every request).
        - Common deployments that send ``no-cache, no-store`` on JWKS
          include Ory Network's free tier and some Descope-style
          configurations.
    """
    return False


def parse_max_age(cache_control: str | None) -> float | None:
    """Extract max-age from a Cache-Control header value.

    Returns:
        The max-age in seconds, or None if not present/parseable.
    """
    if not cache_control:
        return None
    match = _MAX_AGE_RE.search(cache_control)
    if match:
        return float(match.group(1))
    return None


def resolve_ttl(cache_control: str | None, default_ttl: float) -> float:
    """Determine the JWKS cache TTL from HTTP headers or config.

    Priority: Cache-Control max-age (clamped to [60s, 86400s]) >
    ``default_ttl`` (the client's ``Config.jwks_cache_ttl``).
    """
    max_age = parse_max_age(cache_control)
    if max_age is not None:
        ttl = max(MIN_CACHE_TTL_SECONDS, min(max_age, MAX_CACHE_TTL_SECONDS))
        logger.debug(
            "Using provider Cache-Control max-age=%s (clamped to %.0fs)", max_age, ttl
        )
        return ttl
    return default_ttl


def resolve_disco_ttl(cache_control: str | None, default_ttl: float) -> float:
    """Determine the discovery cache TTL from HTTP headers or config.

    Priority: Cache-Control max-age (clamped to [60s, 86400s]) >
    ``default_ttl`` (the client's ``Config.discovery_cache_ttl``).
    """
    max_age = parse_max_age(cache_control)
    if max_age is not None:
        ttl = max(MIN_CACHE_TTL_SECONDS, min(max_age, MAX_CACHE_TTL_SECONDS))
        logger.debug(
            "Using provider Cache-Control max-age=%s for discovery (clamped to %.0fs)",
            max_age,
            ttl,
        )
        return ttl
    return default_ttl


@dataclass
class JwksCacheEntry:
    """A cached JWKS response with timestamp and TTL."""

    response: JwksResponse
    cached_at: float
    ttl: float = DEFAULT_JWKS_CACHE_TTL_SECONDS


@dataclass
class DiscoCacheEntry:
    """A cached discovery document response with timestamp and TTL."""

    response: DiscoveryDocumentResponse
    cached_at: float
    ttl: float = DEFAULT_DISCO_CACHE_TTL_SECONDS


def is_cache_expired(entry: JwksCacheEntry | DiscoCacheEntry) -> bool:
    """Check if a cache entry has expired using its own TTL.

    Uses ``time.monotonic`` so cache freshness is robust against wall-clock
    back-steps (NTP slew, container clock-skew correction). ``cached_at`` is
    therefore a monotonic timestamp produced by the same clock — never an
    interpretable wall-clock value.

    Args:
        entry: The cache entry to check.

    Returns:
        True if the entry is expired.
    """
    age = time.monotonic() - entry.cached_at
    expired = age >= entry.ttl
    if expired:
        logger.debug("Cache entry expired (age=%.1fs, ttl=%.1fs)", age, entry.ttl)
    return expired


def apply_jwks_cache_outcome(
    cache: dict[str, JwksCacheEntry],
    jwks_uri: str,
    response: JwksResponse,
    now: float,
    config: Config,
) -> list[str]:
    """Apply the cache-write/invalidate/retain decision for a JWKS response.

    Decision matrix (order matters):
    - Unsuccessful (network error, 4xx, parse failure): retain any existing
      entry. The last known-good keys remain available while transient errors
      pass. Mirrors the "retain cache on error" pattern from jose4j.
    - Empty ``keys``: retain the existing entry. An empty JWKS is treated as
      a transient upstream blip, never a valid replacement for working keys.
      Checked *before* the uncacheable branch so a malformed ``200 {"keys":
      []}`` paired with ``Cache-Control: no-cache`` does not delete a working
      entry on a transient empty-body blip.
    - ``Cache-Control: no-store`` or ``no-cache`` (via
      :func:`is_uncacheable_for_jwks`): JWKS is public material, so
      caching with the resolved TTL is operationally safe and
      necessary at scale. Today this branch is never taken because
      ``is_uncacheable_for_jwks`` always returns False; it is retained
      as the documented policy hook for future strict-mode opt-ins.
    - Successful, cacheable, non-empty: store with the resolved TTL.

    ``config`` supplies the default TTL (``jwks_cache_ttl``) and the size
    bound (``cache_max_entries``).

    Returns the URIs whose entry left the cache (evicted or invalidated). The
    caller drops its per-URI sidecar state for them — the kid-miss cooldown
    timestamps — which would otherwise grow unboundedly even when the cache
    itself is bounded.
    """
    if not response.is_successful:
        return []
    if not response.keys:
        return []
    if is_uncacheable_for_jwks(response.cache_control):
        with _CACHE_STRUCTURE_LOCK:
            cache.pop(jwks_uri, None)
        return [jwks_uri]
    # Pop-and-reinsert so a refreshed URI moves to the most-recently-used end
    # (LRU eviction will not target it next when the cache is under pressure).
    # The whole structural transaction (reinsert + eviction scan) runs under
    # _CACHE_STRUCTURE_LOCK so it is atomic w.r.t. read-hit reorders and the
    # eviction scan on any other thread/event loop (#397).
    with _CACHE_STRUCTURE_LOCK:
        cache.pop(jwks_uri, None)
        cache[jwks_uri] = JwksCacheEntry(
            response=response,
            cached_at=now,
            ttl=resolve_ttl(response.cache_control, config.jwks_cache_ttl),
        )
        return _enforce_size_limit(cache, config.cache_max_entries)


def apply_disco_cache_outcome(
    cache: dict[tuple[str, tuple], DiscoCacheEntry],
    cache_key: tuple[str, tuple],
    response: DiscoveryDocumentResponse,
    now: float,
    config: Config,
) -> None:
    """Apply the cache-write/invalidate/retain decision for a discovery response.

    Mirrors :func:`apply_jwks_cache_outcome` but without the empty-payload
    check, since discovery responses do not have a single "payload" field
    whose emptiness signals a broken response.
    """
    if not response.is_successful:
        return
    if is_uncacheable(response.cache_control):
        with _CACHE_STRUCTURE_LOCK:
            cache.pop(cache_key, None)
        return
    # Structural transaction under _CACHE_STRUCTURE_LOCK — see
    # apply_jwks_cache_outcome for the cross-loop/cross-thread rationale (#397).
    with _CACHE_STRUCTURE_LOCK:
        cache.pop(cache_key, None)
        cache[cache_key] = DiscoCacheEntry(
            response=response,
            cached_at=now,
            ttl=resolve_disco_ttl(response.cache_control, config.discovery_cache_ttl),
        )
        _enforce_size_limit(cache, config.cache_max_entries)


__all__ = [
    "DEFAULT_DISCO_CACHE_TTL_SECONDS",
    "DEFAULT_JWKS_CACHE_TTL_SECONDS",
    "DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS",
    "DEFAULT_MAX_CACHE_ENTRIES",
    "MAX_CACHE_TTL_SECONDS",
    "MAX_KID_MISS_COOLDOWN_SECONDS",
    "MIN_CACHE_TTL_SECONDS",
    "MIN_KID_MISS_COOLDOWN_SECONDS",
    "DiscoCacheEntry",
    "JwksCacheEntry",
    "apply_disco_cache_outcome",
    "apply_jwks_cache_outcome",
    "clear_cache_locked",
    "is_cache_expired",
    "is_uncacheable",
    "is_uncacheable_for_jwks",
    "parse_max_age",
    "resolve_disco_ttl",
    "resolve_ttl",
    "should_attempt_kid_miss_refresh",
    "touch_cache_entry",
]
