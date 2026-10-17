"""Per-process cache observability counters.

Lightweight, dependency-free hit/miss/refresh counters for the discovery
and JWKS caches. These make the cache-hit rate and upstream-fetch volume
observable without pulling in a metrics runtime (Prometheus, statsd, …);
a caller that wants those can read :func:`get_cache_counters` snapshots and
export them however it likes.

**Scope:** counters are *per-process*. Each worker (uvicorn ``--workers N``,
gunicorn fork, …) keeps its own :data:`CACHE_COUNTERS`; aggregate across
workers externally when a fleet-wide rate is needed (the load/soak harness
sums per-worker snapshots).

**Cost:** every ``record_*`` is an O(1) integer increment under a dedicated
leaf :class:`threading.Lock`. The lock guards only the counter fields — it
never wraps I/O or a cache-structure critical section, so instrumenting the
cache fast path adds no contention against the cache itself.

**What is counted:** the async validation cache paths in
:mod:`py_identity_model.aio.token_validation`
(``_get_disco_response`` / ``_get_cached_jwks`` / ``_refresh_jwks``), for
every :class:`~py_identity_model.aio.validation_cache.AsyncValidationCache`
and whichever ``http_client`` is passed. The sync validation cache paths are
not counted.
"""

from dataclasses import dataclass, field
import threading


@dataclass
class CacheCounters:
    """Thread-safe hit/miss/refresh tallies for the discovery and JWKS caches.

    A *hit* is a request served from a fresh cached entry (no upstream call).
    A *miss* is a request that fetched the document/keys from upstream. A
    *refresh* is a forced upstream JWKS re-fetch triggered by a kid miss or a
    signature-verification failure (key-rotation recovery).

    A miss/refresh counts every request that actually reached the network —
    **including a failed round trip** (a ``429``/``5xx`` upstream response or a
    connection error). Counting failed fetches is deliberate: fetch volume
    during an upstream outage is exactly the signal this metric exists to
    surface, and dropping it would make an outage read as zero upstream work.
    This matches ``docs/performance.md`` ("a request that had to fetch from
    upstream"). Only a request rejected by the pre-flight URL scheme check (e.g.
    a plaintext ``http://`` address under the default HTTPS-required policy) does
    zero upstream work and is *not* counted — so a forged non-https
    discovery/JWKS URI cannot inflate the tally. Likewise a refresh that
    coalesces onto another coroutine's in-flight fetch does no upstream work and
    is not counted.
    """

    disco_hits: int = 0
    disco_misses: int = 0
    jwks_hits: int = 0
    jwks_misses: int = 0
    jwks_refreshes: int = 0
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def record_disco_hit(self) -> None:
        """Count a discovery request served from a fresh cache entry."""
        with self._lock:
            self.disco_hits += 1

    def record_disco_miss(self) -> None:
        """Count a discovery request that fetched from upstream (incl. failures)."""
        with self._lock:
            self.disco_misses += 1

    def record_jwks_hit(self) -> None:
        """Count a JWKS request served from a fresh cache entry."""
        with self._lock:
            self.jwks_hits += 1

    def record_jwks_miss(self) -> None:
        """Count a JWKS request that fetched from upstream (incl. failures)."""
        with self._lock:
            self.jwks_misses += 1

    def record_jwks_refresh(self) -> None:
        """Count a forced upstream JWKS re-fetch (key-rotation recovery, incl.
        failures)."""
        with self._lock:
            self.jwks_refreshes += 1

    def snapshot(self) -> dict[str, int]:
        """Return a point-in-time copy of every counter.

        The returned dict is a detached copy — mutating it does not affect the
        live counters, and the counters can advance freely afterwards.
        """
        with self._lock:
            return {
                "disco_hits": self.disco_hits,
                "disco_misses": self.disco_misses,
                "jwks_hits": self.jwks_hits,
                "jwks_misses": self.jwks_misses,
                "jwks_refreshes": self.jwks_refreshes,
            }

    def reset(self) -> None:
        """Zero every counter. Primarily for tests and per-run baselines."""
        with self._lock:
            self.disco_hits = 0
            self.disco_misses = 0
            self.jwks_hits = 0
            self.jwks_misses = 0
            self.jwks_refreshes = 0


# Process-wide singleton. The async cache paths increment this directly; a
# caller reads it via ``get_cache_counters().snapshot()``.
CACHE_COUNTERS = CacheCounters()


def get_cache_counters() -> CacheCounters:
    """Return the process-wide :data:`CACHE_COUNTERS` singleton."""
    return CACHE_COUNTERS


__all__ = [
    "CACHE_COUNTERS",
    "CacheCounters",
    "get_cache_counters",
]
