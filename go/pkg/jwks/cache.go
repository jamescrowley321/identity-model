package jwks

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// cacheEntry is a cached key set with its expiry instant. The keys slice (not a
// *JSONWebKeySet handle) is cached so that a handle's ForceRefresh can swap in a
// fresh slice without the cache holding a self-referential pointer back to the
// handle.
type cacheEntry struct {
	keys      []JSONWebKey
	expiresAt time.Time

	// lastAccess is a monotonic recency tick: the higher the value, the more
	// recently the entry was used. It is bumped on every read hit and on store.
	// Because it is interior-mutable (an atomic), a read hit can refresh recency
	// while holding only the shared read lock, preserving the concurrent-reader
	// property (JWKS-005) instead of upgrading every cache hit to an exclusive
	// lock. Eviction drops the entry with the smallest tick. Mirrors the Rust
	// port's AtomicU64 last_access.
	lastAccess atomic.Int64
}

// cache is a bounded, TTL cache for JWK Sets keyed by jwks_uri. Concurrent
// fetches for the same URI are deduplicated via singleflight so only one HTTP
// request is made when the cache is empty or expired.
//
// The cache is bounded by a max-entries LRU: without a bound it grows one entry
// per distinct jwks_uri forever, so a caller driven to resolve tokens against
// many distinct issuers (a multi-tenant gateway, an attacker-supplied issuer
// header) leaks memory unbounded (a DoS). Recency is tracked per entry via an
// atomic tick — a read hit or a store bumps it and eviction drops the smallest —
// so the entry evicted under pressure is the least recently *used*, not merely
// the least recently inserted. FIFO would let an attacker reading distinct URIs
// in insertion order evict a legitimately hot entry.
//
// A read hit ([cache.lookup]) takes only the shared read lock and bumps recency
// atomically, so lookups on the hot token-validation path stay concurrent; only
// store and eviction take the exclusive lock. Eviction scans the map for the
// smallest tick (O(n), n <= maxEntries), a rare cost paid only on insert over
// the bound.
type cache struct {
	mu sync.RWMutex

	// entries maps jwks_uri -> its cached key set. Structural mutation
	// (insert/evict) takes the write lock; a read hit takes the read lock and
	// bumps the entry's atomic recency tick.
	entries map[string]*cacheEntry

	// accessCounter hands out the monotonic recency ticks stored per entry.
	accessCounter atomic.Int64

	group singleflight.Group

	// lastRefresh records when each jwks_uri was last refreshed, throttling
	// automatic refreshes so an unknown kid cannot drive unbounded re-fetches
	// (see [cache.refreshThrottled]). It is a sidecar keyed by the same jwks_uri
	// as entries. It is kept bounded two ways: an LRU eviction prunes the evicted
	// URI's record in lockstep (see [cache.evictLocked]), and [cache.markRefresh]
	// independently caps it at maxEntries — a failed ForceRefresh otherwise leaves
	// a record with no backing entry that eviction can never reclaim.
	lastRefresh map[string]time.Time

	// maxEntries bounds len(entries) and len(lastRefresh).
	maxEntries int

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (JWKS-005).
	now func() time.Time
}

// newCache returns an empty cache holding at most maxEntries key sets, using
// the wall clock.
func newCache(maxEntries int) *cache {
	return &cache{
		entries:     make(map[string]*cacheEntry),
		lastRefresh: make(map[string]time.Time),
		maxEntries:  maxEntries,
		now:         time.Now,
	}
}

// nextTick returns the next monotonic recency tick.
func (c *cache) nextTick() int64 {
	return c.accessCounter.Add(1)
}

// markRefresh records that key was just refreshed, starting its cooldown window,
// then caps the cooldown sidecar so it stays bounded.
//
// The cap is independent of entry eviction: ForceRefresh calls invalidate (which
// deliberately keeps the record so the cooldown still throttles repeated
// automatic refreshes) and only re-marks on success. If the re-fetch fails, the
// record has no backing entry, and evictLocked — which only prunes records for
// keys still in entries — can never reclaim it. Capping here (evicting the
// least-recently-refreshed record) keeps lastRefresh bounded under issuer/URI
// rotation regardless.
func (c *cache) markRefresh(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRefresh[key] = c.now()
	for len(c.lastRefresh) > c.maxEntries {
		var oldestKey string
		var oldest time.Time
		found := false
		for k, t := range c.lastRefresh {
			if !found || t.Before(oldest) {
				oldestKey, oldest, found = k, t, true
			}
		}
		if !found {
			break
		}
		delete(c.lastRefresh, oldestKey)
	}
}

// refreshThrottled reports whether key was refreshed less than cooldown ago, so
// another automatic refresh should be suppressed. A non-positive cooldown
// disables throttling.
func (c *cache) refreshThrottled(key string, cooldown time.Duration) bool {
	if cooldown <= 0 {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	last, ok := c.lastRefresh[key]
	if !ok {
		return false
	}
	return c.now().Sub(last) < cooldown
}

// lookup returns the cached keys for key if present and unexpired, bumping the
// entry's recency on a hit. Recency is an atomic tick on the entry, so this holds
// only the shared read lock — keeping concurrent lookups on the hot path from
// serializing. An expired entry is neither promoted nor removed here: it is
// overwritten by the next store or evicted under pressure.
func (c *cache) lookup(key string) ([]JSONWebKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	entry.lastAccess.Store(c.nextTick())
	return entry.keys, true
}

// store records keys for key with the supplied TTL, marks the entry
// most-recently-used, and enforces the max-entries bound.
func (c *cache) store(key string, keys []JSONWebKey, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := &cacheEntry{keys: keys, expiresAt: c.now().Add(ttl)}
	entry.lastAccess.Store(c.nextTick())
	c.entries[key] = entry
	c.evictLocked()
}

// evictLocked drops least-recently-used entries until at most maxEntries remain.
// It must be called with mu held. The victim is the entry with the smallest
// recency tick, found by an O(n) scan (n <= maxEntries) — the trade for keeping
// lookup on a shared read lock. Each evicted jwks_uri's sidecar refresh-cooldown
// record is deleted in lockstep so lastRefresh cannot grow unbounded even though
// entries is bounded.
func (c *cache) evictLocked() {
	for len(c.entries) > c.maxEntries {
		var lruKey string
		var lruTick int64
		found := false
		for k, e := range c.entries {
			t := e.lastAccess.Load()
			if !found || t < lruTick {
				lruKey, lruTick, found = k, t, true
			}
		}
		if !found {
			return
		}
		delete(c.entries, lruKey)
		delete(c.lastRefresh, lruKey)
	}
}

// invalidate drops any cached entry for key so the next fetch re-requests it.
// It backs ForceRefresh (JWKS-006). The refresh-cooldown record is left intact:
// ForceRefresh re-establishes it via markRefresh after the re-fetch succeeds.
func (c *cache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// loader fetches one key set and returns it with the lifetime to cache it for.
type loader func(ctx context.Context) ([]JSONWebKey, time.Duration, error)

// fetch returns the cached keys for jwksURI or loads them, caching the result
// for the lifetime load returns. Concurrent misses for the same URI collapse to
// one load.
//
// Concurrency semantics mirror the discovery client: when several callers miss
// the cache simultaneously, only the first triggers the HTTP request and the
// rest wait on its result. The shared load runs on a context detached from any
// single caller (via [context.WithoutCancel]) so one caller cancelling or
// timing out cannot poison the request other callers depend on; each caller
// still observes its own context cancellation through the select below.
func (c *cache) fetch(ctx context.Context, jwksURI string, load loader) ([]JSONWebKey, error) {
	// JWKS-005: serve a fresh cache entry without any HTTP request. Return a
	// deep copy so the caller's handle cannot mutate the cached master copy.
	if keys, ok := c.lookup(jwksURI); ok {
		return cloneKeys(keys), nil
	}

	// Singleflight collapses concurrent misses into one in-flight request.
	// DoChan (not Do) lets each caller honour its own context independently.
	ch := c.group.DoChan(jwksURI, func() (interface{}, error) {
		// Re-check under the flight in case another goroutine just populated
		// the cache.
		if keys, ok := c.lookup(jwksURI); ok {
			return keys, nil
		}
		// Detach from the winning caller's context so its cancellation does
		// not abort the load the other waiters share.
		keys, ttl, err := load(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(jwksURI, keys, ttl)
		return keys, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		// Each waiter receives the same shared result value; hand back a deep
		// copy so concurrent callers never alias one another's (or the cache's)
		// key set.
		return cloneKeys(res.Val.([]JSONWebKey)), nil
	}
}
