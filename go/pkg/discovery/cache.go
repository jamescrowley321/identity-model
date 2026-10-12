package discovery

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

// cacheEntry is a cached configuration with its expiry instant.
type cacheEntry struct {
	cfg       *ProviderConfiguration
	expiresAt time.Time

	// lastAccess is a monotonic recency tick: the higher the value, the more
	// recently the entry was used. It is bumped on every read hit and on store.
	// Because it is interior-mutable (an atomic), a read hit can refresh recency
	// while holding only the shared read lock, preserving the concurrent-reader
	// property (DISC-004/005) instead of upgrading every cache hit to an
	// exclusive lock. Eviction drops the entry with the smallest tick. Mirrors
	// the Rust port's AtomicU64 last_access.
	lastAccess atomic.Int64
}

// cache is a bounded, TTL cache for discovery documents keyed by issuer URL.
// Concurrent fetches for the same issuer are deduplicated via singleflight so
// only one HTTP request is made when the cache is empty or expired.
//
// The cache is bounded by a max-entries LRU: without a bound it grows one entry
// per distinct issuer forever, so a caller driven to resolve many distinct
// issuers (a multi-tenant gateway, an attacker-supplied issuer header) leaks
// memory unbounded (a DoS). Recency is tracked per entry via an atomic tick — a
// read hit or a store bumps it and eviction drops the smallest — so the entry
// evicted under pressure is the least recently *used*, not merely the least
// recently inserted. FIFO would let an attacker reading distinct issuers in
// insertion order evict a legitimately hot entry.
//
// A read hit ([cache.lookup]) takes only the shared read lock and bumps recency
// atomically, so lookups on the hot path stay concurrent; only store and
// eviction take the exclusive lock. Eviction scans the map for the smallest tick
// (O(n), n <= maxEntries), a rare cost paid only on insert over the bound.
type cache struct {
	mu sync.RWMutex

	// entries maps issuer URL -> its cached configuration. Structural mutation
	// (insert/evict) takes the write lock; a read hit takes the read lock and
	// bumps the entry's atomic recency tick.
	entries map[string]*cacheEntry

	// accessCounter hands out the monotonic recency ticks stored per entry.
	accessCounter atomic.Int64

	group singleflight.Group

	// defaultTTL is the lifetime of a document whose response has no
	// Cache-Control max-age; maxEntries bounds len(entries).
	defaultTTL time.Duration
	maxEntries int

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (DISC-005).
	now func() time.Time
}

// newCache returns an empty cache holding at most maxEntries documents, each
// for defaultTTL unless its response says otherwise, using the wall clock.
func newCache(defaultTTL time.Duration, maxEntries int) *cache {
	return &cache{
		entries:    make(map[string]*cacheEntry),
		defaultTTL: defaultTTL,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// nextTick returns the next monotonic recency tick.
func (c *cache) nextTick() int64 {
	return c.accessCounter.Add(1)
}

// lookup returns the cached configuration for key if present and unexpired,
// bumping the entry's recency on a hit. Recency is an atomic tick on the entry,
// so this holds only the shared read lock — keeping concurrent lookups on the
// hot path from serializing. An expired entry is neither promoted nor removed
// here: it is overwritten by the next store or evicted under pressure.
func (c *cache) lookup(key string) (*ProviderConfiguration, bool) {
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
	return entry.cfg, true
}

// store records cfg for key with the supplied TTL, marks the entry
// most-recently-used, and enforces the max-entries bound.
func (c *cache) store(key string, cfg *ProviderConfiguration, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := &cacheEntry{cfg: cfg, expiresAt: c.now().Add(ttl)}
	entry.lastAccess.Store(c.nextTick())
	c.entries[key] = entry
	c.evictLocked()
}

// evictLocked drops least-recently-used entries until at most maxEntries remain.
// It must be called with mu held. The victim is the entry with the smallest
// recency tick, found by an O(n) scan (n <= maxEntries) — the trade for keeping
// lookup on a shared read lock.
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
	}
}

// loader fetches one document and returns it with its response's
// Cache-Control header.
type loader func(ctx context.Context) (*ProviderConfiguration, string, error)

// fetch returns the cached configuration for issuerURL or loads it, caching
// the result per the Cache-Control rules (spec/config.md): max-age clamped to
// 60 s – 24 h, else defaultTTL; no-store or no-cache is not cached. Concurrent
// misses for the same issuer collapse to one load.
//
// Concurrency semantics: when several callers miss the cache simultaneously,
// only the first triggers the HTTP request and the rest wait on its result.
// The shared load runs on a context detached from any single caller (via
// [context.WithoutCancel]), so one caller cancelling or timing out cannot
// poison the request other callers depend on; each caller still observes its
// own context cancellation through the select below. Because the shared load
// is detached, a deadline carried only on a caller's context does not bound the
// underlying request (the caller still unblocks at its deadline, but the load
// runs to the client's [WithTimeout] per attempt).
func (c *cache) fetch(ctx context.Context, issuerURL string, load loader) (*ProviderConfiguration, error) {
	// DISC-004: serve a fresh cache entry without any HTTP request.
	if doc, ok := c.lookup(issuerURL); ok {
		return doc, nil
	}

	// Singleflight collapses concurrent misses into one in-flight request.
	// DoChan (not Do) lets each caller honour its own context independently.
	ch := c.group.DoChan(issuerURL, func() (interface{}, error) {
		// Re-check under the flight in case another goroutine just populated
		// the cache (DISC-005 boundary).
		if doc, ok := c.lookup(issuerURL); ok {
			return doc, nil
		}
		// Detach from the winning caller's context so its cancellation does
		// not abort the load the other waiters share.
		doc, cacheControl, err := load(context.WithoutCancel(ctx))
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached, and only when the provider
		// allows it.
		if !transport.Uncacheable(cacheControl) {
			c.store(issuerURL, doc, transport.ResolveTTL(cacheControl, c.defaultTTL))
		}
		return doc, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*ProviderConfiguration), nil
	}
}
