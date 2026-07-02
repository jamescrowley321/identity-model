package jwks

import (
	"context"
	"sync"
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
}

// cache is a TTL cache for JWK Sets keyed by jwks_uri. Concurrent fetches for
// the same URI are deduplicated via singleflight so only one HTTP request is
// made when the cache is empty or expired.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	group   singleflight.Group

	// lastRefresh records when each jwks_uri was last refreshed, throttling
	// automatic refreshes so an unknown kid cannot drive unbounded re-fetches
	// (see [cache.refreshThrottled]).
	lastRefresh map[string]time.Time

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (JWKS-005).
	now func() time.Time
}

// globalCache backs the package-level [FetchKeySet].
var globalCache = newCache()

// newCache returns an empty cache using the wall clock.
func newCache() *cache {
	return &cache{
		entries:     make(map[string]cacheEntry),
		lastRefresh: make(map[string]time.Time),
		now:         time.Now,
	}
}

// markRefresh records that key was just refreshed, starting its cooldown window.
func (c *cache) markRefresh(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRefresh[key] = c.now()
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

// lookup returns the cached keys for key if present and unexpired.
func (c *cache) lookup(key string) ([]JSONWebKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	return entry.keys, true
}

// store records keys for key with the supplied TTL.
func (c *cache) store(key string, keys []JSONWebKey, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{keys: keys, expiresAt: c.now().Add(ttl)}
}

// invalidate drops any cached entry for key so the next fetch re-requests it.
// It backs ForceRefresh (JWKS-006).
func (c *cache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// fetch returns the cached keys for jwksURI or fetches them, caching the
// result. Concurrent misses for the same URI collapse to one fetch.
//
// Concurrency semantics mirror the discovery client: when several callers miss
// the cache simultaneously, only the first triggers the HTTP request and the
// rest wait on its result. The shared fetch runs on a context detached from any
// single caller (via [context.WithoutCancel]) so one caller cancelling or
// timing out cannot poison the request other callers depend on; each caller
// still observes its own context cancellation through the select below. The
// timeout and cache TTL applied to the shared fetch are those of the caller
// that wins the flight (first-wins).
func (c *cache) fetch(ctx context.Context, jwksURI string, cfg *config) ([]JSONWebKey, error) {
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
		// not abort the fetch the other waiters share. fetchAndParse still
		// bounds the request with the configured (or default) timeout.
		keys, err := fetchAndParse(context.WithoutCancel(ctx), jwksURI, cfg)
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(jwksURI, keys, cfg.cacheTTL)
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
