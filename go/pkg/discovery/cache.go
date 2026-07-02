package discovery

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// cacheEntry is a cached configuration with its expiry instant.
type cacheEntry struct {
	cfg       *ProviderConfiguration
	expiresAt time.Time
}

// cache is a TTL cache for discovery documents keyed by issuer URL. Concurrent
// fetches for the same issuer are deduplicated via singleflight so only one
// HTTP request is made when the cache is empty or expired.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	group   singleflight.Group

	// now returns the current time; overridable in tests to drive TTL expiry
	// deterministically (DISC-005).
	now func() time.Time
}

// globalCache backs the package-level [FetchConfiguration].
var globalCache = newCache()

// newCache returns an empty cache using the wall clock.
func newCache() *cache {
	return &cache{
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// lookup returns the cached configuration for key if present and unexpired.
func (c *cache) lookup(key string) (*ProviderConfiguration, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	return entry.cfg, true
}

// store records cfg for key with the supplied TTL.
func (c *cache) store(key string, cfg *ProviderConfiguration, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{cfg: cfg, expiresAt: c.now().Add(ttl)}
}

// fetch returns the cached configuration for issuerURL or fetches it, caching
// the result. Concurrent misses for the same issuer collapse to one fetch.
//
// Concurrency semantics: when several callers miss the cache simultaneously,
// only the first triggers the HTTP request and the rest wait on its result.
// The shared fetch runs on a context detached from any single caller (via
// [context.WithoutCancel]), so one caller cancelling or timing out cannot
// poison the request other callers depend on; each caller still observes its
// own context cancellation through the select below. Because the shared fetch
// is detached, a deadline carried only on a caller's context does not bound the
// underlying request (the caller still unblocks at its deadline, but the fetch
// runs to the configured [WithTimeout] or the default request timeout). The
// timeout and cache TTL applied to the shared fetch are those of the caller
// that wins the flight (first-wins) — callers needing distinct timeouts should
// not rely on the shared cache for that guarantee.
func (c *cache) fetch(ctx context.Context, issuerURL string, cfg *config) (*ProviderConfiguration, error) {
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
		// not abort the fetch the other waiters share. fetchAndValidate still
		// bounds the request with the configured (or default) timeout.
		doc, err := fetchAndValidate(context.WithoutCancel(ctx), issuerURL, cfg)
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(issuerURL, doc, cfg.cacheTTL)
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
