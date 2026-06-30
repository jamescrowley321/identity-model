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
func (c *cache) fetch(ctx context.Context, issuerURL string, cfg *config) (*ProviderConfiguration, error) {
	// DISC-004: serve a fresh cache entry without any HTTP request.
	if doc, ok := c.lookup(issuerURL); ok {
		return doc, nil
	}

	// Singleflight collapses concurrent misses into one in-flight request.
	v, err, _ := c.group.Do(issuerURL, func() (interface{}, error) {
		// Re-check under the flight in case another goroutine just populated
		// the cache (DISC-005 boundary).
		if doc, ok := c.lookup(issuerURL); ok {
			return doc, nil
		}
		doc, err := fetchAndValidate(ctx, issuerURL, cfg)
		if err != nil {
			return nil, err
		}
		// Only successful fetches are cached.
		c.store(issuerURL, doc, cfg.cacheTTL)
		return doc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*ProviderConfiguration), nil
}

// reset clears all cached entries and restores the wall clock. Test-only helper
// to isolate cases that share the package-global cache.
func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
	c.now = time.Now
}
