package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The max-entries LRU bound is exercised here directly against the cache methods
// (store/lookup/evict) so the recency behaviour is asserted without the noise of
// HTTP plumbing; TestFetchConfiguration_MaxCacheEntries_EvictsLRU then proves the
// same bound flows through the public FetchConfiguration path.

// cfgFor builds a minimal provider configuration stored under a synthetic
// issuer. store and lookup do no validation, so an issuer-only doc identifies an
// entry.
func cfgFor(id string) *ProviderConfiguration {
	return &ProviderConfiguration{Issuer: id}
}

// cacheLen returns the number of live entries without promoting any of them
// (lookup would bump an entry's recency and perturb the LRU order).
func cacheLen(c *cache) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cacheHas reports whether key is present without promoting it.
func cacheHas(c *cache, key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.entries[key]
	return ok
}

// (a) The number of cached entries never exceeds the configured cap, regardless
// of how many distinct issuers are inserted.
func TestCache_SizeNeverExceedsCap(t *testing.T) {
	for _, limit := range []int{1, 2, 8, 64} {
		t.Run(fmt.Sprintf("cap=%d", limit), func(t *testing.T) {
			c := newCache(time.Hour, limit)
			for i := 0; i < limit*4; i++ {
				key := fmt.Sprintf("https://issuer.example/%d", i)
				c.store(key, cfgFor(key), time.Hour)
				if got := cacheLen(c); got > limit {
					t.Fatalf("after %d inserts, size = %d, want <= %d", i+1, got, limit)
				}
			}
			if got := cacheLen(c); got != limit {
				t.Errorf("final size = %d, want %d (cap saturated)", got, limit)
			}
		})
	}
}

// (b) Eviction is least-recently-used: the entry evicted under pressure is the
// one used longest ago, and a read hit refreshes recency so a would-be victim
// survives. Each case runs a script of store("s:key") / read("r:key") ops
// against a cap-2 cache and asserts exactly which keys survive.
func TestCache_LRUEvictionOrder(t *testing.T) {
	const limit = 2
	tests := []struct {
		name     string
		ops      []string
		survives []string
		evicted  []string
	}{
		{
			name:     "insertion order evicts oldest",
			ops:      []string{"s:A", "s:B", "s:C"},
			survives: []string{"B", "C"},
			evicted:  []string{"A"},
		},
		{
			name:     "read refreshes recency so oldest survives",
			ops:      []string{"s:A", "s:B", "r:A", "s:C"},
			survives: []string{"A", "C"},
			evicted:  []string{"B"},
		},
		{
			name:     "restore promotes on write so it is not the next victim",
			ops:      []string{"s:A", "s:B", "s:A", "s:C"},
			survives: []string{"A", "C"},
			evicted:  []string{"B"},
		},
		{
			name:     "read miss on evicted key does not promote it back",
			ops:      []string{"s:A", "s:B", "s:C", "r:A"},
			survives: []string{"B", "C"},
			evicted:  []string{"A"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(time.Hour, limit)
			for _, op := range tt.ops {
				action, id := op[:1], op[2:]
				switch action {
				case "s":
					c.store(id, cfgFor(id), time.Hour)
				case "r":
					c.lookup(id)
				default:
					t.Fatalf("bad op %q", op)
				}
			}
			if got := cacheLen(c); got != limit {
				t.Fatalf("size = %d, want %d", got, limit)
			}
			for _, id := range tt.survives {
				if !cacheHas(c, id) {
					t.Errorf("%q was evicted, want retained", id)
				}
			}
			for _, id := range tt.evicted {
				if cacheHas(c, id) {
					t.Errorf("%q was retained, want evicted", id)
				}
			}
		})
	}
}

// (e) The bound must not regress TTL expiry: a bounded cache still expires
// entries by TTL, and an expired entry is not served (nor promoted) on lookup.
func TestCache_BoundDoesNotRegressTTL(t *testing.T) {
	c := newCache(time.Hour, 8)
	base := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	c.now = func() time.Time { return time.Unix(0, clock.Load()) }

	c.store("A", cfgFor("A"), time.Minute)

	// Within TTL: hit.
	if _, ok := c.lookup("A"); !ok {
		t.Fatal("within TTL: lookup(A) = miss, want hit")
	}
	// Past TTL: miss, even though the entry still occupies a slot.
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	if _, ok := c.lookup("A"); ok {
		t.Error("past TTL: lookup(A) = hit, want miss (TTL regressed)")
	}
}

// End-to-end: the bound flows through FetchConfiguration. With a cap of 2,
// fetching three distinct issuers evicts the least-recently-used one, so
// re-fetching it re-hits the network while the most-recently-used issuer is
// still served from cache. This proves WithMaxCacheEntries is wired into the
// public API and that singleflight-backed fetch/store still honour the bound.
func TestFetchConfiguration_MaxCacheEntries_EvictsLRU(t *testing.T) {
	newDiscoServer := func() (string, *int32) {
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != wellKnownPath {
				http.NotFound(w, r)
				return
			}
			atomic.AddInt32(&hits, 1)
			_, _ = w.Write(validDocFor(httpURL(r)))
		}))
		t.Cleanup(srv.Close)
		return srv.URL, &hits
	}

	urlA, hitsA := newDiscoServer()
	urlB, _ := newDiscoServer() // B's fate depends on the re-fetch sequence; not asserted.
	urlC, hitsC := newDiscoServer()

	client := testClient(t, WithInsecureAllowHTTP(), WithMaxCacheEntries(2))
	for _, u := range []string{urlA, urlB, urlC} {
		if _, err := client.FetchConfiguration(context.Background(), u); err != nil {
			t.Fatalf("FetchConfiguration(%s): %v", u, err)
		}
	}
	// A was the least-recently-used of {A,B,C} and is evicted by C's insert.
	if got := atomic.LoadInt32(hitsA); got != 1 {
		t.Fatalf("precondition: A fetched %d times, want 1", got)
	}

	// Re-fetching A misses (evicted) → one more network hit.
	if _, err := client.FetchConfiguration(context.Background(), urlA); err != nil {
		t.Fatalf("re-fetch A: %v", err)
	}
	if got := atomic.LoadInt32(hitsA); got != 2 {
		t.Errorf("A hits = %d, want 2 (evicted then re-fetched)", got)
	}

	// C was most-recently-used and is still cached → served without a network hit.
	if _, err := client.FetchConfiguration(context.Background(), urlC); err != nil {
		t.Fatalf("re-fetch C: %v", err)
	}
	if got := atomic.LoadInt32(hitsC); got != 1 {
		t.Errorf("C hits = %d, want 1 (still cached)", got)
	}
}
