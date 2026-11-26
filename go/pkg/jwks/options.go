package jwks

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultCacheTTL is the default lifetime of a cached JWK Set when
// [WithCacheTTL] is not supplied. Signing keys rotate infrequently, so a long
// TTL is safe — a key-not-found resolution forces a refresh regardless
// (JWKS-004).
const defaultCacheTTL = 24 * time.Hour

// defaultMaxCacheEntries bounds how many distinct jwks_uri entries the
// package-level cache retains when [WithMaxCacheEntries] and the
// JWKS_CACHE_MAX_ENTRIES environment variable are both unset. 64 covers any
// realistic multi-issuer deployment while keeping worst-case memory bounded
// against an unbounded-growth (DoS) attack that drives the relying party to
// resolve tokens against many distinct jwks_uri values. Mirrors the reference
// implementation's default (py-identity-model JWKS_CACHE_MAX_ENTRIES=64).
const defaultMaxCacheEntries = 64

// maxCacheEntriesEnv is the environment variable that overrides
// [defaultMaxCacheEntries].
const maxCacheEntriesEnv = "JWKS_CACHE_MAX_ENTRIES"

// defaultRefreshCooldown is the minimum interval between automatic forced
// refreshes for a given jwks_uri (see [WithRefreshCooldown]). It bounds the rate
// at which an unknown kid can trigger a network re-fetch, so an attacker
// presenting tokens with random kid values cannot amplify traffic against the
// provider. Explicit [JSONWebKeySet.ForceRefresh] is not throttled.
const defaultRefreshCooldown = 5 * time.Second

// config holds the resolved settings for a FetchKeySet call.
type config struct {
	httpClient      *http.Client
	cacheTTL        time.Duration
	timeout         time.Duration
	allowHTTP       bool
	refreshCooldown time.Duration
	maxEntries      int
}

// Option customises FetchKeySet via the functional-options pattern. The option
// surface mirrors the discovery client so the two compose consistently.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		httpClient:      http.DefaultClient,
		cacheTTL:        defaultCacheTTL,
		refreshCooldown: defaultRefreshCooldown,
		maxEntries:      maxCacheEntriesFromEnv(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}
	if cfg.cacheTTL <= 0 {
		cfg.cacheTTL = defaultCacheTTL
	}
	if cfg.refreshCooldown < 0 {
		cfg.refreshCooldown = defaultRefreshCooldown
	}
	// maxEntries is deliberately not clamped: a value <= 0 is the documented
	// unbounded escape hatch, so it must reach the cache verbatim.
	return cfg
}

// maxCacheEntriesFromEnv resolves the default cache bound from
// JWKS_CACHE_MAX_ENTRIES. An unset, empty, non-integer or negative value falls
// back to [defaultMaxCacheEntries] so a typo cannot silently unbound or corrupt
// the cache; a value of 0 selects the unbounded escape hatch, and any positive
// integer is the LRU cap. Matches the Rust and Python ports, which also reject
// negative values rather than treating them as unbounded (cross-language
// parity on the shared env contract).
func maxCacheEntriesFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(maxCacheEntriesEnv))
	if raw == "" {
		return defaultMaxCacheEntries
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return defaultMaxCacheEntries
	}
	return n
}

// WithCacheTTL sets how long a fetched key set is cached before the next call
// re-fetches it. The default is 24 hours. A non-positive duration is ignored
// and the default is retained.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithHTTPClient uses client for the JWKS request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the JWKS request with a context deadline of d. It composes
// with the caller's context; the earlier deadline wins.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithRefreshCooldown sets the minimum interval between automatic forced
// refreshes triggered by [JSONWebKeySet.ResolveKeyWithRefresh] for the same
// jwks_uri. Within the cooldown a kid miss returns a key-not-found error without
// re-fetching, bounding attacker-driven re-fetches when token kid values are
// untrusted. The default is 5 seconds. A zero value disables throttling; a
// negative value is ignored and the default is retained. Explicit
// [JSONWebKeySet.ForceRefresh] is never throttled.
func WithRefreshCooldown(d time.Duration) Option {
	return func(c *config) { c.refreshCooldown = d }
}

// WithInsecureAllowHTTP permits http:// jwks_uri values, which are otherwise
// rejected. Intended for local development and integration tests against
// non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}

// WithMaxCacheEntries bounds the number of distinct jwks_uri entries the
// package-level cache retains. When the bound is exceeded the least-recently-used
// entry is evicted (a read hit or a store counts as a use), and the evicted
// URI's refresh-cooldown record is dropped in lockstep so that sidecar stays
// bounded too. This caps memory against a caller driven to resolve tokens
// against many distinct jwks_uri values — a multi-tenant gateway or an
// attacker-supplied issuer header — which would otherwise grow the cache
// without limit (a memory-exhaustion DoS).
//
// The default is 64 (see [defaultMaxCacheEntries]); it can also be set process-
// wide with the JWKS_CACHE_MAX_ENTRIES environment variable, which this option
// overrides for the call. A value of 0 disables the bound (unbounded), the
// backward-compatible escape hatch for callers that accept the risk; a negative
// value is invalid and falls back to the default, matching the
// JWKS_CACHE_MAX_ENTRIES env-var semantics so a mis-parsed config value cannot
// silently unbound the cache.
//
// Because the cache is shared, the bound applied to a stored entry is the one
// supplied by the caller that wins the fetch flight (first-wins), consistent
// with [WithCacheTTL].
func WithMaxCacheEntries(n int) Option {
	return func(c *config) {
		if n < 0 {
			n = defaultMaxCacheEntries
		}
		c.maxEntries = n
	}
}
