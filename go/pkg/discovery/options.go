package discovery

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultCacheTTL is the default lifetime of a cached discovery document when
// [WithCacheTTL] is not supplied.
const defaultCacheTTL = 24 * time.Hour

// defaultMaxCacheEntries bounds how many distinct issuer entries the
// package-level cache retains when [WithMaxCacheEntries] and the
// DISCO_CACHE_MAX_ENTRIES environment variable are both unset. 64 covers any
// realistic multi-issuer deployment while keeping worst-case memory bounded
// against an unbounded-growth (DoS) attack that drives the relying party to
// resolve many distinct issuers. Mirrors the reference implementation's default
// (py-identity-model JWKS_CACHE_MAX_ENTRIES=64).
const defaultMaxCacheEntries = 64

// maxCacheEntriesEnv is the environment variable that overrides
// [defaultMaxCacheEntries].
const maxCacheEntriesEnv = "DISCO_CACHE_MAX_ENTRIES"

// config holds the resolved settings for a FetchConfiguration call.
type config struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	timeout    time.Duration
	allowHTTP  bool
	maxEntries int
}

// Option customises FetchConfiguration via the functional-options pattern.
type Option func(*config)

// newConfig applies opts on top of the defaults.
func newConfig(opts ...Option) *config {
	cfg := &config{
		httpClient: http.DefaultClient,
		cacheTTL:   defaultCacheTTL,
		maxEntries: maxCacheEntriesFromEnv(),
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
	// maxEntries is deliberately not clamped: a value <= 0 is the documented
	// unbounded escape hatch, so it must reach the cache verbatim.
	return cfg
}

// maxCacheEntriesFromEnv resolves the default cache bound from
// DISCO_CACHE_MAX_ENTRIES. An unset, empty, non-integer or negative value falls
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

// WithCacheTTL sets how long a fetched configuration is cached before the next
// call re-fetches it. The default is 24 hours. A non-positive duration is
// ignored and the default is retained.
func WithCacheTTL(d time.Duration) Option {
	return func(c *config) { c.cacheTTL = d }
}

// WithHTTPClient uses client for the discovery request instead of
// [http.DefaultClient].
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

// WithTimeout bounds the discovery request with a context deadline of d. It
// composes with the caller's context; the earlier deadline wins.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithInsecureAllowHTTP permits http:// issuer URLs, which are otherwise
// rejected (DISC-010). Intended for local development and integration tests
// against non-TLS providers; do not use in production.
func WithInsecureAllowHTTP() Option {
	return func(c *config) { c.allowHTTP = true }
}

// WithMaxCacheEntries bounds the number of distinct issuer entries the
// package-level cache retains. When the bound is exceeded the least-recently-used
// entry is evicted (a read hit or a store counts as a use). This caps memory
// against a caller driven to resolve many distinct issuers — a multi-tenant
// gateway or an attacker-supplied issuer header — which would otherwise grow the
// cache without limit (a memory-exhaustion DoS).
//
// The default is 64 (see [defaultMaxCacheEntries]); it can also be set process-
// wide with the DISCO_CACHE_MAX_ENTRIES environment variable, which this option
// overrides for the call. A value of 0 disables the bound (unbounded), the
// backward-compatible escape hatch for callers that accept the risk; a negative
// value is invalid and falls back to the default, matching the
// DISCO_CACHE_MAX_ENTRIES env-var semantics so a mis-parsed config value cannot
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
