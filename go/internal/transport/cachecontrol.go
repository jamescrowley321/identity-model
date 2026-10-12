package transport

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Cache lifetime clamp for a provider's Cache-Control max-age (spec/config.md
// "Cache rules").
const (
	MinCacheTTL = 60 * time.Second
	MaxCacheTTL = 86400 * time.Second
)

var (
	maxAgeRe  = regexp.MustCompile(`(?i)max-age=(\d+)`)
	noStoreRe = regexp.MustCompile(`(?i)\bno-store\b`)
	noCacheRe = regexp.MustCompile(`(?i)\bno-cache\b`)
)

// CacheControl returns every Cache-Control field of h joined into one
// comma-separated value (RFC 9110 §5.3), so a directive in a later field line
// counts as much as one in the first.
func CacheControl(h http.Header) string {
	return strings.Join(h.Values("Cache-Control"), ",")
}

// ResolveTTL returns the cache lifetime for a response with the given
// Cache-Control header: its max-age clamped to [MinCacheTTL, MaxCacheTTL], or
// def when it has none.
func ResolveTTL(cacheControl string, def time.Duration) time.Duration {
	m := maxAgeRe.FindStringSubmatch(cacheControl)
	if m == nil {
		return def
	}
	secs, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || secs > int64(MaxCacheTTL/time.Second) {
		// Only an out-of-range number fails to parse: \d+ is all digits.
		return MaxCacheTTL
	}
	return max(time.Duration(secs)*time.Second, MinCacheTTL)
}

// Uncacheable reports whether Cache-Control forbids caching the response
// (no-store, RFC 9111 §5.2.2.5, or no-cache, §5.2.2.4). The discovery cache
// honours it; the JWKS cache deliberately does not (#396).
func Uncacheable(cacheControl string) bool {
	return noStoreRe.MatchString(cacheControl) || noCacheRe.MatchString(cacheControl)
}
