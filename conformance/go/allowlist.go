package main

import (
	"fmt"
	"net/url"
	"strings"
)

// reasonIssuerNotAllowed is recorded when RP_ALLOWED_ISSUER_ORIGINS is set and
// the issuer a caller names is outside it; the harness then contacts nothing.
const reasonIssuerNotAllowed = "issuer_not_allowed"

// parseAllowedOrigins parses RP_ALLOWED_ISSUER_ORIGINS: a comma-separated list
// of origins (scheme://host[:port], a trailing "/" tolerated). Empty means no
// restriction. An entry with a path, query, fragment or user info is an error,
// so a misconfiguration fails at start-up instead of silently allowing more.
func parseAllowedOrigins(raw string) ([]string, error) {
	var origins []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil {
			return nil, fmt.Errorf("RP_ALLOWED_ISSUER_ORIGINS entry %q: %w", entry, err)
		}
		if u.Scheme == "" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("RP_ALLOWED_ISSUER_ORIGINS entry %q is not an origin (scheme://host[:port])", entry)
		}
		origins = append(origins, origin(u))
	}
	return origins, nil
}

// issuerAllowed reports whether issuer's origin is one of allowed. An empty
// allowlist allows every issuer. The comparison is on the parsed scheme and
// host (case-insensitive host, exact port), never a string prefix, so
// "https://suite.example@evil.test" or "https://suite.example.evil.test" never
// match "https://suite.example".
func issuerAllowed(allowed []string, issuer string) bool {
	if len(allowed) == 0 {
		return true
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return false
	}
	got := origin(u)
	for _, a := range allowed {
		if a == got {
			return true
		}
	}
	return false
}

func origin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}
