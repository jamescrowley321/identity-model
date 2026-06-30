package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxBodyBytes caps the JWKS response read into memory. A key set is a small
// JSON object; this guards against a malicious or misconfigured provider
// streaming an unbounded body (memory-exhaustion DoS).
const maxBodyBytes = 1 << 20 // 1 MiB

// defaultRequestTimeout bounds a fetch when neither [WithTimeout] nor the
// caller's context supplies a deadline, so a hung server cannot block forever.
const defaultRequestTimeout = 30 * time.Second

// JSONWebKey is a single JSON Web Key (RFC 7517 §4). The common signing-key
// parameters are modelled as fields; key-type-specific material is exposed as
// strings (base64url-encoded per RFC 7518) for a later verifier to decode into
// a crypto.PublicKey. Parameters not modelled here are preserved in Extra.
type JSONWebKey struct {
	Kty string `json:"kty"`           // key type (RFC 7517 §4.1, required)
	Kid string `json:"kid,omitempty"` // key ID (RFC 7517 §4.5)
	Use string `json:"use,omitempty"` // public key use, e.g. "sig" (§4.2)
	Alg string `json:"alg,omitempty"` // algorithm, e.g. "RS256" (§4.4)

	// RSA parameters (RFC 7518 §6.3.1).
	N string `json:"n,omitempty"` // modulus
	E string `json:"e,omitempty"` // exponent

	// EC parameters (RFC 7518 §6.2.1).
	Crv string `json:"crv,omitempty"` // curve
	X   string `json:"x,omitempty"`   // x coordinate
	Y   string `json:"y,omitempty"`   // y coordinate

	// Extra holds any key parameters not modelled above (e.g. x5c, x5t).
	Extra map[string]json.RawMessage `json:"-"`
}

// modelledKeyFields is the set of JSON names decoded into named [JSONWebKey]
// fields. They are excluded from Extra so Extra holds only unmodelled
// parameters, honouring its documented contract.
var modelledKeyFields = map[string]struct{}{
	"kty": {}, "kid": {}, "use": {}, "alg": {},
	"n": {}, "e": {},
	"crv": {}, "x": {}, "y": {},
}

// validate enforces the required parameters for a key (JWKS-002, RFC 7517 §4).
// Per §4, kty is the only universally required member; kid/use/alg are optional
// and omitted by some providers, so they are not hard-required here (see the
// package decision record). Key-type-specific material is required so a later
// verifier can construct a public key: RSA needs n and e, EC needs crv/x/y.
func (k *JSONWebKey) validate() error {
	if k.Kty == "" {
		return &InvalidKeyError{Kid: k.Kid, Reason: "missing required parameter \"kty\""}
	}
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return &InvalidKeyError{Kid: k.Kid, Reason: "RSA key missing modulus \"n\" or exponent \"e\""}
		}
	case "EC":
		if k.Crv == "" || k.X == "" || k.Y == "" {
			return &InvalidKeyError{Kid: k.Kid, Reason: "EC key missing curve \"crv\", \"x\" or \"y\""}
		}
	}
	// Other key types (e.g. oct, OKP) are accepted without parameter checks;
	// their material is not modelled and is preserved in Extra.
	return nil
}

// JSONWebKeySet is a parsed JWK Set (RFC 7517 §5) plus the state needed to
// refresh it. Keys holds the keys in document order. The handle remembers the
// source URI and configuration so [JSONWebKeySet.ForceRefresh] and
// [JSONWebKeySet.ResolveKeyWithRefresh] can re-fetch on demand.
type JSONWebKeySet struct {
	Keys []JSONWebKey

	mu    sync.RWMutex
	uri   string
	cfg   *config
	cache *cache
}

// FetchKeySet fetches, parses and caches the JWK Set at jwksURI (typically the
// jwks_uri from discovery). It returns a [JSONWebKeySet] containing all keys
// (JWKS-001, RFC 7517 §5).
//
// Results are cached with a configurable TTL (default 24h, see [WithCacheTTL]);
// a cache hit within the TTL makes no HTTP request (JWKS-005), and concurrent
// calls for the same URI are deduplicated to a single in-flight request
// (singleflight).
func FetchKeySet(ctx context.Context, jwksURI string, opts ...Option) (*JSONWebKeySet, error) {
	cfg := newConfig(opts...)
	keys, err := globalCache.fetch(ctx, jwksURI, cfg)
	if err != nil {
		return nil, err
	}
	return &JSONWebKeySet{Keys: keys, uri: jwksURI, cfg: cfg, cache: globalCache}, nil
}

// ResolveKey returns the key whose kid matches and reports whether one was
// found, scanning the in-memory set only (JWKS-003, RFC 7517 §4.5). It makes no
// network request; use [JSONWebKeySet.ResolveKeyWithRefresh] to re-fetch on a
// miss.
func (s *JSONWebKeySet) ResolveKey(kid string) (*JSONWebKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.Keys {
		if s.Keys[i].Kid == kid {
			k := cloneKey(s.Keys[i])
			return &k, true
		}
	}
	return nil, false
}

// ResolveKeyWithRefresh resolves kid, and on a miss performs one forced refresh
// and retries before returning a [KeyNotFoundError] (JWKS-004). This handles
// key rotation: a token signed with a freshly published key whose kid is not
// yet cached triggers a re-fetch.
func (s *JSONWebKeySet) ResolveKeyWithRefresh(ctx context.Context, kid string) (*JSONWebKey, error) {
	if k, ok := s.ResolveKey(kid); ok {
		return k, nil
	}
	if err := s.ForceRefresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := s.ResolveKey(kid); ok {
		return k, nil
	}
	return nil, &KeyNotFoundError{Kid: kid}
}

// ForceRefresh invalidates the cached set for this URI and re-fetches it,
// replacing Keys with the fresh set (JWKS-006). Callers invoke it after a
// signature verification failure that may indicate the provider has rotated its
// keys.
func (s *JSONWebKeySet) ForceRefresh(ctx context.Context) error {
	s.cache.invalidate(s.uri)
	keys, err := s.cache.fetch(ctx, s.uri, s.cfg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.Keys = keys
	s.mu.Unlock()
	return nil
}

// fetchAndParse performs the HTTP request, parses the body and validates each
// key. It contains no caching logic so it can be invoked once per singleflight
// group.
func fetchAndParse(ctx context.Context, jwksURI string, cfg *config) ([]JSONWebKey, error) {
	uri := strings.TrimSpace(jwksURI)
	if uri == "" {
		return nil, &ParseError{Err: fmt.Errorf("jwks URI is empty")}
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, &ParseError{Err: fmt.Errorf("invalid jwks URI %q: %w", jwksURI, err)}
	}
	// Require HTTPS in production; http:// only with WithInsecureAllowHTTP.
	if parsed.Scheme != "https" && !(cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, &HTTPSRequiredError{URI: jwksURI}
	}

	// Always bound the request: the configured timeout, or a default so a hung
	// server cannot block indefinitely.
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", uri, err)
	}
	defer resp.Body.Close()

	// Cap the body to guard against an unbounded response (memory-exhaustion
	// DoS). Read one extra byte so an oversized body can be detected below.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}

	// A non-2xx response is a transport error carrying the status code. Check
	// this before the size check so a large error page still surfaces as an
	// HTTPError (with its status) rather than a misleading parse error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: uri}
	}

	if len(body) > maxBodyBytes {
		return nil, &ParseError{Err: fmt.Errorf("jwks document exceeds %d bytes", maxBodyBytes)}
	}

	return parseKeySet(body, uri)
}

// parseKeySet decodes a JWK Set body into validated keys (JWKS-001/002/007).
func parseKeySet(body []byte, uri string) ([]JSONWebKey, error) {
	// JWKS-007: a non-JSON body, or one whose "keys" member is not an array,
	// is a parse error.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &ParseError{Err: err}
	}

	keys := make([]JSONWebKey, 0, len(doc.Keys))
	for _, raw := range doc.Keys {
		k, err := parseKey(raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	// JWKS-007: an empty (or absent) key set yields no usable keys.
	if len(keys) == 0 {
		return nil, &EmptyKeySetError{URI: uri}
	}
	return keys, nil
}

// cloneKey returns a deep copy of k, duplicating the Extra map so a caller that
// mutates the returned key cannot reach into a key set shared by the cache or by
// another handle. The json.RawMessage values are treated as read-only and are
// not themselves copied.
func cloneKey(k JSONWebKey) JSONWebKey {
	if k.Extra != nil {
		extra := make(map[string]json.RawMessage, len(k.Extra))
		for name, raw := range k.Extra {
			extra[name] = raw
		}
		k.Extra = extra
	}
	return k
}

// cloneKeys returns a deep copy of keys so every handle owns an isolated slice;
// mutating one handle's Keys never affects the cached master copy or another
// handle that resolved the same URI.
func cloneKeys(keys []JSONWebKey) []JSONWebKey {
	if keys == nil {
		return nil
	}
	out := make([]JSONWebKey, len(keys))
	for i := range keys {
		out[i] = cloneKey(keys[i])
	}
	return out
}

// parseKey decodes and validates a single JWK, preserving unmodelled parameters
// in Extra (RFC 7517 §4).
func parseKey(raw json.RawMessage) (JSONWebKey, error) {
	var k JSONWebKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return JSONWebKey{}, &ParseError{Err: err}
	}
	// Preserve only unmodelled parameters in Extra. Decoding into a map then
	// dropping the modelled keys keeps Extra true to its contract.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return JSONWebKey{}, &ParseError{Err: err}
	}
	for name := range m {
		if _, modelled := modelledKeyFields[name]; modelled {
			delete(m, name)
		}
	}
	if len(m) > 0 {
		k.Extra = m
	}
	if err := k.validate(); err != nil {
		return JSONWebKey{}, err
	}
	return k, nil
}
