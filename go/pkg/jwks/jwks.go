package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

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
// source URI and its [Client] so [JSONWebKeySet.ForceRefresh] and
// [JSONWebKeySet.ResolveKeyWithRefresh] can re-fetch on demand.
type JSONWebKeySet struct {
	Keys []JSONWebKey

	mu     sync.RWMutex
	uri    string
	client *Client
}

// Client fetches, caches and refreshes JWK Sets. It holds its options and owns
// its cache and kid-miss cooldown state, so two clients never share cached
// keys. A Client is safe for concurrent use.
type Client struct {
	cfg       *config
	transport *transport.Transport
	cache     *cache
}

// NewClient returns a client with opts applied over the defaults. An invalid
// option value is a [*ConfigError]; it is never replaced by its default.
func NewClient(opts ...Option) (*Client, error) {
	cfg, tr, err := newConfig(opts...)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, transport: tr, cache: newCache(cfg.maxEntries)}, nil
}

// defaultClient backs the package-level [FetchKeySet]. The defaults are
// valid, so building it cannot fail.
var defaultClient = func() *Client {
	c, err := NewClient()
	if err != nil {
		panic(err)
	}
	return c
}()

// FetchKeySet fetches, parses and caches the JWK Set at jwksURI using a client
// built from the defaults. See [Client.FetchKeySet].
func FetchKeySet(ctx context.Context, jwksURI string) (*JSONWebKeySet, error) {
	return defaultClient.FetchKeySet(ctx, jwksURI)
}

// FetchKeySet fetches, parses and caches the JWK Set at jwksURI (typically the
// jwks_uri from discovery). It returns a [JSONWebKeySet] of the usable keys
// (JWKS-001, RFC 7517 §5); a key that fails validation is skipped (JWKS-008).
//
// The set is cached for the response's Cache-Control max-age, clamped to 60
// seconds – 24 hours, or for [WithCacheTTL] when there is none. no-store and
// no-cache are deliberately ignored: honouring them on public key sets turns
// every validation into a fetch (#396). A cache hit makes no HTTP request
// (JWKS-005), and concurrent calls for the same URI share one in-flight
// request (singleflight).
func (c *Client) FetchKeySet(ctx context.Context, jwksURI string) (*JSONWebKeySet, error) {
	keys, err := c.cache.fetch(ctx, jwksURI, c.loader(jwksURI))
	if err != nil {
		return nil, err
	}
	return &JSONWebKeySet{Keys: keys, uri: jwksURI, client: c}, nil
}

// loader returns the cache loader that fetches jwksURI.
func (c *Client) loader(jwksURI string) loader {
	return func(ctx context.Context) ([]JSONWebKey, time.Duration, error) {
		keys, cacheControl, err := c.fetchAndParse(ctx, jwksURI)
		if err != nil {
			return nil, 0, err
		}
		return keys, transport.ResolveTTL(cacheControl, c.cfg.cacheTTL), nil
	}
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
//
// The automatic refresh is rate-limited per jwks_uri by the refresh cooldown
// (see [WithRefreshCooldown]): because kid is taken from an untrusted token
// header, an attacker presenting tokens with random kid values would otherwise
// drive an unbounded number of outbound JWKS fetches. Within the cooldown a miss
// returns [KeyNotFoundError] without re-fetching.
func (s *JSONWebKeySet) ResolveKeyWithRefresh(ctx context.Context, kid string) (*JSONWebKey, error) {
	if k, ok := s.ResolveKey(kid); ok {
		return k, nil
	}
	if s.client.cache.refreshThrottled(s.uri, s.client.cfg.refreshCooldown) {
		return nil, &KeyNotFoundError{Kid: kid}
	}
	if err := s.ForceRefresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := s.ResolveKey(kid); ok {
		return k, nil
	}
	return nil, &KeyNotFoundError{Kid: kid}
}

// ResolveSigningKey resolves the key that verifies a token whose JOSE header
// carries kid and alg.
//
// With a kid it is [JSONWebKeySet.ResolveKeyWithRefresh]. With no kid (an OP
// may omit it when its set holds a single key, OIDC Core 1.0 §10.1) it scans
// the in-memory set only, with no forced refresh: the set is narrowed to signing
// keys (use absent or "sig", RFC 7517 §4.2; if none, every key), then, while
// more than one remains, to keys whose alg is absent or equals alg (§4.4) and to
// keys whose kty matches alg, each step applied only when it leaves a key. The
// one remaining key is returned; more than one is an [AmbiguousKeyError]
// (JWKS-009). Callers must reject alg "none" before calling it.
//
// Either way, a key that declares an alg other than a non-empty alg is not
// returned: that is a [KeyAlgorithmMismatchError] (JWKS-010, RFC 7517 §4.4).
//
// The fallback to every key when none is a signing key matches the Python
// implementation, where a kid naming a use "enc" key is also used; enforcing
// use on both paths in every language is tracked in #888.
func (s *JSONWebKeySet) ResolveSigningKey(ctx context.Context, kid, alg string) (*JSONWebKey, error) {
	var key *JSONWebKey
	var err error
	if kid != "" {
		key, err = s.ResolveKeyWithRefresh(ctx, kid)
	} else {
		key, err = s.resolveKidless(alg)
	}
	if err != nil {
		return nil, err
	}
	if alg != "" && key.Alg != "" && key.Alg != alg {
		return nil, &KeyAlgorithmMismatchError{Kid: key.Kid, KeyAlg: key.Alg, Alg: alg}
	}
	return key, nil
}

// resolveKidless selects the key for a token with no kid from the in-memory
// set, as described on [JSONWebKeySet.ResolveSigningKey].
func (s *JSONWebKeySet) resolveKidless(alg string) (*JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidates := kidlessCandidates(s.Keys, alg)
	switch len(candidates) {
	case 0:
		return nil, &KeyNotFoundError{}
	case 1:
		k := cloneKey(*candidates[0])
		return &k, nil
	}
	kids := make([]string, 0, len(candidates))
	for _, k := range candidates {
		if k.Kid != "" {
			kids = append(kids, k.Kid)
		}
	}
	return nil, &AmbiguousKeyError{Alg: alg, Kids: kids, Count: len(candidates)}
}

// algKty maps a JWS alg to the JWK kty that can verify it (RFC 7518 §3.1).
var algKty = map[string]string{
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"PS256": "RSA", "PS384": "RSA", "PS512": "RSA",
	"ES256": "EC", "ES384": "EC", "ES512": "EC", "ES256K": "EC",
	"EdDSA": "OKP", "Ed25519": "OKP", "Ed448": "OKP",
	"HS256": "oct", "HS384": "oct", "HS512": "oct",
}

// kidlessCandidates narrows keys to those that could verify a token with no
// kid, in the order and with the fallbacks described on
// [JSONWebKeySet.ResolveSigningKey].
func kidlessCandidates(keys []JSONWebKey, alg string) []*JSONWebKey {
	all := make([]*JSONWebKey, 0, len(keys))
	for i := range keys {
		all = append(all, &keys[i])
	}
	candidates := narrow(all, func(k *JSONWebKey) bool { return k.Use == "" || k.Use == "sig" })
	if len(candidates) > 1 && alg != "" {
		candidates = narrow(candidates, func(k *JSONWebKey) bool { return k.Alg == "" || k.Alg == alg })
		if kty, ok := algKty[alg]; ok {
			candidates = narrow(candidates, func(k *JSONWebKey) bool { return k.Kty == kty })
		}
	}
	return candidates
}

// narrow returns the keys that satisfy keep, or keys unchanged when none does.
func narrow(keys []*JSONWebKey, keep func(*JSONWebKey) bool) []*JSONWebKey {
	kept := make([]*JSONWebKey, 0, len(keys))
	for _, k := range keys {
		if keep(k) {
			kept = append(kept, k)
		}
	}
	if len(kept) == 0 {
		return keys
	}
	return kept
}

// ForceRefresh invalidates the cached set for this URI and re-fetches it,
// replacing Keys with the fresh set (JWKS-006). Callers invoke it after a
// signature verification failure that may indicate the provider has rotated its
// keys. Unlike the automatic refresh in [JSONWebKeySet.ResolveKeyWithRefresh],
// an explicit ForceRefresh is never throttled, but it does start the cooldown
// window that gates subsequent automatic refreshes.
func (s *JSONWebKeySet) ForceRefresh(ctx context.Context) error {
	c := s.client
	c.cache.invalidate(s.uri)
	keys, err := c.cache.fetch(ctx, s.uri, c.loader(s.uri))
	if err != nil {
		return err
	}
	c.cache.markRefresh(s.uri)
	s.mu.Lock()
	s.Keys = keys
	s.mu.Unlock()
	return nil
}

// fetchAndParse performs the HTTP request, parses the body and validates each
// key. It returns the response's Cache-Control header for the cache. It
// contains no caching logic so it can be invoked once per singleflight group.
func (c *Client) fetchAndParse(ctx context.Context, jwksURI string) ([]JSONWebKey, string, error) {
	uri := strings.TrimSpace(jwksURI)
	if uri == "" {
		return nil, "", &ParseError{Err: fmt.Errorf("jwks URI is empty")}
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, "", &ParseError{Err: fmt.Errorf("invalid jwks URI %q: %w", jwksURI, err)}
	}
	// Require HTTPS in production; http:// only with WithInsecureAllowHTTP.
	if parsed.Scheme != "https" && !(c.cfg.allowHTTP && parsed.Scheme == "http") {
		return nil, "", &HTTPSRequiredError{URI: jwksURI}
	}

	resp, err := c.transport.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("jwks: fetch %s: %w", uri, err)
	}
	defer resp.Body.Close()

	// Cap the body at WithMaxSize to guard against an unbounded response
	// (memory-exhaustion DoS). Read one extra byte so an oversized body can be
	// detected below. At math.MaxInt64 there is no extra byte to read, and +1
	// would overflow to a negative limit that reads nothing.
	maxSize := c.cfg.maxSize
	limit := int64(maxSize)
	if limit < math.MaxInt64 {
		limit++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, "", fmt.Errorf("jwks: read body: %w", err)
	}

	// A non-2xx response is a transport error carrying the status code. Check
	// this before the size check so a large error page still surfaces as an
	// HTTPError (with its status) rather than a misleading parse error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", &HTTPError{StatusCode: resp.StatusCode, URL: uri}
	}

	if len(body) > maxSize {
		return nil, "", &ParseError{Err: fmt.Errorf("jwks document exceeds %d bytes", maxSize)}
	}

	keys, err := parseKeySet(body, uri, c.cfg.maxKeys)
	if err != nil {
		return nil, "", err
	}
	return keys, transport.CacheControl(resp.Header), nil
}

// parseKeySet decodes a JWK Set body into validated keys (JWKS-001/002/007).
// A set with more than maxKeys members is rejected before any key is parsed.
func parseKeySet(body []byte, uri string, maxKeys int) ([]JSONWebKey, error) {
	// JWKS-007: a non-JSON body, or one whose "keys" member is not an array,
	// is a parse error.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &ParseError{Err: err}
	}
	if len(doc.Keys) > maxKeys {
		return nil, &ParseError{Err: fmt.Errorf("jwks document has %d keys, exceeds limit of %d", len(doc.Keys), maxKeys)}
	}

	// JWKS-008 (RFC 7517 §5): a key that fails validation or has a mistyped
	// parameter is skipped, so an unusable key cannot block resolution of a
	// usable one. A member that is not a JSON object still fails the document.
	keys := make([]JSONWebKey, 0, len(doc.Keys))
	var firstInvalid error
	for _, raw := range doc.Keys {
		k, err := parseKey(raw)
		var iErr *InvalidKeyError
		if errors.As(err, &iErr) {
			if firstInvalid == nil {
				firstInvalid = err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	// No usable key: report why the keys were rejected, else JWKS-007's
	// empty-set error.
	if len(keys) == 0 {
		if firstInvalid != nil {
			return nil, firstInvalid
		}
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
	// A member that is not a JSON object leaves the document malformed
	// (JWKS-007).
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return JSONWebKey{}, &ParseError{Err: err}
	}
	if m == nil { // JSON null decodes to a nil map without error
		return JSONWebKey{}, &ParseError{Err: errors.New("JWK Set member is null, not an object")}
	}
	// An object with a mistyped parameter (e.g. "use": 1) is one unusable key,
	// which parseKeySet skips (JWKS-008).
	var k JSONWebKey
	if err := json.Unmarshal(raw, &k); err != nil {
		var kid string
		_ = json.Unmarshal(m["kid"], &kid)
		return JSONWebKey{}, &InvalidKeyError{Kid: kid, Reason: "mistyped parameter: " + err.Error()}
	}
	// Preserve only unmodelled parameters in Extra. Decoding into a map then
	// dropping the modelled keys keeps Extra true to its contract.
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
