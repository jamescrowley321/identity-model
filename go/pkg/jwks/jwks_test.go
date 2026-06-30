package jwks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixture reads a shared conformance fixture from spec/test-fixtures/jwks.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/jwks; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "jwks", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// newServer returns an httptest server serving body with status and a pointer
// to a counter incremented on each request.
func newServer(t *testing.T, status int, body []byte) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// freshCache isolates a test from the package-global cache.
func freshCache(t *testing.T) {
	t.Helper()
	globalCache.reset()
	t.Cleanup(globalCache.reset)
}

// rsaKeyJSON returns a minimal valid RSA signing key with the given kid. The
// modulus is a non-empty placeholder; parameter validation only checks for
// presence (decoding into crypto material is the verifier's job, G3.4).
func rsaKeyJSON(kid string) string {
	return `{"kty":"RSA","kid":"` + kid + `","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}`
}

// keySetJSON wraps one or more key JSON objects in a JWK Set document.
func keySetJSON(keys ...string) []byte {
	return []byte(`{"keys":[` + strings.Join(keys, ",") + `]}`)
}

// JWKS-001: fetch and parse a valid JWK Set (RSA + EC) from the shared fixture.
func TestFetchKeySet_Valid(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, fixture(t, "valid.json"))

	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(set.Keys))
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("HTTP requests = %d, want 1", got)
	}
}

// JWKS-002: each key exposes the required parameters; RSA exposes n/e and EC
// exposes crv/x/y.
func TestParseKey_RequiredParams(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "valid.json"))
	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}

	rsa, ok := set.ResolveKey("rsa-sig-key")
	if !ok {
		t.Fatal("rsa-sig-key not resolved")
	}
	for name, val := range map[string]string{
		"kty": rsa.Kty, "kid": rsa.Kid, "use": rsa.Use, "alg": rsa.Alg, "n": rsa.N, "e": rsa.E,
	} {
		if val == "" {
			t.Errorf("RSA key parameter %q is empty", name)
		}
	}
	if rsa.Kty != "RSA" {
		t.Errorf("RSA kty = %q, want RSA", rsa.Kty)
	}

	ec, ok := set.ResolveKey("ec-sig-key")
	if !ok {
		t.Fatal("ec-sig-key not resolved")
	}
	for name, val := range map[string]string{
		"kty": ec.Kty, "kid": ec.Kid, "crv": ec.Crv, "x": ec.X, "y": ec.Y,
	} {
		if val == "" {
			t.Errorf("EC key parameter %q is empty", name)
		}
	}
	if ec.Kty != "EC" {
		t.Errorf("EC kty = %q, want EC", ec.Kty)
	}
}

// JWKS-002 (negative): a key missing required type material is rejected.
func TestParseKey_InvalidKeyRejected(t *testing.T) {
	freshCache(t)
	// RSA key missing the exponent "e".
	srv, _ := newServer(t, http.StatusOK, keySetJSON(`{"kty":"RSA","kid":"broken","n":"AQAB"}`))
	_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var iErr *InvalidKeyError
	if !errors.As(err, &iErr) {
		t.Fatalf("err = %v, want *InvalidKeyError", err)
	}
	if iErr.Kid != "broken" {
		t.Errorf("invalid key kid = %q, want broken", iErr.Kid)
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("errors.Is(ErrInvalidKey) = false")
	}
}

// JWKS-002: a key missing kty is rejected (the only universally required member).
func TestParseKey_MissingKtyRejected(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, keySetJSON(`{"kid":"no-kty","n":"AQAB","e":"AQAB"}`))
	_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

// JWKS-002: unmodelled key parameters are preserved in Extra, and modelled ones
// do not leak into it.
func TestParseKey_PreservesExtra(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, keySetJSON(
		`{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB","x5t":"abc","x5c":["cert"]}`))
	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	k := set.Keys[0]
	for _, want := range []string{"x5t", "x5c"} {
		if _, ok := k.Extra[want]; !ok {
			t.Errorf("extra parameter %q not preserved, got %v", want, k.Extra)
		}
	}
	for _, modelled := range []string{"kty", "kid", "n", "e"} {
		if _, ok := k.Extra[modelled]; ok {
			t.Errorf("modelled parameter %q leaked into Extra", modelled)
		}
	}
}

// Defensive copy: mutating a key resolved from one handle (or its Extra map)
// must not corrupt the shared cached set seen by a second handle for the same
// URI. Guards against the cache aliasing fixed in the review.
func TestResolveKey_ReturnsIsolatedCopy(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, keySetJSON(
		`{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB","x5t":"orig"}`))

	first, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet (first): %v", err)
	}
	k, ok := first.ResolveKey("k1")
	if !ok {
		t.Fatal("k1 not resolved")
	}
	// Mutate the returned key's fields and Extra map.
	k.Kty = "TAMPERED"
	k.Extra["x5t"] = []byte(`"hacked"`)
	first.Keys[0].Alg = "TAMPERED"

	// A second cache-hit handle must see the original, untouched values.
	second, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet (second): %v", err)
	}
	k2, ok := second.ResolveKey("k1")
	if !ok {
		t.Fatal("k1 not resolved on second handle")
	}
	if k2.Kty != "RSA" {
		t.Errorf("cached kty corrupted: got %q, want RSA", k2.Kty)
	}
	if k2.Alg != "" {
		t.Errorf("cached alg corrupted: got %q, want empty", k2.Alg)
	}
	if got := string(k2.Extra["x5t"]); got != `"orig"` {
		t.Errorf("cached Extra corrupted: got %s, want \"orig\"", got)
	}
}

// JWKS-003: resolve a key by kid; an absent kid reports not found.
func TestResolveKey_ByKid(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "valid.json"))
	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	if k, ok := set.ResolveKey("ec-sig-key"); !ok || k.Kid != "ec-sig-key" {
		t.Errorf("ResolveKey(ec-sig-key) = %v, %v", k, ok)
	}
	if _, ok := set.ResolveKey("absent"); ok {
		t.Error("ResolveKey(absent) = true, want false")
	}
}

// JWKS-004: a miss triggers a forced refresh and a retry that then succeeds
// (key rotation).
func TestResolveKeyWithRefresh_MissThenRefresh(t *testing.T) {
	freshCache(t)
	var rotated atomic.Bool
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if rotated.Load() {
			_, _ = w.Write(keySetJSON(rsaKeyJSON("old-key"), rsaKeyJSON("new-key")))
			return
		}
		_, _ = w.Write(keySetJSON(rsaKeyJSON("old-key")))
	}))
	t.Cleanup(srv.Close)

	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	// "new-key" is not yet published; the provider rotates it in.
	rotated.Store(true)
	k, err := set.ResolveKeyWithRefresh(context.Background(), "new-key")
	if err != nil {
		t.Fatalf("ResolveKeyWithRefresh: %v", err)
	}
	if k.Kid != "new-key" {
		t.Errorf("resolved kid = %q, want new-key", k.Kid)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("HTTP requests = %d, want 2 (initial + forced refresh)", got)
	}
}

// JWKS-004: when the kid is still absent after a forced refresh, a
// key-not-found error is returned.
func TestResolveKeyWithRefresh_StillMissing(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, keySetJSON(rsaKeyJSON("only-key")))
	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	_, err = set.ResolveKeyWithRefresh(context.Background(), "ghost")
	var kErr *KeyNotFoundError
	if !errors.As(err, &kErr) {
		t.Fatalf("err = %v, want *KeyNotFoundError", err)
	}
	if kErr.Kid != "ghost" {
		t.Errorf("not-found kid = %q, want ghost", kErr.Kid)
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("errors.Is(ErrKeyNotFound) = false")
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("HTTP requests = %d, want 2 (initial + forced refresh)", got)
	}
}

// JWKS-005: a second call within the TTL is served from cache (no HTTP request).
func TestFetchKeySet_CacheHit(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, fixture(t, "valid.json"))
	for i := 0; i < 3; i++ {
		if _, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("HTTP requests = %d, want 1 (cache hit)", got)
	}
}

// JWKS-005: after the TTL expires the next call re-fetches.
func TestFetchKeySet_CacheExpiry(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, fixture(t, "valid.json"))

	base := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	globalCache.mu.Lock()
	globalCache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	globalCache.mu.Unlock()

	if _, err := FetchKeySet(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	// Within TTL: cache hit.
	clock.Store(base.Add(30 * time.Second).UnixNano())
	if _, err := FetchKeySet(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("after within-TTL call, requests = %d, want 1", got)
	}
	// Past TTL: re-fetch.
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	if _, err := FetchKeySet(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Errorf("after TTL expiry, requests = %d, want 2", got)
	}
}

// JWKS-006: ForceRefresh invalidates and re-fetches, exposing rotated keys.
func TestForceRefresh(t *testing.T) {
	freshCache(t)
	var rotated atomic.Bool
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if rotated.Load() {
			_, _ = w.Write(keySetJSON(rsaKeyJSON("rotated-key")))
			return
		}
		_, _ = w.Write(keySetJSON(rsaKeyJSON("original-key")))
	}))
	t.Cleanup(srv.Close)

	set, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	if _, ok := set.ResolveKey("original-key"); !ok {
		t.Fatal("original-key not present before refresh")
	}

	rotated.Store(true)
	if err := set.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if _, ok := set.ResolveKey("rotated-key"); !ok {
		t.Error("rotated-key not present after ForceRefresh")
	}
	if _, ok := set.ResolveKey("original-key"); ok {
		t.Error("original-key still present after ForceRefresh (cache not invalidated)")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("HTTP requests = %d, want 2 (initial + forced refresh)", got)
	}
}

// JWKS-007: a malformed (non-JSON) body surfaces a parse error.
func TestFetchKeySet_Malformed(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, []byte("not json <html>"))
	_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var pErr *ParseError
	if !errors.As(err, &pErr) {
		t.Fatalf("err = %v, want *ParseError", err)
	}
	if !errors.Is(err, ErrParse) {
		t.Errorf("errors.Is(ErrParse) = false")
	}
}

// JWKS-007: an empty key set surfaces a descriptive empty-key-set error.
func TestFetchKeySet_Empty(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "empty.json"))
	_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var eErr *EmptyKeySetError
	if !errors.As(err, &eErr) {
		t.Fatalf("err = %v, want *EmptyKeySetError", err)
	}
	if !errors.Is(err, ErrEmptyKeySet) {
		t.Errorf("errors.Is(ErrEmptyKeySet) = false")
	}
}

// AC singleflight: concurrent callers collapse to a single HTTP request.
func TestFetchKeySet_Singleflight(t *testing.T) {
	freshCache(t)
	var hits int32
	release := make(chan struct{})
	body := fixture(t, "valid.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the request open so all goroutines pile up behind it
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("HTTP requests = %d, want 1 (singleflight)", got)
	}
}

// AC options: http:// is rejected by default and allowed with WithInsecureAllowHTTP.
func TestFetchKeySet_RequiresHTTPS(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, fixture(t, "valid.json"))

	_, err := FetchKeySet(context.Background(), srv.URL)
	if !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("err = %v, want ErrHTTPSRequired", err)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("HTTPS check should short-circuit before any request, got %d", got)
	}
	if _, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
		t.Errorf("with WithInsecureAllowHTTP: %v", err)
	}
}

// AC options: a non-2xx response surfaces a typed HTTP error with the status.
func TestFetchKeySet_HTTPError(t *testing.T) {
	freshCache(t)
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		globalCache.reset()
		srv, _ := newServer(t, status, []byte(`{}`))
		_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
		var hErr *HTTPError
		if !errors.As(err, &hErr) {
			t.Fatalf("status %d: err = %v, want *HTTPError", status, err)
		}
		if hErr.StatusCode != status {
			t.Errorf("status code = %d, want %d", hErr.StatusCode, status)
		}
		if !errors.Is(err, ErrHTTPStatus) {
			t.Errorf("status %d: errors.Is(ErrHTTPStatus) = false", status)
		}
	}
}

// AC options: the supplied http.Client is used for the request.
func TestFetchKeySet_WithHTTPClient(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "valid.json"))
	rt := &countingTransport{next: http.DefaultTransport}
	client := &http.Client{Transport: rt}
	if _, err := FetchKeySet(context.Background(), srv.URL, WithHTTPClient(client), WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	if atomic.LoadInt32(&rt.calls) != 1 {
		t.Errorf("custom transport calls = %d, want 1", rt.calls)
	}
}

// AC options: a short timeout surfaces a context deadline error.
func TestFetchKeySet_WithTimeout(t *testing.T) {
	freshCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write(fixture(t, "valid.json"))
	}))
	t.Cleanup(srv.Close)

	_, err := FetchKeySet(context.Background(), srv.URL, WithTimeout(20*time.Millisecond), WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

// A blank or whitespace-only URI is a parse error, not a misleading
// HTTPS-required error.
func TestFetchKeySet_BlankURI(t *testing.T) {
	freshCache(t)
	for _, uri := range []string{"", "   "} {
		_, err := FetchKeySet(context.Background(), uri)
		if !errors.Is(err, ErrParse) {
			t.Errorf("uri %q: err = %v, want ErrParse", uri, err)
		}
	}
}

// A non-2xx response must surface as an HTTPError carrying the status even when
// the error body is large: the status check precedes the size check.
func TestFetchKeySet_LargeErrorBody(t *testing.T) {
	freshCache(t)
	big := make([]byte, maxBodyBytes+100)
	for i := range big {
		big[i] = 'x'
	}
	srv, _ := newServer(t, http.StatusInternalServerError, big)
	_, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var hErr *HTTPError
	if !errors.As(err, &hErr) {
		t.Fatalf("err = %v, want *HTTPError", err)
	}
	if hErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", hErr.StatusCode)
	}
}

// Errors must not be cached: a failure followed by success must re-fetch.
func TestFetchKeySet_ErrorsNotCached(t *testing.T) {
	freshCache(t)
	var fail atomic.Bool
	fail.Store(true)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(keySetJSON(rsaKeyJSON("k1")))
	}))
	t.Cleanup(srv.Close)

	if _, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP()); err == nil {
		t.Fatal("expected error on first call")
	}
	fail.Store(false)
	if _, err := FetchKeySet(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("second call after recovery: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("requests = %d, want 2 (error not cached)", got)
	}
}

// --- helpers ---

// reset clears all cached entries and restores the wall clock. Test-only helper
// (defined in a _test.go file so it never ships in the library binary) to
// isolate cases that share the package-global cache.
func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
	c.now = time.Now
}

type countingTransport struct {
	next  http.RoundTripper
	calls int32
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.calls, 1)
	return t.next.RoundTrip(req)
}
