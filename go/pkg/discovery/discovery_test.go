package discovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixture reads a shared conformance fixture from spec/test-fixtures/discovery.
// Fixtures declare issuer https://provider.example.com; tests rewrite the issuer
// field to the httptest server URL where an exact match is required.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/discovery; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "discovery", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// newServer returns an httptest server serving body at the discovery path and a
// pointer to a counter incremented on each discovery request.
func newServer(t *testing.T, status int, body []byte) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wellKnownPath {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// validDocFor returns a valid discovery document whose issuer equals the given
// URL, so the issuer-match check (DISC-003) passes against an httptest server.
func validDocFor(issuer string) []byte {
	return []byte(`{
		"issuer": "` + issuer + `",
		"authorization_endpoint": "` + issuer + `/auth",
		"token_endpoint": "` + issuer + `/token",
		"userinfo_endpoint": "` + issuer + `/userinfo",
		"jwks_uri": "` + issuer + `/jwks",
		"response_types_supported": ["code", "id_token"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["RS256", "ES256"],
		"x_custom_extension_field": "should-be-ignored-not-rejected"
	}`)
}

// freshCache isolates a test from the package-global cache.
func freshCache(t *testing.T) {
	t.Helper()
	globalCache.reset()
	t.Cleanup(globalCache.reset)
}

// DISC-001: fetch and parse a valid discovery document.
func TestFetchConfiguration_Valid(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write(validDocFor(srv.URL))
	})

	cfg, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if cfg.Issuer != srv.URL {
		t.Errorf("issuer = %q, want %q", cfg.Issuer, srv.URL)
	}
	if cfg.TokenEndpoint != srv.URL+"/token" {
		t.Errorf("token endpoint = %q", cfg.TokenEndpoint)
	}
}

// DISC-002: all seven required fields are present and accessible.
func TestFetchConfiguration_AllRequiredFields(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validDocFor(srv.URL))
	})

	cfg, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	checks := map[string]bool{
		"issuer":                                cfg.Issuer != "",
		"authorization_endpoint":                cfg.AuthorizationEndpoint != "",
		"token_endpoint":                        cfg.TokenEndpoint != "",
		"jwks_uri":                              cfg.JWKSURI != "",
		"response_types_supported":              len(cfg.ResponseTypesSupported) > 0,
		"subject_types_supported":               len(cfg.SubjectTypesSupported) > 0,
		"id_token_signing_alg_values_supported": len(cfg.IDTokenSigningAlgValuesSupported) > 0,
	}
	for field, ok := range checks {
		if !ok {
			t.Errorf("required field %q not accessible", field)
		}
	}
}

// DISC-003: issuer mismatch is rejected.
func TestFetchConfiguration_IssuerMismatch(t *testing.T) {
	freshCache(t)
	// fixture issuer is https://attacker.example.com, never the server URL.
	srv, _ := newServer(t, http.StatusOK, fixture(t, "issuer-mismatch.json"))

	_, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("err = %v, want ErrIssuerMismatch", err)
	}
	var mErr *IssuerMismatchError
	if !errors.As(err, &mErr) {
		t.Fatalf("err = %T, want *IssuerMismatchError", err)
	}
	if mErr.Returned != "https://attacker.example.com" {
		t.Errorf("returned issuer = %q", mErr.Returned)
	}
}

// DISC-004: a second call within the TTL is served from cache (no HTTP request).
func TestFetchConfiguration_CacheHit(t *testing.T) {
	freshCache(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	for i := 0; i < 3; i++ {
		if _, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("HTTP requests = %d, want 1 (cache hit)", got)
	}
}

// DISC-005: after the TTL expires the next call re-fetches.
func TestFetchConfiguration_CacheExpiry(t *testing.T) {
	freshCache(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	// Drive time deterministically through the injectable clock.
	base := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	globalCache.mu.Lock()
	globalCache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	globalCache.mu.Unlock()

	if _, err := FetchConfiguration(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	// Within TTL: cache hit.
	clock.Store(base.Add(30 * time.Second).UnixNano())
	if _, err := FetchConfiguration(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("after within-TTL call, requests = %d, want 1", got)
	}
	// Past TTL: re-fetch.
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	if _, err := FetchConfiguration(context.Background(), srv.URL, WithCacheTTL(time.Minute), WithInsecureAllowHTTP()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("after TTL expiry, requests = %d, want 2", got)
	}
}

// DISC-006: non-2xx responses surface a typed HTTP error with the status code.
func TestFetchConfiguration_HTTPError(t *testing.T) {
	freshCache(t)
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		globalCache.reset()
		srv, _ := newServer(t, status, []byte(`{}`))
		_, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
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

// DISC-007: a non-JSON body surfaces a parse error.
func TestFetchConfiguration_InvalidJSON(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, []byte("this is not json <html>"))
	_, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if !errors.Is(err, ErrParse) {
		t.Fatalf("err = %v, want ErrParse", err)
	}
	var pErr *ParseError
	if !errors.As(err, &pErr) {
		t.Fatalf("err = %T, want *ParseError", err)
	}
}

// DISC-008: a missing required field is reported by name.
func TestFetchConfiguration_MissingField(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "missing-jwks-uri.json"))
	_, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var mErr *MissingFieldsError
	if !errors.As(err, &mErr) {
		t.Fatalf("err = %v, want *MissingFieldsError", err)
	}
	if !contains(mErr.Fields, "jwks_uri") {
		t.Errorf("missing fields = %v, want to include jwks_uri", mErr.Fields)
	}
	if !errors.Is(err, ErrMissingFields) {
		t.Errorf("errors.Is(ErrMissingFields) = false")
	}
}

// DISC-008: multiple missing required fields are all reported.
func TestFetchConfiguration_MissingMultipleFields(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, fixture(t, "missing-multiple-fields.json"))
	_, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	var mErr *MissingFieldsError
	if !errors.As(err, &mErr) {
		t.Fatalf("err = %v, want *MissingFieldsError", err)
	}
	// missing-multiple-fields.json omits token_endpoint and
	// subject_types_supported (jwks_uri is present).
	for _, want := range []string{"token_endpoint", "subject_types_supported"} {
		if !contains(mErr.Fields, want) {
			t.Errorf("missing fields = %v, want to include %q", mErr.Fields, want)
		}
	}
}

// DISC-009: unknown extra fields are ignored, not rejected.
func TestFetchConfiguration_IgnoresUnknownFields(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validDocFor(srv.URL))
	})
	cfg, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if _, ok := cfg.Extra["x_custom_extension_field"]; !ok {
		t.Errorf("expected unknown field preserved in Extra, got %v", cfg.Extra)
	}
}

// DISC-010: http:// issuers are rejected by default and allowed only with
// WithInsecureAllowHTTP.
func TestFetchConfiguration_RequireHTTPS(t *testing.T) {
	freshCache(t)
	srv, hits := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write(validDocFor(srv.URL))
	})

	// Default (production) mode rejects http:// without a network request.
	_, err := FetchConfiguration(context.Background(), srv.URL)
	if !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("err = %v, want ErrHTTPSRequired", err)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("HTTPS check should short-circuit before any request, got %d", got)
	}

	// With the dev escape hatch the same URL succeeds.
	if _, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
		t.Errorf("with WithInsecureAllowHTTP: %v", err)
	}
}

// AC singleflight: concurrent callers collapse to a single HTTP request.
func TestFetchConfiguration_Singleflight(t *testing.T) {
	freshCache(t)
	var hits int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the request open so all goroutines pile up behind it
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP())
		}(i)
	}
	// Give goroutines time to register with singleflight before releasing.
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

// AC WithHTTPClient: the supplied client is used for the request.
func TestFetchConfiguration_WithHTTPClient(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validDocFor(srv.URL))
	})

	rt := &countingTransport{next: http.DefaultTransport}
	client := &http.Client{Transport: rt}
	if _, err := FetchConfiguration(context.Background(), srv.URL, WithHTTPClient(client), WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if atomic.LoadInt32(&rt.calls) != 1 {
		t.Errorf("custom transport calls = %d, want 1", rt.calls)
	}
}

// AC WithTimeout: a short deadline surfaces a context error.
func TestFetchConfiguration_WithTimeout(t *testing.T) {
	freshCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	_, err := FetchConfiguration(context.Background(), srv.URL, WithTimeout(20*time.Millisecond), WithInsecureAllowHTTP())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

// Trailing slashes on the issuer must not change the resolved endpoint or the
// issuer-match comparison.
func TestFetchConfiguration_TrailingSlash(t *testing.T) {
	freshCache(t)
	srv, _ := newServer(t, http.StatusOK, nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validDocFor(srv.URL))
	})
	if _, err := FetchConfiguration(context.Background(), srv.URL+"/", WithInsecureAllowHTTP()); err != nil {
		t.Errorf("trailing-slash issuer: %v", err)
	}
}

// Errors must not be cached: a failure followed by success must re-fetch.
func TestFetchConfiguration_ErrorsNotCached(t *testing.T) {
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
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	if _, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP()); err == nil {
		t.Fatal("expected error on first call")
	}
	fail.Store(false)
	if _, err := FetchConfiguration(context.Background(), srv.URL, WithInsecureAllowHTTP()); err != nil {
		t.Fatalf("second call after recovery: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("requests = %d, want 2 (error not cached)", got)
	}
}

// --- helpers ---

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// httpURL reconstructs the scheme://host base URL the client used to reach the
// handler, so generated documents can declare a matching issuer.
func httpURL(r *http.Request) string {
	return "http://" + r.Host
}

type countingTransport struct {
	next  http.RoundTripper
	calls int32
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.calls, 1)
	return t.next.RoundTrip(req)
}
