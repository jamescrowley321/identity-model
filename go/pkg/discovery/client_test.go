package discovery

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/transport"
)

func TestNewClient_Defaults(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	want := &config{
		transport:  transport.Settings{Timeout: 30 * time.Second, RetryMaxAttempts: 3, RetryBaseDelay: time.Second},
		cacheTTL:   time.Hour,
		maxEntries: 64,
	}
	if !reflect.DeepEqual(c.cfg, want) {
		t.Errorf("default config = %+v, want %+v", c.cfg, want)
	}
	if !reflect.DeepEqual(defaultClient.cfg, want) {
		t.Errorf("package default client config = %+v, want %+v", defaultClient.cfg, want)
	}
}

func TestNewClient_RejectsInvalidOptions(t *testing.T) {
	cases := map[string]struct {
		opts []Option
		want []ConfigIssue
	}{
		"cache TTL below 60s":  {[]Option{WithCacheTTL(59 * time.Second)}, []ConfigIssue{{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"}}},
		"cache TTL above 24h":  {[]Option{WithCacheTTL(24*time.Hour + time.Nanosecond)}, []ConfigIssue{{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"}}},
		"zero cache TTL":       {[]Option{WithCacheTTL(0)}, []ConfigIssue{{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"}}},
		"zero max entries":     {[]Option{WithMaxCacheEntries(0)}, []ConfigIssue{{Setting: "WithMaxCacheEntries", Rule: "must be >= 1"}}},
		"negative max entries": {[]Option{WithMaxCacheEntries(-1)}, []ConfigIssue{{Setting: "WithMaxCacheEntries", Rule: "must be >= 1"}}},
		"zero timeout":         {[]Option{WithTimeout(0)}, []ConfigIssue{{Setting: "WithTimeout", Rule: "must be > 0"}}},
		"negative retries":     {[]Option{WithRetryMaxAttempts(-1)}, []ConfigIssue{{Setting: "WithRetryMaxAttempts", Rule: "must be >= 0"}}},
		"negative delay":       {[]Option{WithRetryBaseDelay(-time.Second)}, []ConfigIssue{{Setting: "WithRetryBaseDelay", Rule: "must be >= 0"}}},
		"unreadable CA bundle": {[]Option{WithCABundle(filepath.Join(t.TempDir(), "missing.pem"))}, []ConfigIssue{{Setting: "WithCABundle", Rule: "must be a readable PEM file with at least one certificate"}}},
		"every issue at once": {
			[]Option{WithTimeout(0), WithCacheTTL(0), WithMaxCacheEntries(0)},
			[]ConfigIssue{
				{Setting: "WithTimeout", Rule: "must be > 0"},
				{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"},
				{Setting: "WithMaxCacheEntries", Rule: "must be >= 1"},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(tc.opts...)
			if c != nil {
				t.Error("NewClient returned a client for invalid options")
			}
			var cErr *ConfigError
			if !errors.As(err, &cErr) {
				t.Fatalf("err = %v, want *ConfigError", err)
			}
			if !reflect.DeepEqual(cErr.Issues, tc.want) {
				t.Errorf("issues = %+v, want %+v", cErr.Issues, tc.want)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Error("errors.Is(err, ErrInvalidConfig) = false")
			}
		})
	}
}

func TestNewClient_AcceptsRangeEdges(t *testing.T) {
	for name, opts := range map[string][]Option{
		"low edges":  {WithCacheTTL(60 * time.Second), WithMaxCacheEntries(1), WithRetryMaxAttempts(0), WithRetryBaseDelay(0), WithTimeout(time.Nanosecond)},
		"high edges": {WithCacheTTL(86400 * time.Second)},
	} {
		if _, err := NewClient(opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// cacheControlServer serves a valid document with the given Cache-Control
// header and counts requests.
func cacheControlServer(t *testing.T, cacheControl string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// Cache rules (spec/config.md): max-age sets the lifetime, clamped to 60 s –
// 24 h; no-store / no-cache mean not cached; no max-age falls back to
// WithCacheTTL.
func TestFetchConfiguration_CacheControl(t *testing.T) {
	cases := []struct {
		header   string
		lifetime time.Duration // 0: never cached
	}{
		{"", time.Hour},
		{"public", time.Hour},
		{"max-age=120", 120 * time.Second},
		{"max-age=5", 60 * time.Second},
		{"max-age=999999", 24 * time.Hour},
		{"no-store", 0},
		{"no-cache", 0},
		{"no-store, max-age=600", 0},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			srv, hits := cacheControlServer(t, tc.header)
			client := testClient(t, WithInsecureAllowHTTP())
			base := time.Unix(1_700_000_000, 0)
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			client.cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
			fetch := func() {
				t.Helper()
				if _, err := client.FetchConfiguration(context.Background(), srv.URL); err != nil {
					t.Fatal(err)
				}
			}

			fetch()
			fetch()
			if tc.lifetime == 0 {
				if got := hits.Load(); got != 2 {
					t.Errorf("requests = %d, want 2 (not cached)", got)
				}
				return
			}
			clock.Store(base.Add(tc.lifetime - time.Nanosecond).UnixNano())
			fetch()
			if got := hits.Load(); got != 1 {
				t.Fatalf("requests before expiry = %d, want 1", got)
			}
			clock.Store(base.Add(tc.lifetime).UnixNano())
			fetch()
			if got := hits.Load(); got != 2 {
				t.Errorf("requests at expiry = %d, want 2", got)
			}
		})
	}
}

func TestFetchConfiguration_RetriesServerErrors(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(validDocFor(httpURL(r)))
	}))
	t.Cleanup(srv.Close)

	if _, err := testClient(t, WithInsecureAllowHTTP()).FetchConfiguration(context.Background(), srv.URL); err != nil {
		t.Fatalf("FetchConfiguration: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (one retry)", got)
	}

	hits.Store(0)
	_, err := testClient(t, WithInsecureAllowHTTP(), WithRetryMaxAttempts(0)).FetchConfiguration(context.Background(), srv.URL)
	var hErr *HTTPError
	if !errors.As(err, &hErr) || hErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("with retries off: err = %v, want HTTPError 503", err)
	}
}

func TestClients_DoNotShareCaches(t *testing.T) {
	srv, hits := cacheControlServer(t, "")
	a, b := testClient(t, WithInsecureAllowHTTP()), testClient(t, WithInsecureAllowHTTP())
	for _, c := range []*Client{a, b, a, b} {
		if _, err := c.FetchConfiguration(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (one per client)", got)
	}
}

func TestFetchConfiguration_WithCABundle(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(validDocFor(srv.URL))
	}))
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := testClient(t, WithRetryMaxAttempts(0)).FetchConfiguration(context.Background(), srv.URL); err == nil {
		t.Fatal("system roots trusted the self-signed test server")
	}
	if _, err := testClient(t, WithCABundle(path)).FetchConfiguration(context.Background(), srv.URL); err != nil {
		t.Errorf("with CA bundle: %v", err)
	}
}
