package jwks

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
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
		transport:       transport.Settings{Timeout: 30 * time.Second, RetryMaxAttempts: 3, RetryBaseDelay: time.Second},
		cacheTTL:        24 * time.Hour,
		maxEntries:      64,
		maxSize:         524288,
		maxKeys:         100,
		refreshCooldown: 5 * time.Second,
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
		"zero max size":          {[]Option{WithMaxSize(0)}, []ConfigIssue{{Setting: "WithMaxSize", Rule: "must be >= 1"}}},
		"zero max keys":          {[]Option{WithMaxKeys(0)}, []ConfigIssue{{Setting: "WithMaxKeys", Rule: "must be >= 1"}}},
		"cache TTL below 60s":    {[]Option{WithCacheTTL(59 * time.Second)}, []ConfigIssue{{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"}}},
		"cache TTL above 24h":    {[]Option{WithCacheTTL(24*time.Hour + time.Nanosecond)}, []ConfigIssue{{Setting: "WithCacheTTL", Rule: "must be 60s to 86400s"}}},
		"negative cooldown":      {[]Option{WithRefreshCooldown(-time.Nanosecond)}, []ConfigIssue{{Setting: "WithRefreshCooldown", Rule: "must be 0s to 3600s"}}},
		"cooldown above an hour": {[]Option{WithRefreshCooldown(time.Hour + time.Nanosecond)}, []ConfigIssue{{Setting: "WithRefreshCooldown", Rule: "must be 0s to 3600s"}}},
		"zero max entries":       {[]Option{WithMaxCacheEntries(0)}, []ConfigIssue{{Setting: "WithMaxCacheEntries", Rule: "must be >= 1"}}},
		"zero timeout":           {[]Option{WithTimeout(0)}, []ConfigIssue{{Setting: "WithTimeout", Rule: "must be > 0"}}},
		"negative retries":       {[]Option{WithRetryMaxAttempts(-1)}, []ConfigIssue{{Setting: "WithRetryMaxAttempts", Rule: "must be >= 0"}}},
		"negative delay":         {[]Option{WithRetryBaseDelay(-time.Second)}, []ConfigIssue{{Setting: "WithRetryBaseDelay", Rule: "must be >= 0"}}},
		"unreadable CA bundle":   {[]Option{WithCABundle(filepath.Join(t.TempDir(), "missing.pem"))}, []ConfigIssue{{Setting: "WithCABundle", Rule: "must be a readable PEM file with at least one certificate"}}},
		"every issue at once": {
			[]Option{WithMaxCacheEntries(0), WithMaxKeys(0), WithTimeout(0)},
			[]ConfigIssue{
				{Setting: "WithTimeout", Rule: "must be > 0"},
				{Setting: "WithMaxKeys", Rule: "must be >= 1"},
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
		"low edges":  {WithMaxSize(1), WithMaxKeys(1), WithCacheTTL(60 * time.Second), WithRefreshCooldown(0), WithMaxCacheEntries(1), WithRetryMaxAttempts(0), WithRetryBaseDelay(0)},
		"high edges": {WithCacheTTL(86400 * time.Second), WithRefreshCooldown(3600 * time.Second)},
	} {
		if _, err := NewClient(opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Cache rules (spec/config.md): max-age sets the lifetime, clamped to 60 s –
// 24 h; no-store and no-cache are ignored for JWKS (#396); no max-age falls
// back to WithCacheTTL.
func TestFetchKeySet_CacheControl(t *testing.T) {
	cases := []struct {
		header   string
		lifetime time.Duration
	}{
		{"", 24 * time.Hour},
		{"max-age=120", 120 * time.Second},
		{"max-age=5", 60 * time.Second},
		{"max-age=999999", 24 * time.Hour},
		{"no-store", 24 * time.Hour},
		{"no-cache, no-store", 24 * time.Hour},
		{"no-store, max-age=300", 300 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if tc.header != "" {
					w.Header().Set("Cache-Control", tc.header)
				}
				_, _ = w.Write(keySetJSON(rsaKeyJSON("k1")))
			}))
			t.Cleanup(srv.Close)
			client := testClient(t, WithInsecureAllowHTTP())
			base := time.Unix(1_700_000_000, 0)
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			client.cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
			fetch := func() {
				t.Helper()
				if _, err := client.FetchKeySet(context.Background(), srv.URL); err != nil {
					t.Fatal(err)
				}
			}

			fetch()
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

func TestFetchKeySet_MaxSize(t *testing.T) {
	body := keySetJSON(rsaKeyJSON("k1"))
	srv, _ := newServer(t, http.StatusOK, body)

	if _, err := testClient(t, WithInsecureAllowHTTP(), WithMaxSize(len(body))).FetchKeySet(context.Background(), srv.URL); err != nil {
		t.Errorf("body of exactly WithMaxSize bytes: %v", err)
	}
	_, err := testClient(t, WithInsecureAllowHTTP(), WithMaxSize(len(body)-1)).FetchKeySet(context.Background(), srv.URL)
	if !errors.Is(err, ErrParse) || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("body one byte over WithMaxSize: err = %v, want a size ParseError", err)
	}
}

func TestFetchKeySet_DefaultMaxSize(t *testing.T) {
	pad := strings.Repeat("x", DefaultMaxSize)
	srv, _ := newServer(t, http.StatusOK, keySetJSON(`{"kty":"RSA","kid":"k1","n":"AQAB","e":"AQAB","pad":"`+pad+`"}`))
	_, err := testClient(t, WithInsecureAllowHTTP()).FetchKeySet(context.Background(), srv.URL)
	if !errors.Is(err, ErrParse) || !strings.Contains(err.Error(), "exceeds 524288 bytes") {
		t.Errorf("err = %v, want a ParseError naming the 524288-byte limit", err)
	}
}

func TestFetchKeySet_MaxKeys(t *testing.T) {
	keys := func(n int) []byte {
		members := make([]string, n)
		for i := range members {
			members[i] = rsaKeyJSON("k" + strings.Repeat("i", i+1))
		}
		return keySetJSON(members...)
	}
	cases := []struct {
		name    string
		n       int
		opts    []Option
		wantErr bool
	}{
		{"default limit", DefaultMaxKeys, nil, false},
		{"over default limit", DefaultMaxKeys + 1, nil, true},
		{"at configured limit", 3, []Option{WithMaxKeys(3)}, false},
		{"over configured limit", 4, []Option{WithMaxKeys(3)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newServer(t, http.StatusOK, keys(tc.n))
			set, err := testClient(t, append([]Option{WithInsecureAllowHTTP()}, tc.opts...)...).FetchKeySet(context.Background(), srv.URL)
			if tc.wantErr {
				if !errors.Is(err, ErrParse) || !strings.Contains(err.Error(), "exceeds limit") {
					t.Errorf("err = %v, want a key-count ParseError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchKeySet: %v", err)
			}
			if len(set.Keys) != tc.n {
				t.Errorf("keys = %d, want %d", len(set.Keys), tc.n)
			}
		})
	}
}

func TestFetchKeySet_RetriesServerErrors(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write(keySetJSON(rsaKeyJSON("k1")))
	}))
	t.Cleanup(srv.Close)
	if _, err := testClient(t, WithInsecureAllowHTTP()).FetchKeySet(context.Background(), srv.URL); err != nil {
		t.Fatalf("FetchKeySet: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("requests = %d, want 2 (one retry)", got)
	}
}

func TestClients_DoNotShareCachesOrCooldowns(t *testing.T) {
	srv, hits := newServer(t, http.StatusOK, keySetJSON(rsaKeyJSON("k1")))
	a := testClient(t, WithInsecureAllowHTTP(), WithRefreshCooldown(time.Hour))
	b := testClient(t, WithInsecureAllowHTTP(), WithRefreshCooldown(time.Hour))
	setA, err := a.FetchKeySet(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	setB, err := b.FetchKeySet(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("requests = %d, want 2 (one per client)", got)
	}
	// A's kid-miss refresh starts A's cooldown only; B may still refresh.
	_, _ = setA.ResolveKeyWithRefresh(context.Background(), "ghost")
	_, _ = setA.ResolveKeyWithRefresh(context.Background(), "ghost")
	_, _ = setB.ResolveKeyWithRefresh(context.Background(), "ghost")
	if got := atomic.LoadInt32(hits); got != 4 {
		t.Errorf("requests = %d, want 4 (one refresh per client)", got)
	}
}

// The largest WithMaxSize must not overflow the one-byte-over read limit.
func TestFetchKeySet_MaxSizeAtMaxInt(t *testing.T) {
	srv, _ := newServer(t, http.StatusOK, keySetJSON(rsaKeyJSON("k1")))
	if _, err := testClient(t, WithInsecureAllowHTTP(), WithMaxSize(math.MaxInt)).FetchKeySet(context.Background(), srv.URL); err != nil {
		t.Errorf("WithMaxSize(math.MaxInt): %v", err)
	}
}

// A max-age in a later Cache-Control field line counts (RFC 9110 §5.3).
func TestFetchKeySet_CacheControlSpansFieldLines(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Add("Cache-Control", "public")
		w.Header().Add("Cache-Control", "max-age=300")
		_, _ = w.Write(keySetJSON(rsaKeyJSON("k1")))
	}))
	t.Cleanup(srv.Close)
	client := testClient(t, WithInsecureAllowHTTP())
	base := time.Unix(1_700_000_000, 0)
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	client.cache.now = func() time.Time { return time.Unix(0, clock.Load()) }

	if _, err := client.FetchKeySet(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(300 * time.Second).UnixNano())
	if _, err := client.FetchKeySet(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("requests after 300s = %d, want 2 (max-age=300 from the second field line)", got)
	}
}
