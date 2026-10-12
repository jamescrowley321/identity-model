package transport

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recordSleeps replaces the transport's sleep with one that records each delay
// and returns at once.
func recordSleeps(t *Transport) *[]time.Duration {
	var got []time.Duration
	t.sleep = func(ctx context.Context, d time.Duration) error {
		got = append(got, d)
		return ctx.Err()
	}
	return &got
}

func mustBuild(t *testing.T, s Settings) *Transport {
	t.Helper()
	tr, issues := s.Build()
	if len(issues) > 0 {
		t.Fatalf("Build: %v", issues)
	}
	return tr
}

func getReq(url string) func(context.Context) (*http.Request, error) {
	return func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	}
}

func TestDefaults(t *testing.T) {
	want := Settings{Timeout: 30 * time.Second, RetryMaxAttempts: 3, RetryBaseDelay: time.Second}
	if got := Defaults(); !reflect.DeepEqual(got, want) {
		t.Errorf("Defaults() = %+v, want %+v", got, want)
	}
}

func TestBuild_RejectsOutOfRange(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Settings)
		want   []Issue
	}{
		"zero timeout":     {func(s *Settings) { s.Timeout = 0 }, []Issue{{Setting: "WithTimeout", Rule: "must be > 0"}}},
		"negative timeout": {func(s *Settings) { s.Timeout = -time.Second }, []Issue{{Setting: "WithTimeout", Rule: "must be > 0"}}},
		"negative retries": {func(s *Settings) { s.RetryMaxAttempts = -1 }, []Issue{{Setting: "WithRetryMaxAttempts", Rule: "must be >= 0"}}},
		"negative delay":   {func(s *Settings) { s.RetryBaseDelay = -time.Nanosecond }, []Issue{{Setting: "WithRetryBaseDelay", Rule: "must be >= 0"}}},
		"missing bundle":   {func(s *Settings) { s.CABundle = "/nonexistent/ca.pem" }, []Issue{{Setting: "WithCABundle", Rule: "must be a readable PEM file with at least one certificate"}}},
		"every issue at once": {
			func(s *Settings) { s.Timeout = 0; s.RetryMaxAttempts = -1; s.RetryBaseDelay = -1 },
			[]Issue{
				{Setting: "WithTimeout", Rule: "must be > 0"},
				{Setting: "WithRetryMaxAttempts", Rule: "must be >= 0"},
				{Setting: "WithRetryBaseDelay", Rule: "must be >= 0"},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := Defaults()
			tc.mutate(&s)
			tr, issues := s.Build()
			if tr != nil {
				t.Errorf("Build returned a transport for invalid settings")
			}
			if !reflect.DeepEqual(issues, tc.want) {
				t.Errorf("issues = %+v, want %+v", issues, tc.want)
			}
		})
	}
}

func TestBuild_AcceptsRangeEdges(t *testing.T) {
	s := Settings{Timeout: time.Nanosecond, RetryMaxAttempts: 0, RetryBaseDelay: 0}
	if _, issues := s.Build(); len(issues) > 0 {
		t.Errorf("edges rejected: %v", issues)
	}
}

func TestConfigError_NamesSettingNotValue(t *testing.T) {
	err := NewConfigError("jwks", []Issue{{Setting: "WithTimeout", Rule: "must be > 0"}})
	if got, want := err.Error(), "jwks: invalid configuration: WithTimeout must be > 0"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("errors.Is(err, ErrInvalidConfig) = false")
	}
}

func TestDo_RetriesRetryableStatusesThenSucceeds(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) < 3 {
				w.WriteHeader(status)
				return
			}
			_, _ = io.WriteString(w, "ok")
		}))
		tr := mustBuild(t, Defaults())
		sleeps := recordSleeps(tr)

		resp, err := tr.Do(context.Background(), getReq(srv.URL))
		if err != nil {
			t.Fatalf("status %d: Do: %v", status, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		srv.Close()

		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Errorf("status %d: got %d %q, want 200 \"ok\"", status, resp.StatusCode, body)
		}
		if got := calls.Load(); got != 3 {
			t.Errorf("status %d: calls = %d, want 3", status, got)
		}
		if want := []time.Duration{time.Second, 2 * time.Second}; !reflect.DeepEqual(*sleeps, want) {
			t.Errorf("status %d: sleeps = %v, want %v", status, *sleeps, want)
		}
	}
}

func TestDo_ReturnsLastResponseWhenRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	tr := mustBuild(t, Defaults())
	sleeps := recordSleeps(tr)

	resp, err := tr.Do(context.Background(), getReq(srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	if got := calls.Load(); got != 4 {
		t.Errorf("calls = %d, want 4 (1 + 3 retries)", got)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; !reflect.DeepEqual(*sleeps, want) {
		t.Errorf("sleeps = %v, want %v", *sleeps, want)
	}
}

func TestDo_DoesNotRetryOtherStatuses(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
		}))
		tr := mustBuild(t, Defaults())
		sleeps := recordSleeps(tr)
		resp, err := tr.Do(context.Background(), getReq(srv.URL))
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		srv.Close()
		if got := calls.Load(); got != 1 {
			t.Errorf("status %d: calls = %d, want 1", status, got)
		}
		if len(*sleeps) != 0 {
			t.Errorf("status %d: slept %v", status, *sleeps)
		}
	}
}

func TestDo_ZeroAttemptsDisablesRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	s := Defaults()
	s.RetryMaxAttempts = 0
	tr := mustBuild(t, s)
	resp, err := tr.Do(context.Background(), getReq(srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestDo_RetriesTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused from now on

	tr := mustBuild(t, Defaults())
	sleeps := recordSleeps(tr)
	var builds int
	_, err := tr.Do(context.Background(), func(ctx context.Context) (*http.Request, error) {
		builds++
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	})
	if err == nil {
		t.Fatal("Do: want a transport error")
	}
	if builds != 4 {
		t.Errorf("attempts = %d, want 4", builds)
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; !reflect.DeepEqual(*sleeps, want) {
		t.Errorf("sleeps = %v, want %v", *sleeps, want)
	}
}

func TestDo_DoesNotRetryPermanentErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	refusal := errors.New("redirect refused")
	s := Defaults()
	s.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return Permanent(refusal)
	}}
	tr := mustBuild(t, s)
	sleeps := recordSleeps(tr)
	_, err := tr.Do(context.Background(), getReq(srv.URL))
	if !errors.Is(err, refusal) {
		t.Fatalf("err = %v, want the refusal", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("requests = %d, want 1 (a permanent error is not retried)", got)
	}
	if len(*sleeps) != 0 {
		t.Errorf("slept %v", *sleeps)
	}
}

func TestDo_DoesNotRetryAfterCallerCancels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tr := mustBuild(t, Defaults())
	sleeps := recordSleeps(tr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tr.Do(ctx, getReq(srv.URL))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("slept %v after cancellation", *sleeps)
	}
}

func TestDo_RebuildsRequestBodyEachAttempt(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if len(bodies) < 2 {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	tr := mustBuild(t, Defaults())
	recordSleeps(tr)
	resp, err := tr.Do(context.Background(), func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader("grant_type=x"))
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if want := []string{"grant_type=x", "grant_type=x"}; !reflect.DeepEqual(bodies, want) {
		t.Errorf("bodies = %q, want %q", bodies, want)
	}
}

func TestDo_TimeoutAppliesPerAttemptAndCoversBodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	s := Defaults()
	s.Timeout = time.Minute
	tr := mustBuild(t, s)
	resp, err := tr.Do(context.Background(), getReq(srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// The attempt's context must stay live until the body is read.
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("read body = %q, %v", body, err)
	}
	_ = resp.Body.Close()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	s.Timeout = 50 * time.Millisecond
	s.RetryMaxAttempts = 0
	tr = mustBuild(t, s)
	if _, err := tr.Do(context.Background(), getReq(slow.URL)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestRetryDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		base       time.Duration
		attempt    int
		retryAfter string
		want       time.Duration
	}{
		{"exponential", time.Second, 2, "", 4 * time.Second},
		{"zero base", 0, 2, "", 0},
		{"backoff capped", time.Second, 10, "", MaxRetryDelay},
		{"retry-after larger wins", time.Second, 0, "7", 7 * time.Second},
		{"backoff larger wins", time.Second, 3, "2", 8 * time.Second},
		{"retry-after capped", time.Second, 0, "100000", MaxRetryDelay},
		{"retry-after http-date", time.Second, 0, now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second},
		{"retry-after past date", time.Second, 0, now.Add(-time.Hour).Format(http.TimeFormat), time.Second},
		{"retry-after garbage ignored", time.Second, 1, "soon", 2 * time.Second},
		{"retry-after negative ignored", time.Second, 1, "-5", 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryDelay(tc.base, tc.attempt, tc.retryAfter, now); got != tc.want {
				t.Errorf("retryDelay = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveTTL(t *testing.T) {
	def := 3 * time.Hour
	cases := map[string]time.Duration{
		"":                             def,
		"public":                       def,
		"max-age=300":                  300 * time.Second,
		"public, MAX-AGE=600":          600 * time.Second,
		"max-age=0":                    MinCacheTTL,
		"max-age=59":                   MinCacheTTL,
		"max-age=86401":                MaxCacheTTL,
		"max-age=99999999999999999999": MaxCacheTTL,
		"no-store, max-age=120":        120 * time.Second,
	}
	for header, want := range cases {
		if got := ResolveTTL(header, def); got != want {
			t.Errorf("ResolveTTL(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestUncacheable(t *testing.T) {
	cases := map[string]bool{
		"":                  false,
		"max-age=300":       false,
		"no-store":          true,
		"No-Cache":          true,
		"public, no-cache":  true,
		"no-transform":      false,
		"x-no-storefront=1": false,
	}
	for header, want := range cases {
		if got := Uncacheable(header); got != want {
			t.Errorf("Uncacheable(%q) = %v, want %v", header, got, want)
		}
	}
}

// writeCA writes srv's certificate to a PEM file and returns its path.
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCABundle_TrustsOnlyTheBundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	s := Defaults()
	s.RetryMaxAttempts = 0
	tr := mustBuild(t, s)
	if _, err := tr.Do(context.Background(), getReq(srv.URL)); err == nil {
		t.Fatal("default bundle trusted the test server's self-signed certificate")
	}

	s.CABundle = writeCA(t, srv)
	tr = mustBuild(t, s)
	resp, err := tr.Do(context.Background(), getReq(srv.URL))
	if err != nil {
		t.Fatalf("Do with CA bundle: %v", err)
	}
	_ = resp.Body.Close()

	tlsCfg := tr.client.Transport.(*http.Transport).TLSClientConfig
	if tlsCfg.MinVersion < tls.VersionTLS12 || tlsCfg.InsecureSkipVerify {
		t.Errorf("TLS config = %+v, want verification on and TLS 1.2+", tlsCfg)
	}
}

func TestCABundle_RejectsFileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Defaults()
	s.CABundle = path
	_, issues := s.Build()
	want := []Issue{{Setting: "WithCABundle", Rule: "must be a readable PEM file with at least one certificate"}}
	if !reflect.DeepEqual(issues, want) {
		t.Errorf("issues = %+v, want %+v", issues, want)
	}
}

func TestCABundle_CannotCombineWithHTTPClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	s := Defaults()
	s.CABundle = writeCA(t, srv)
	s.HTTPClient = &http.Client{}
	_, issues := s.Build()
	want := []Issue{{Setting: "WithCABundle", Rule: "cannot be combined with WithHTTPClient"}}
	if !reflect.DeepEqual(issues, want) {
		t.Errorf("issues = %+v, want %+v", issues, want)
	}
}

func TestBuild_UsesSuppliedClientOrDefault(t *testing.T) {
	tr := mustBuild(t, Defaults())
	if tr.Client() != http.DefaultClient {
		t.Errorf("default settings did not use http.DefaultClient")
	}
	c := &http.Client{}
	s := Defaults()
	s.HTTPClient = c
	if got := mustBuild(t, s).Client(); got != c {
		t.Errorf("Client() = %p, want the supplied %p", got, c)
	}
}

func TestWithClient_LeavesOriginalUntouched(t *testing.T) {
	tr := mustBuild(t, Defaults())
	c := &http.Client{}
	other := tr.WithClient(c)
	if other.Client() != c || tr.Client() != http.DefaultClient {
		t.Errorf("WithClient changed the original or ignored the new client")
	}
}
