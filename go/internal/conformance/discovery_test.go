//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

// specSecond is the wall-clock time one vector second maps to: the Go cache
// has no injectable clock, so TTL vectors run scaled down in real time, with
// margins (30 vector seconds = 1.5s) wide enough to survive the race detector.
const specSecond = 50 * time.Millisecond

// fixtureHost is the placeholder host in fixtures and expected results; the
// fixture serves it rewritten to the vector's base URL.
const fixtureHost = "https://server.example.com"

// runDiscoveryVector is the discovery.json adapter: discovery.FetchConfiguration.
func runDiscoveryVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()
	discovery.ClearCache()
	t.Cleanup(discovery.ClearCache)

	var opts []discovery.Option
	if requireHTTPS, _ := v.Input["require_https"].(bool); !requireHTTPS {
		opts = append(opts, discovery.WithInsecureAllowHTTP())
	}
	if ttl, ok := v.Input["cache_ttl_seconds"].(float64); ok {
		opts = append(opts, discovery.WithCacheTTL(time.Duration(ttl)*specSecond))
	}
	offsets := []any{0.0}
	if at, ok := v.Input["calls_at_seconds"].([]any); ok {
		offsets = at
	}

	var (
		cfg *discovery.ProviderConfiguration
		err error
	)
	start := time.Now()
	for _, at := range offsets {
		time.Sleep(time.Until(start.Add(time.Duration(at.(float64)) * specSecond)))
		if cfg, err = discovery.FetchConfiguration(context.Background(), base, opts...); err != nil {
			break
		}
	}

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		assertDiscoveryResult(t, label, base, cfg, v.Expect.Result)
	case OutcomeReject:
		assertDiscoveryError(t, label, err, v.Expect)
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
}

func assertDiscoveryError(t *testing.T, label string, err error, want HTTPExpect) {
	t.Helper()
	var (
		httpErr    *discovery.HTTPError
		missingErr *discovery.MissingFieldsError
	)
	switch want.Error {
	case "issuer_mismatch":
		if !errors.Is(err, discovery.ErrIssuerMismatch) {
			t.Fatalf("%s: err = %v, want ErrIssuerMismatch", label, err)
		}
	case "http_status":
		if !errors.As(err, &httpErr) {
			t.Fatalf("%s: err = %v, want *HTTPError", label, err)
		}
		if httpErr.StatusCode != want.Status {
			t.Errorf("%s: status = %d, want %d", label, httpErr.StatusCode, want.Status)
		}
	case "parse":
		if !errors.Is(err, discovery.ErrParse) {
			t.Fatalf("%s: err = %v, want ErrParse", label, err)
		}
	case "missing_fields":
		if !errors.As(err, &missingErr) {
			t.Fatalf("%s: err = %v, want *MissingFieldsError", label, err)
		}
		if !slices.Equal(missingErr.Fields, want.Fields) {
			t.Errorf("%s: missing fields = %v, want %v", label, missingErr.Fields, want.Fields)
		}
	case "https_required":
		if !errors.Is(err, discovery.ErrHTTPSRequired) {
			t.Fatalf("%s: err = %v, want ErrHTTPSRequired", label, err)
		}
	default:
		t.Fatalf("%s: unknown expected error %q", label, want.Error)
	}
}

// assertDiscoveryResult compares each expected field with the configuration's
// JSON form, after pointing the fixture host at the vector's base URL.
func assertDiscoveryResult(t *testing.T, label, base string, cfg *discovery.ProviderConfiguration, want map[string]any) {
	t.Helper()
	gotJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("%s: marshal result: %v", label, err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("%s: marshal expected result: %v", label, err)
	}
	var got, exp map[string]any
	if err := json.Unmarshal(gotJSON, &got); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(wantJSON), fixtureHost, base)), &exp); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	for k, w := range exp {
		if !reflect.DeepEqual(got[k], w) {
			t.Errorf("%s: %s = %v, want %v", label, k, got[k], w)
		}
	}
}
