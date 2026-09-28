package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fixtureHost is the placeholder base URL in HTTP fixtures; the mock server
// replaces it with its own URL so discovery documents point back at it.
const fixtureHost = "https://server.example.com"

// HTTPCapability is a spec/vectors/<capability>.json file whose vectors drive
// an HTTP client against canned responses.
type HTTPCapability struct {
	Capability string     `json:"capability"`
	Spec       string     `json:"spec"`
	SpecURL    string     `json:"spec_url"`
	Notes      string     `json:"notes,omitempty"`
	Tests      []HTTPCase `json:"tests"`
}

// HTTPCase is one conformance test id with its HTTP vectors.
type HTTPCase struct {
	ID         string       `json:"id"`
	Title      string       `json:"title"`
	Given      string       `json:"given"`
	When       string       `json:"when"`
	Then       string       `json:"then"`
	References []string     `json:"references,omitempty"`
	Vectors    []HTTPVector `json:"vectors"`
}

// HTTPVector is one executable HTTP scenario.
type HTTPVector struct {
	Name  string                  `json:"name"`
	Input map[string]any          `json:"input"`
	HTTP  map[string]HTTPResponse `json:"http"`
	// HTTPSequence serves the n-th response to the n-th request on a path;
	// the last one repeats.
	HTTPSequence  map[string][]HTTPResponse `json:"http_sequence,omitempty"`
	ExpectRequest *ExpectRequest            `json:"expect_request,omitempty"`
	ExpectCalls   map[string]int            `json:"expect_calls,omitempty"`
	Expect        HTTPExpect                `json:"expect"`
}

// HTTPResponse is a canned response for one request path.
type HTTPResponse struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyFixture string            `json:"body_fixture,omitempty"`
}

// ExpectRequest is the request the client under test must send.
type ExpectRequest struct {
	Path    string            `json:"path"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
}

// HTTPExpect is the asserted outcome of the call.
type HTTPExpect struct {
	Outcome         string         `json:"outcome"`
	Error           string         `json:"error,omitempty"`
	Status          int            `json:"status,omitempty"`
	WWWAuthenticate string         `json:"www_authenticate,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
	CustomClaims    map[string]any `json:"custom_claims,omitempty"`
	// Keys is the expected key set, each key as its non-empty JWK members.
	Keys []map[string]string `json:"keys,omitempty"`
}

// LoadHTTPCapability reads an HTTP vector file, rejecting unknown fields.
func LoadHTTPCapability(t *testing.T, name string) *HTTPCapability {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specVectorsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c HTTPCapability
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if len(c.Tests) == 0 {
		t.Fatalf("%s defines no tests", name)
	}
	return &c
}

// recordedRequest is what the mock server received on one path.
type recordedRequest struct {
	method string
	header http.Header
	form   url.Values
}

// mockServer serves a vector's canned responses and records each request.
type mockServer struct {
	*httptest.Server
	mu    sync.Mutex
	seen  map[string]recordedRequest
	calls map[string]int
}

// newMockServer starts a server that answers each path in v.HTTP (or
// v.HTTPSequence) with its canned response and 404s anything else.
func newMockServer(t *testing.T, v HTTPVector) *mockServer {
	t.Helper()
	m := &mockServer{seen: map[string]recordedRequest{}, calls: map[string]int{}}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse request form: %v", err)
		}
		m.mu.Lock()
		m.seen[r.URL.Path] = recordedRequest{method: r.Method, header: r.Header.Clone(), form: form}
		n := m.calls[r.URL.Path]
		m.calls[r.URL.Path]++
		m.mu.Unlock()

		resp, ok := v.HTTP[r.URL.Path]
		if seq := v.HTTPSequence[r.URL.Path]; len(seq) > 0 {
			resp, ok = seq[min(n, len(seq)-1)], true
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		for k, val := range resp.Headers {
			w.Header().Set(k, val)
		}
		var payload []byte
		if resp.BodyFixture != "" {
			raw, err := os.ReadFile(filepath.Join(fixtureRoot, resp.BodyFixture))
			if err != nil {
				t.Errorf("read fixture %s: %v", resp.BodyFixture, err)
			}
			payload = []byte(strings.ReplaceAll(string(raw), fixtureHost, m.URL))
			if len(payload) > 0 && w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "application/json")
			}
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(m.Close)
	return m
}

// assertRequest checks the recorded request against the vector's expectation.
func (m *mockServer) assertRequest(t *testing.T, label string, want *ExpectRequest) {
	t.Helper()
	if want == nil {
		return
	}
	m.mu.Lock()
	got, ok := m.seen[want.Path]
	m.mu.Unlock()
	if !ok {
		t.Fatalf("%s: no request to %s", label, want.Path)
	}
	if got.method != want.Method {
		t.Errorf("%s: method = %s, want %s", label, got.method, want.Method)
	}
	for k, v := range want.Headers {
		// Content-Type may carry parameters (charset); compare the media type.
		have := got.header.Get(k)
		if strings.EqualFold(k, "content-type") {
			have = strings.TrimSpace(strings.Split(have, ";")[0])
		}
		if have != v {
			t.Errorf("%s: header %s = %q, want %q", label, k, have, v)
		}
	}
	for k, v := range want.Form {
		if have := got.form.Get(k); have != v {
			t.Errorf("%s: form %s = %q, want %q", label, k, have, v)
		}
	}
}

// assertCalls checks the number of requests received on each path.
func (m *mockServer) assertCalls(t *testing.T, label string, want map[string]int) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for p, n := range want {
		if m.calls[p] != n {
			t.Errorf("%s: %d requests to %s, want %d", label, m.calls[p], p, n)
		}
	}
}

// inputString returns a string input field, or "" when absent.
func inputString(v HTTPVector, key string) string {
	s, _ := v.Input[key].(string)
	return s
}

// vectorLabel names a vector in failure messages.
func vectorLabel(id string, idx int, v HTTPVector) string {
	if v.Name != "" {
		return fmt.Sprintf("%s (%s)", id, v.Name)
	}
	return fmt.Sprintf("%s[%d]", id, idx)
}
