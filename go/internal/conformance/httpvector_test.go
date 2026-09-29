//go:build integration

package conformance

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/integrationtest"
)

// vectorOP is the node-oidc fixture that serves the canned HTTP vectors
// (infra/node-oidc-provider/vectors.js). It is the vector server whatever the
// integration profile, since make test-integration-go also runs IdentityServer.
const vectorOP = "http://localhost:9010"

// HTTPVector is one executable HTTP scenario. The fixture serves http and
// http_sequence and checks expect_request and expect_calls; they are decoded
// here only so an unknown field fails loading. Op "live" sends the call to the
// real node-oidc OP instead, and such a vector carries none of those four.
type HTTPVector struct {
	Name          string                    `json:"name"`
	Op            string                    `json:"op,omitempty"`
	Input         map[string]any            `json:"input"`
	HTTP          map[string]HTTPResponse   `json:"http"`
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
	// Result is expected fields of an accepted result, as JSON values.
	Result map[string]any `json:"result,omitempty"`
	// Fields lists the fields a missing_fields reject must name.
	Fields []string `json:"fields,omitempty"`
}

// httpAdapter calls the library for one vector against base (the vector's
// URL on the fixture) and checks the result against v.Expect.
type httpAdapter func(t *testing.T, label, base string, v HTTPVector)

// httpAdapters is keyed by vector file name (spec/vectors/<name>.json).
var httpAdapters = map[string]httpAdapter{
	"discovery":     runDiscoveryVector,
	"introspection": runIntrospectionVector,
	"jwks":          runJWKSVector,
	"revocation":    runRevocationVector,
	"userinfo":      runUserInfoVector,
}

// TestHTTPVectors runs every HTTP vector in spec/vectors against the node-oidc
// fixture. A file with HTTP vectors but no adapter fails, as does a case in an
// adapted file that has no vectors.
func TestHTTPVectors(t *testing.T) {
	probe := &http.Client{Timeout: 5 * time.Second}
	resp, err := probe.Get(vectorOP + "/.well-known/openid-configuration")
	if err != nil {
		integrationtest.FailUnreachable(t, "node-oidc fixture not reachable at %s (run `make infra-up`): %v", vectorOP, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node-oidc fixture at %s: discovery answered %d", vectorOP, resp.StatusCode)
	}

	run := randomToken(t)
	files, err := filepath.Glob(filepath.Join(specVectorsDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vector files in %s: %v", specVectorsDir, err)
	}
	for _, file := range files {
		capability := strings.TrimSuffix(filepath.Base(file), ".json")
		adapter := httpAdapters[capability]
		for _, tc := range loadHTTPCases(t, file) {
			if adapter != nil && tc.total == 0 {
				t.Errorf("%s: case has no vectors", tc.id)
			}
			if adapter != nil {
				for _, i := range tc.dropped {
					t.Errorf("%s[%d]: neither an HTTP nor a pure-logic vector", tc.id, i)
				}
			}
			for _, iv := range tc.vectors {
				i, v := iv.idx, iv.v
				label := vectorLabel(tc.id, i, v)
				if adapter == nil {
					t.Errorf("%s: %s.json has HTTP vectors but no adapter", label, capability)
					continue
				}
				// The fixture and the other runners index the case's full
				// vector list, so an unnamed vector keeps its original index.
				key := v.Name
				if key == "" {
					key = fmt.Sprint(i)
				}
				t.Run(tc.id+"/"+key, func(t *testing.T) {
					if v.Op == "live" {
						adapter(t, label, vectorOP, v)
						return
					}
					base := fmt.Sprintf("%s/v/%s/%s/%s/%s", vectorOP, run, capability, tc.id, key)
					defer checkRequests(t, label, base)
					adapter(t, label, base, v)
				})
			}
		}
	}
}

// httpCase is one case id with its HTTP vectors. total counts every vector in
// the case; dropped lists the indexes of vectors that are neither HTTP nor pure
// logic (input.operation).
type httpCase struct {
	id      string
	total   int
	vectors []indexedVector
	dropped []int
}

// indexedVector is an HTTP vector with its index in the case's vector list.
type indexedVector struct {
	idx int
	v   HTTPVector
}

// loadHTTPCases returns every case in file with its HTTP vectors (those with
// op, http or http_sequence), decoding each strictly. Other vectors are
// skipped.
func loadHTTPCases(t *testing.T, file string) []httpCase {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var raw struct {
		Tests []struct {
			ID      string                       `json:"id"`
			Vectors []map[string]json.RawMessage `json:"vectors"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("decode %s: %v", file, err)
	}
	if len(raw.Tests) == 0 {
		t.Fatalf("%s defines no tests", filepath.Base(file))
	}
	cases := make([]httpCase, 0, len(raw.Tests))
	for _, tc := range raw.Tests {
		c := httpCase{id: tc.ID, total: len(tc.Vectors)}
		for idx, fields := range tc.Vectors {
			_, h := fields["http"]
			_, hs := fields["http_sequence"]
			_, op := fields["op"]
			if !h && !hs && !op {
				var input map[string]json.RawMessage
				_ = json.Unmarshal(fields["input"], &input)
				if _, logic := input["operation"]; !logic {
					c.dropped = append(c.dropped, idx)
				}
				continue
			}
			vb, _ := json.Marshal(fields)
			dec := json.NewDecoder(bytes.NewReader(vb))
			dec.DisallowUnknownFields()
			var v HTTPVector
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s %s: decode vector: %v", filepath.Base(file), tc.ID, err)
			}
			if op && v.Op != "live" {
				t.Fatalf("%s %s: unknown op %q", filepath.Base(file), tc.ID, v.Op)
			}
			if op {
				for _, k := range []string{"http", "http_sequence", "expect_request", "expect_calls"} {
					if _, ok := fields[k]; ok {
						t.Fatalf("%s %s: a live vector carries %s", filepath.Base(file), tc.ID, k)
					}
				}
			}
			c.vectors = append(c.vectors, indexedVector{idx: idx, v: v})
		}
		cases = append(cases, c)
	}
	return cases
}

// checkRequests fails t with each difference the fixture found between the
// requests it received for base and the vector's expect_request/expect_calls.
func checkRequests(t *testing.T, label, base string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/_check")
	if err != nil {
		t.Errorf("%s: _check: %v", label, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	var got struct {
		OK    bool     `json:"ok"`
		Diffs []string `json:"diffs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Errorf("%s: decode _check: %v", label, err)
		return
	}
	for _, d := range got.Diffs {
		t.Errorf("%s: %s", label, d)
	}
	if !got.OK && len(got.Diffs) == 0 {
		t.Errorf("%s: _check not ok", label)
	}
}

func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random run token: %v", err)
	}
	return hex.EncodeToString(b)
}

// inputString returns a string input field, or "" when absent.
func inputString(v HTTPVector, key string) string {
	s, _ := v.Input[key].(string)
	return s
}

// inputOr returns a string input field, or def when the field is absent. A
// present "" is kept, as in the Python and Rust runners.
func inputOr(v HTTPVector, key, def string) string {
	if raw, ok := v.Input[key]; ok {
		if s, ok := raw.(string); ok {
			return s
		}
	}
	return def
}

// vectorLabel names a vector in failure messages.
func vectorLabel(id string, idx int, v HTTPVector) string {
	if v.Name != "" {
		return fmt.Sprintf("%s (%s)", id, v.Name)
	}
	return fmt.Sprintf("%s[%d]", id, idx)
}
