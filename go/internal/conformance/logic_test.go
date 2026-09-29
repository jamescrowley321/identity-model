package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// logicVector is a pure-logic vector: input.operation names what to run and
// expect.result what it must produce. It needs no HTTP.
type logicVector struct {
	Name   string         `json:"name"`
	Input  map[string]any `json:"input"`
	Expect struct {
		Outcome string         `json:"outcome"`
		Result  map[string]any `json:"result"`
	} `json:"expect"`
}

// logicOperations maps an operation name to its check. An operation with no
// entry fails the run.
var logicOperations = map[string]func(t *testing.T, label string, v logicVector){
	"generate_code_verifier": runGenerateVerifierVector,
	"s256_challenge": func(t *testing.T, label string, v logicVector) {
		verifier, ok := v.Input["code_verifier"].(string)
		if !ok {
			t.Fatalf("%s: input.code_verifier is not a string", label)
		}
		if got, want := token.S256Challenge(verifier), v.Expect.Result["code_challenge"]; got != want {
			t.Errorf("%s: code_challenge = %q, want %v", label, got, want)
		}
	},
}

// TestLogicVectors runs every pure-logic vector (input.operation) in
// spec/vectors in-process. HTTP vectors in the same files run in
// TestHTTPVectors against the node-oidc fixture.
func TestLogicVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(specVectorsDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vector files in %s: %v", specVectorsDir, err)
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var spec struct {
			Tests []struct {
				ID      string            `json:"id"`
				Vectors []json.RawMessage `json:"vectors"`
			} `json:"tests"`
		}
		if err := json.Unmarshal(b, &spec); err != nil {
			t.Fatalf("decode %s: %v", file, err)
		}
		for _, tc := range spec.Tests {
			for i, raw := range tc.Vectors {
				var v logicVector
				if err := json.Unmarshal(raw, &v); err != nil {
					t.Fatalf("%s %s[%d]: %v", filepath.Base(file), tc.ID, i, err)
				}
				op, ok := v.Input["operation"].(string)
				if !ok {
					continue
				}
				key := v.Name
				if key == "" {
					key = fmt.Sprint(i)
				}
				label := fmt.Sprintf("%s (%s)", tc.ID, key)
				t.Run(tc.ID+"/"+key, func(t *testing.T) {
					check, ok := logicOperations[op]
					if !ok {
						t.Fatalf("%s: no runner for operation %q", label, op)
					}
					if v.Expect.Outcome != OutcomeAccept {
						t.Fatalf("%s: outcome = %q, want accept", label, v.Expect.Outcome)
					}
					check(t, label, v)
				})
			}
		}
	}
}

// runGenerateVerifierVector generates distinct_samples verifiers, checks each
// one's length and alphabet, and requires them all to differ.
func runGenerateVerifierVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	minLen, _ := v.Expect.Result["min_length"].(float64)
	maxLen, _ := v.Expect.Result["max_length"].(float64)
	alphabet, _ := v.Expect.Result["alphabet"].(string)
	samples, _ := v.Expect.Result["distinct_samples"].(float64)
	if samples < 2 {
		t.Fatalf("%s: distinct_samples = %v, want at least 2", label, samples)
	}
	seen := map[string]bool{}
	for range int(samples) {
		verifier, err := token.GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if n := float64(len(verifier)); n < minLen || n > maxLen {
			t.Errorf("%s: verifier length %d outside [%v, %v]", label, len(verifier), minLen, maxLen)
		}
		for _, c := range verifier {
			if !strings.ContainsRune(alphabet, c) {
				t.Errorf("%s: verifier %q has character %q outside the alphabet", label, verifier, c)
			}
		}
		if seen[verifier] {
			t.Errorf("%s: verifier %q generated twice", label, verifier)
		}
		seen[verifier] = true
	}
}
