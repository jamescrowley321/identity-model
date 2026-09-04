package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// The ID-Token capability (spec/conformance/id-token.json) uses a different,
// higher-level vector shape than validation.json: each vector supplies an
// already-decoded claim set plus the ID-Token JOSE-header alg and the caller
// inputs, rather than a token to mint and sign. These types model that shape so
// the Go runner drives the same cross-language oracle the Python reference does.

// IDTokenCapability is spec/conformance/id-token.json.
type IDTokenCapability struct {
	Capability                string        `json:"capability"`
	Spec                      string        `json:"spec"`
	SpecURL                   string        `json:"spec_url"`
	CrossLanguageCoverageGate string        `json:"cross_language_coverage_gate,omitempty"`
	Notes                     string        `json:"notes,omitempty"`
	Tests                     []IDTokenCase `json:"tests"`
}

// IDTokenCase is one IDT-* conformance id with one or more vectors.
type IDTokenCase struct {
	ID         string          `json:"id"`
	Title      string          `json:"title"`
	Given      string          `json:"given"`
	When       string          `json:"when"`
	Then       string          `json:"then"`
	References []string        `json:"references,omitempty"`
	Vectors    []IDTokenVector `json:"vectors"`
}

// IDTokenVector is one executable check: an input claim set + caller inputs and
// the asserted outcome.
type IDTokenVector struct {
	Name   string        `json:"name,omitempty"`
	Input  IDTokenInput  `json:"input"`
	Expect IDTokenExpect `json:"expect"`
}

// IDTokenInput is the language-neutral input to the ID-Token profile validator.
// The opt-in fields are pointers so "absent" (nil, do not run the check) is
// distinguished from an empty value.
type IDTokenInput struct {
	Claims map[string]any `json:"claims"`
	// HeaderAlg is a JSON string or null (null → nil → missing alg).
	HeaderAlg   *string  `json:"header_alg"`
	ClientID    string   `json:"client_id,omitempty"`
	Nonce       *string  `json:"nonce,omitempty"`
	AccessToken *string  `json:"access_token,omitempty"`
	Code        *string  `json:"code,omitempty"`
	MaxAge      *int     `json:"max_age,omitempty"`
	Leeway      *float64 `json:"leeway,omitempty"`
	// Now is the fixed POSIX-seconds clock for the auth_time/max_age check.
	Now float64 `json:"now"`
}

// IDTokenExpect is the asserted outcome. Reject carries the canonical error
// family ("id_token_profile") and a stable reason label.
type IDTokenExpect struct {
	Outcome string `json:"outcome"`          // OutcomeAccept | OutcomeReject
	Error   string `json:"error,omitempty"`  // canonical error family (reject)
	Reason  string `json:"reason,omitempty"` // stable reason label (reject)
}

// LoadIDTokenCapability reads and decodes the id-token capability vector file.
// Unknown fields are rejected so a typo in a vector fails loudly instead of
// silently skipping a check.
func LoadIDTokenCapability(path string) (*IDTokenCapability, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read id-token capability %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c IDTokenCapability
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode id-token capability %s: %w", path, err)
	}
	return &c, nil
}
