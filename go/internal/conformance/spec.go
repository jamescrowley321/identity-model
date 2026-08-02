// Package conformance is the shared, cross-language conformance harness for
// identity-model. It loads the language-neutral vector definitions in
// spec/conformance/*.json so every language binding validates against a single
// source of truth rather than a per-language copy of the tests.
//
// The vectors express expected outcomes with canonical, language-neutral error
// codes (see the Error* constants); each language executor maps them to its own
// error types. Expected behaviour tracks the OIDF-certified py-identity-model
// reference implementation.
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Canonical, language-neutral error codes used in vector expectations.
const (
	ErrorMalformed       = "malformed"
	ErrorAlgNone         = "alg_none"
	ErrorUnsupportedAlg  = "unsupported_alg"
	ErrorSignature       = "signature"
	ErrorKeyConversion   = "key_conversion"
	ErrorClaimValidation = "claim_validation"
)

// Vector outcomes.
const (
	OutcomeAccept = "accept"
	OutcomeReject = "reject"
)

// executionNative marks a case that cannot be expressed as a static vector and
// is covered by a bespoke package test instead.
const executionNative = "native"

// Capability is one spec/conformance/<capability>.json file.
type Capability struct {
	Capability string `json:"capability"`
	Spec       string `json:"spec"`
	SpecURL    string `json:"spec_url"`
	Notes      string `json:"notes,omitempty"`
	Tests      []Case `json:"tests"`
}

// Case is one conformance test id. The prose fields (Given/When/Then) are the
// human contract; Vectors are the machine-executable form. A case with no
// Vectors must set Execution="native" plus Reason and NativeTest, because some
// behaviours (e.g. a forced JWKS refresh) cannot be expressed as a static
// vector.
type Case struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Given      string   `json:"given"`
	When       string   `json:"when"`
	Then       string   `json:"then"`
	References []string `json:"references,omitempty"`

	Vectors    []Vector `json:"vectors,omitempty"`
	Execution  string   `json:"execution,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	NativeTest string   `json:"native_test,omitempty"`
}

// IsNative reports whether the case is executed by a bespoke package test
// rather than the declarative vector runner.
func (c Case) IsNative() bool { return c.Execution == executionNative }

// Vector is one executable check within a case.
type Vector struct {
	Name    string    `json:"name,omitempty"`
	Token   TokenSpec `json:"token"`
	Options Options   `json:"options"`
	Expect  Expect    `json:"expect"`
}

// TokenSpec describes the token under test: either a static fixture file or a
// freshly minted JWS. Time-based claims are minted at run time so they stay
// valid (see spec/test-fixtures/validation/README.md).
type TokenSpec struct {
	// Static is a fixture-relative path to a committed token (mutually
	// exclusive with the minting fields below).
	Static string `json:"static,omitempty"`

	// SigningKey selects the key used to sign a minted token: "fixture"
	// (default, the shared signing key) or "ephemeral" (a throwaway key, so
	// the signature will not verify against the resolved public key).
	SigningKey string `json:"signing_key,omitempty"`
	// HeaderKid overrides the kid emitted in the JWS header. With an ephemeral
	// key this forges a header kid that resolves to a non-matching public key.
	HeaderKid string `json:"header_kid,omitempty"`
	// Alg is the JWS signing algorithm (default RS256).
	Alg string `json:"alg,omitempty"`
	// Claims is the token payload. Keys exp/nbf/iat are duration strings
	// (Go time.ParseDuration) resolved relative to Options.Now; all other
	// values are literal.
	Claims map[string]any `json:"claims,omitempty"`
}

// Options mirrors the language-neutral validation options.
type Options struct {
	Now               string   `json:"now,omitempty"` // RFC3339 fixed clock
	ExpectedIssuer    string   `json:"expected_issuer,omitempty"`
	ExpectedAudience  string   `json:"expected_audience,omitempty"`
	ExpectedNonce     string   `json:"expected_nonce,omitempty"`
	ClockSkew         string   `json:"clock_skew,omitempty"`
	RequiredClaims    []string `json:"required_claims,omitempty"`
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
}

// Expect is the asserted outcome of validating the token.
type Expect struct {
	Outcome string         `json:"outcome"`          // OutcomeAccept | OutcomeReject
	Error   string         `json:"error,omitempty"`  // canonical error code (reject)
	Claim   string         `json:"claim,omitempty"`  // offending claim for claim_validation
	Claims  map[string]any `json:"claims,omitempty"` // asserted claims (accept)
}

// LoadCapability reads and decodes a capability vector file. Unknown fields are
// rejected so a typo in a vector fails loudly instead of silently skipping a
// check.
func LoadCapability(path string) (*Capability, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read capability %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Capability
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode capability %s: %w", path, err)
	}
	return &c, nil
}
