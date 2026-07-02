package token

import (
	"strings"
	"testing"
)

// ACG-003: S256Challenge must match the RFC 7636 Appendix B worked example
// exactly. See spec/test-fixtures/token/pkce-appendix-b.json.
func TestS256Challenge_RFC7636AppendixB(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := S256Challenge(verifier); got != challenge {
		t.Errorf("S256Challenge = %q, want %q", got, challenge)
	}
}

// ACG-002: GenerateCodeVerifier yields a 43-128 char unreserved string.
func TestGenerateCodeVerifier_LengthAndCharset(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for i := 0; i < 100; i++ {
		v, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("GenerateCodeVerifier: %v", err)
		}
		if len(v) < minCodeVerifierLength || len(v) > maxCodeVerifierLength {
			t.Fatalf("length = %d, want %d-%d", len(v), minCodeVerifierLength, maxCodeVerifierLength)
		}
		for _, c := range v {
			if !strings.ContainsRune(unreserved, c) {
				t.Fatalf("verifier %q contains non-unreserved char %q", v, c)
			}
		}
		if !validCodeVerifier(v) {
			t.Fatalf("generated verifier %q failed validCodeVerifier", v)
		}
	}
}

// ACG-002: successive verifiers must differ (cryptographic randomness).
func TestGenerateCodeVerifier_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		v, err := GenerateCodeVerifier()
		if err != nil {
			t.Fatalf("GenerateCodeVerifier: %v", err)
		}
		if seen[v] {
			t.Fatalf("duplicate verifier generated: %q", v)
		}
		seen[v] = true
	}
}

func TestValidCodeVerifier(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"appendix-b", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", true},
		{"min-43", strings.Repeat("a", 43), true},
		{"max-128", strings.Repeat("a", 128), true},
		{"too-short-42", strings.Repeat("a", 42), false},
		{"too-long-129", strings.Repeat("a", 129), false},
		{"illegal-char", strings.Repeat("a", 42) + "/", false},
		{"all-unreserved", "ABCabc012" + strings.Repeat("-._~", 9), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCodeVerifier(tc.in); got != tc.want {
				t.Errorf("validCodeVerifier(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
