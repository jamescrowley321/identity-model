package conformance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// TestAuthorizationCodeConformance drives every vector in
// authorization-code.json: PKCE data vectors against GenerateCodeVerifier and
// S256Challenge, HTTP vectors against token.AuthorizationCode.
func TestAuthorizationCodeConformance(t *testing.T) {
	suite := LoadHTTPCapability(t, "authorization-code.json")

	for _, tc := range suite.Tests {
		t.Run(tc.ID, func(t *testing.T) {
			if len(tc.Vectors) == 0 {
				t.Fatalf("%s: no vectors", tc.ID)
			}
			for i, v := range tc.Vectors {
				label := vectorLabel(tc.ID, i, v)
				switch op := inputString(v, "operation"); op {
				case "generate_code_verifier":
					runGenerateVerifierVector(t, label, v)
				case "s256_challenge":
					got := token.S256Challenge(inputString(v, "code_verifier"))
					if want := v.Expect.Result["code_challenge"]; got != want {
						t.Errorf("%s: code_challenge = %q, want %v", label, got, want)
					}
				case "":
					runAuthorizationCodeVector(t, label, v)
				default:
					t.Fatalf("%s: unknown operation %q", label, op)
				}
			}
		})
	}
}

// runGenerateVerifierVector generates distinct_samples verifiers, checks each
// one's length and alphabet, and requires them all to differ.
func runGenerateVerifierVector(t *testing.T, label string, v HTTPVector) {
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

func runAuthorizationCodeVector(t *testing.T, label string, v HTTPVector) {
	t.Helper()
	srv := newMockServer(t, v)

	opts := []token.Option{token.WithInsecureAllowHTTP()}
	if s := inputString(v, "client_secret"); s != "" {
		opts = append(opts, token.WithClientSecret(s))
	}
	if s := inputString(v, "code_verifier"); s != "" {
		opts = append(opts, token.WithCodeVerifier(s))
	}
	resp, err := token.AuthorizationCode(context.Background(), srv.URL+"/token", "cid",
		inputString(v, "code"), inputString(v, "redirect_uri"), opts...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		assertTokenResult(t, label, resp, v.Expect.Result)
	case OutcomeReject:
		var te *token.TokenError
		if !errors.As(err, &te) {
			t.Fatalf("%s: expected TokenError %q, got %v", label, v.Expect.Error, err)
		}
		want := token.TokenError{
			Code:             v.Expect.Error,
			ErrorDescription: v.Expect.ErrorDescription,
			ErrorURI:         v.Expect.ErrorURI,
			StatusCode:       v.Expect.Status,
		}
		if *te != want {
			t.Errorf("%s: error = %+v, want %+v", label, *te, want)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
	srv.assertRequest(t, label, v.ExpectRequest)
}
