//go:build integration

package conformance

import (
	"context"
	"errors"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// runAuthorizationCodeVector is the authorization-code.json adapter for its
// HTTP vectors: token.AuthorizationCode. The PKCE vectors are pure logic and
// run in logic_test.go.
func runAuthorizationCodeVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()
	opts := []token.Option{token.WithInsecureAllowHTTP()}
	if s := inputString(v, "client_secret"); s != "" {
		opts = append(opts, token.WithClientSecret(s))
	}
	if s := inputString(v, "code_verifier"); s != "" {
		opts = append(opts, token.WithCodeVerifier(s))
	}
	resp, err := token.AuthorizationCode(context.Background(), base+"/token", "cid",
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
}
