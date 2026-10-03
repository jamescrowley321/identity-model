//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// runTokenExchangeVector is the token-exchange.json adapter: token.TokenExchange.
func runTokenExchangeVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()

	opts := []token.Option{token.WithInsecureAllowHTTP()}
	if inputString(v, "client_auth") == "client_secret_post" {
		opts = append(opts, token.WithClientAuth(token.ClientSecretPost))
	}
	if actor := inputString(v, "actor_token"); actor != "" {
		opts = append(opts, token.WithActorToken(actor, inputString(v, "actor_token_type")))
	}
	if s := inputString(v, "requested_token_type"); s != "" {
		opts = append(opts, token.WithRequestedTokenType(s))
	}
	if s := inputString(v, "audience"); s != "" {
		opts = append(opts, token.WithAudience(s))
	}
	if s := inputString(v, "resource"); s != "" {
		opts = append(opts, token.WithResource(s))
	}
	if s := inputString(v, "scope"); s != "" {
		opts = append(opts, token.WithScopes(s))
	}
	resp, err := token.TokenExchange(context.Background(), base+"/token", "cid", "secret",
		inputString(v, "subject_token"), inputString(v, "subject_token_type"), opts...)

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

// assertTokenResult compares each expected field with the response's JSON form.
func assertTokenResult(t *testing.T, label string, resp *token.TokenResponse, want map[string]any) {
	t.Helper()
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("%s: marshal result: %v", label, err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	for k, w := range want {
		if !reflect.DeepEqual(got[k], w) {
			t.Errorf("%s: %s = %v, want %v", label, k, got[k], w)
		}
	}
}
