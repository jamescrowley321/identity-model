//go:build integration

package conformance

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

// headerTransport adds default headers to every request, so a vector can
// prove a caller-supplied http.Client performed the request.
type headerTransport map[string]string

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// runClientCredentialsVector is the client-credentials.json adapter:
// token.ClientCredentials.
func runClientCredentialsVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()

	opts := []token.Option{token.WithInsecureAllowHTTP()}
	if inputString(v, "client_auth") == "client_secret_post" {
		opts = append(opts, token.WithClientAuth(token.ClientSecretPost))
	}
	if scopes, ok := v.Input["scopes"].([]any); ok {
		var s []string
		for _, sc := range scopes {
			s = append(s, sc.(string))
		}
		opts = append(opts, token.WithScopes(s...))
	}
	if extra, ok := v.Input["extra_params"].(map[string]any); ok {
		params := map[string]string{}
		for k, val := range extra {
			params[k] = val.(string)
		}
		opts = append(opts, token.WithExtraParams(params))
	}
	if headers, ok := v.Input["http_client_headers"].(map[string]any); ok {
		ht := headerTransport{}
		for k, val := range headers {
			ht[k] = val.(string)
		}
		opts = append(opts, token.WithHTTPClient(&http.Client{Transport: ht}))
	}
	secret := "secret"
	if s, ok := v.Input["client_secret"].(string); ok {
		secret = s
	}
	resp, err := token.ClientCredentials(context.Background(), base+"/token", "cid", secret, opts...)

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
