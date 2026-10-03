//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/introspection"
)

// runIntrospectionVector is the introspection.json adapter: introspection.Introspect.
func runIntrospectionVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()
	ctx := context.Background()

	endpoint := base + "/introspect"
	if discover, _ := v.Input["discover"].(bool); discover {
		discovery.ClearCache()
		cfg, err := discovery.FetchConfiguration(ctx, base, discovery.WithInsecureAllowHTTP())
		if err != nil {
			t.Fatalf("%s: discovery: %v", label, err)
		}
		endpoint = cfg.IntrospectionEndpoint
	}

	opts := []introspection.Option{introspection.WithInsecureAllowHTTP()}
	if hint := inputString(v, "token_type_hint"); hint != "" {
		opts = append(opts, introspection.WithTokenTypeHint(hint))
	}
	if inputString(v, "client_auth") == "client_secret_post" {
		opts = append(opts, introspection.WithClientAuth(introspection.ClientSecretPost))
	}
	secret := inputString(v, "client_secret")
	if secret == "" {
		secret = "secret"
	}
	ir, err := introspection.Introspect(ctx, endpoint, "cid", secret, inputString(v, "token"), opts...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		typed := typedIntrospectionClaims(t, ir)
		for name, want := range v.Expect.Claims {
			have, ok := typed[name]
			if !ok {
				t.Errorf("%s: member %s is not a typed field", label, name)
			} else if !reflect.DeepEqual(have, want) {
				t.Errorf("%s: typed member %s = %v, want %v", label, name, have, want)
			}
		}
		for name, want := range v.Expect.CustomClaims {
			if have := ir.Extra[name]; !reflect.DeepEqual(have, want) {
				t.Errorf("%s: overflow member %s = %v, want %v", label, name, have, want)
			}
		}
	case OutcomeReject:
		if v.Expect.Error == "malformed" {
			// A 2xx body that is not a valid §2.2 response fails to decode.
			var re *introspection.RequestError
			if !errors.As(err, &re) || re.Op != "decode introspection response" {
				t.Fatalf("%s: expected a decode RequestError, got %v", label, err)
			}
			if re.StatusCode != v.Expect.Status {
				t.Errorf("%s: status = %d, want %d", label, re.StatusCode, v.Expect.Status)
			}
			return
		}
		var ie *introspection.IntrospectionError
		if !errors.As(err, &ie) {
			t.Fatalf("%s: expected IntrospectionError %q, got %v", label, v.Expect.Error, err)
		}
		if ie.Code != v.Expect.Error {
			t.Errorf("%s: error = %q, want %q", label, ie.Code, v.Expect.Error)
		}
		if ie.StatusCode != v.Expect.Status {
			t.Errorf("%s: status = %d, want %d", label, ie.StatusCode, v.Expect.Status)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
}

// typedIntrospectionClaims maps the typed §2.2 fields back to member names, as
// JSON values, so they compare against the vector's claims. Extra is excluded.
func typedIntrospectionClaims(t *testing.T, ir *introspection.Introspection) map[string]any {
	t.Helper()
	b, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("marshal typed members: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal typed members: %v", err)
	}
	return out
}
