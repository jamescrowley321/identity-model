package conformance

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// TestJWKSConformance drives every vector in jwks.json against one
// jwks.FetchKeySet handle per vector.
func TestJWKSConformance(t *testing.T) {
	suite := LoadHTTPCapability(t, "jwks.json")

	for _, tc := range suite.Tests {
		t.Run(tc.ID, func(t *testing.T) {
			if len(tc.Vectors) == 0 {
				t.Fatalf("%s: no vectors", tc.ID)
			}
			for i, v := range tc.Vectors {
				runJWKSVector(t, vectorLabel(tc.ID, i, v), v)
			}
		})
	}
}

// jwksErrors maps the canonical reject codes to the Go sentinel errors.
var jwksErrors = map[string]error{
	"malformed":     jwks.ErrParse,
	"empty_key_set": jwks.ErrEmptyKeySet,
	"key_not_found": jwks.ErrKeyNotFound,
}

func runJWKSVector(t *testing.T, label string, v HTTPVector) {
	t.Helper()
	jwks.ClearCache()
	srv := newMockServer(t, v)
	ctx := context.Background()
	uri := srv.URL + "/jwks"

	var set *jwks.JSONWebKeySet
	var got []jwks.JSONWebKey
	var err error
	steps, _ := v.Input["steps"].([]any)
	// Each resolve takes the next of input.kids when given, else input.kid.
	kids, _ := v.Input["kids"].([]any)
	for i, step := range steps {
		switch step {
		case "fetch":
			if set, err = jwks.FetchKeySet(ctx, uri, jwks.WithInsecureAllowHTTP()); err == nil {
				got = set.Keys
			}
		case "resolve":
			kid := inputString(v, "kid")
			if len(kids) > 0 {
				kid, _ = kids[0].(string)
				kids = kids[1:]
			}
			var k *jwks.JSONWebKey
			if k, err = set.ResolveKeyWithRefresh(ctx, kid); err == nil {
				got = []jwks.JSONWebKey{*k}
			} else if errors.Is(err, jwks.ErrKeyNotFound) && i+1 < len(steps) {
				// A key-not-found miss before the last step does not end the run.
				err, got = nil, nil
			}
		case "force_refresh":
			if err = set.ForceRefresh(ctx); err == nil {
				got = set.Keys
			}
		default:
			t.Fatalf("%s: unknown step %v", label, step)
		}
		if err != nil {
			break
		}
	}

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		have := make([]map[string]string, 0, len(got))
		for _, k := range got {
			have = append(have, jwkMembers(k))
		}
		if !reflect.DeepEqual(have, v.Expect.Keys) {
			t.Errorf("%s: keys = %v, want %v", label, have, v.Expect.Keys)
		}
	case OutcomeReject:
		want, ok := jwksErrors[v.Expect.Error]
		if !ok {
			t.Fatalf("%s: unknown expected error %q", label, v.Expect.Error)
		}
		if !errors.Is(err, want) {
			t.Fatalf("%s: expected %q, got %v", label, v.Expect.Error, err)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
	srv.assertRequest(t, label, v.ExpectRequest)
	srv.assertCalls(t, label, v.ExpectCalls)
}

// jwkMembers returns the key's non-empty modelled JWK members.
func jwkMembers(k jwks.JSONWebKey) map[string]string {
	all := map[string]string{
		"kty": k.Kty, "kid": k.Kid, "use": k.Use, "alg": k.Alg,
		"n": k.N, "e": k.E, "crv": k.Crv, "x": k.X, "y": k.Y,
	}
	maps.DeleteFunc(all, func(_, v string) bool { return v == "" })
	return all
}
