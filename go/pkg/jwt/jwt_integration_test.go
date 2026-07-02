//go:build integration

package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// infraIssuer is the local node-oidc-provider from infra/ (docker compose up).
const infraIssuer = "http://localhost:9000"

// TestIntegration_Validate_AgainstLiveJWKS discovers the live provider, fetches
// its real JWKS, then validates a token signed by our own (non-provider) key.
// Because that key's kid is absent from the provider's set, validation must
// drive a JWKS forced refresh (ResolveKeyWithRefresh) and ultimately surface
// jwks.ErrKeyNotFound against the live endpoint.
//
// Full validation of a provider-issued id_token (where the signature verifies)
// requires the authorization-code flow and is deferred to stories 3.5/3.6.
func TestIntegration_Validate_AgainstLiveJWKS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := discovery.FetchConfiguration(ctx, infraIssuer, discovery.WithInsecureAllowHTTP())
	if err != nil {
		t.Skipf("infra provider not reachable at %s (run `cd infra && docker compose up -d`): %v", infraIssuer, err)
	}

	set, err := jwks.FetchKeySet(ctx, cfg.JWKSURI, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch live jwks: %v", err)
	}
	if len(set.Keys) == 0 {
		t.Fatalf("live jwks returned no keys")
	}

	// Sign a token with our own key, whose kid the provider does not publish.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := &jose.JSONWebKey{Key: priv, KeyID: "local-test-key", Algorithm: "RS256"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": infraIssuer,
		"sub": "integration-subject",
		"aud": "integration-client",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.Validate(ctx, token, set)
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("err = %v, want jwks.ErrKeyNotFound after live forced refresh", err)
	}
}
