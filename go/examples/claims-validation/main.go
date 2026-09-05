// Command claims-validation demonstrates the injectable, composable claims
// validator wired into JWT validation. It builds a policy by combining two
// ready-made validators — RequireClaims("sub", "email") and RequireScopes("read")
// — with CombineClaimsValidators in "all" mode, then installs the combined
// validator on jwt.Validate via WithClaimsValidator. The application policy runs
// only after the signature, algorithm-allowlist, and registered-claim checks
// pass.
//
// The example is self-contained: it generates a key, serves a matching JWKS
// locally, mints two tokens, and validates both against the same policy:
//
//   - an accepted token that carries sub, email, and the "read" scope, and
//   - a rejected token that carries sub and email but only the "write" scope,
//     so the RequireScopes member rejects it with a structured error naming the
//     "scope" claim.
//
// Run it with no arguments:
//
//	go run ./examples/claims-validation
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

const (
	demoIssuer   = "https://demo.example.com"
	demoAudience = "demo-client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "example failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// A signing key and a matching public JWKS served locally, so the example
	// runs end to end with no external provider.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	signKey := &jose.JSONWebKey{Key: priv, KeyID: "demo-key", Algorithm: "RS256", Use: "sig"}
	pubKey := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "demo-key", Algorithm: "RS256", Use: "sig"}

	jwksDoc, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pubKey}})
	if err != nil {
		return err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	ctx := context.Background()
	set, err := jwks.FetchKeySet(ctx, srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		return err
	}

	// Compose application policy from two ready-made validators. In "all" mode
	// every member must accept; the first rejection propagates, surfacing that
	// member's claim.
	requireIdentity, err := jwt.RequireClaims("sub", "email")
	if err != nil {
		return err
	}
	requireScope, err := jwt.RequireScopes("read")
	if err != nil {
		return err
	}
	policy, err := jwt.CombineClaimsValidators(
		[]jwt.ClaimsValidator{requireIdentity, requireScope},
		jwt.CombineAll,
	)
	if err != nil {
		return err
	}

	validateOpts := []jwt.Option{
		jwt.WithExpectedIssuer(demoIssuer),
		jwt.WithExpectedAudience(demoAudience),
		jwt.WithClaimsValidator(policy),
	}

	// An accepted token: correct signature, issuer, audience, plus the sub,
	// email, and read scope the policy requires.
	accepted, err := mintToken(signKey, map[string]any{
		"iss":   demoIssuer,
		"sub":   "user-1",
		"aud":   demoAudience,
		"email": "user-1@example.com",
		"scope": "read write",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		return err
	}

	// A rejected token: identical except it lacks the "read" scope, so the
	// RequireScopes member rejects it after the standard checks pass.
	rejected, err := mintToken(signKey, map[string]any{
		"iss":   demoIssuer,
		"sub":   "user-2",
		"aud":   demoAudience,
		"email": "user-2@example.com",
		"scope": "write",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		return err
	}

	fmt.Println("Policy: RequireClaims(\"sub\", \"email\") AND RequireScopes(\"read\"), combined with CombineAll.")

	fmt.Println("\nToken A (sub, email, scope \"read write\"):")
	claims, err := jwt.Validate(ctx, accepted, set, validateOpts...)
	if err != nil {
		return fmt.Errorf("token A should have been accepted: %w", err)
	}
	fmt.Printf("  accepted — sub=%s email=%s\n", claims.Subject, mustString(claims, "email"))

	fmt.Println("\nToken B (sub, email, scope \"write\" — missing \"read\"):")
	_, err = jwt.Validate(ctx, rejected, set, validateOpts...)
	if err == nil {
		return errors.New("token B should have been rejected by the scope policy")
	}
	var cve *jwt.ClaimsValidationError
	if errors.As(err, &cve) {
		fmt.Printf("  rejected — reason: %s (claim %q)\n", cve.Reason, cve.Claim)
	} else {
		fmt.Printf("  rejected — %v\n", err)
	}
	return nil
}

// mintToken signs an RS256 JWT (kid=demo-key) carrying claims.
func mintToken(signKey *jose.JSONWebKey, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func mustString(c *jwt.Claims, name string) string {
	s, err := c.GetString(name)
	if err != nil {
		return ""
	}
	return s
}
