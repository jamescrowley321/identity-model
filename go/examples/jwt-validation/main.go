// Command jwt-validation validates a JWT against a JWK Set with configurable
// options (expected issuer, audience, nonce, clock skew).
//
// Validate a real token against a provider's JWKS:
//
//	go run ./examples/jwt-validation \
//	  -token "$ID_TOKEN" \
//	  -jwks-uri https://www.googleapis.com/oauth2/v3/certs \
//	  -issuer https://accounts.google.com -audience my-client-id
//
// With no -token, the example runs a self-contained demo: it generates a key,
// serves a matching JWKS locally, mints a token and validates it end to end.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

func main() {
	token := flag.String("token", "", "JWT to validate (empty runs the self-contained demo)")
	jwksURI := flag.String("jwks-uri", "", "JWKS URI to resolve the signing key")
	issuer := flag.String("issuer", "", "expected issuer (iss)")
	audience := flag.String("audience", "", "expected audience (aud)")
	nonce := flag.String("nonce", "", "expected nonce")
	skew := flag.Duration("clock-skew", 0, "permitted clock skew for exp/nbf")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// jwks_uri (development only)")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	flag.Parse()

	if *token == "" {
		if err := runDemo(); err != nil {
			fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *jwksURI == "" {
		fmt.Fprintln(os.Stderr, "-jwks-uri is required when -token is supplied")
		os.Exit(2)
	}

	ctx := context.Background()
	fetchOpts := []jwks.Option{jwks.WithTimeout(*timeout)}
	if *insecureHTTP {
		fetchOpts = append(fetchOpts, jwks.WithInsecureAllowHTTP())
	}
	set, err := jwks.FetchKeySet(ctx, *jwksURI, fetchOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch jwks failed: %v\n", err)
		os.Exit(1)
	}

	var opts []jwt.Option
	if *issuer != "" {
		opts = append(opts, jwt.WithExpectedIssuer(*issuer))
	}
	if *audience != "" {
		opts = append(opts, jwt.WithExpectedAudience(*audience))
	}
	if *nonce != "" {
		opts = append(opts, jwt.WithExpectedNonce(*nonce))
	}
	if *skew > 0 {
		opts = append(opts, jwt.WithClockSkew(*skew))
	}

	claims, err := jwt.Validate(ctx, *token, set, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "validation failed: %v\n", err)
		os.Exit(1)
	}
	printClaims(claims)
}

// runDemo generates a key, serves a matching JWKS, mints a token and validates
// it, so the example works with no arguments.
func runDemo() error {
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

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return err
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss":   "https://demo.example.com",
		"sub":   "demo-user",
		"aud":   "demo-client",
		"nonce": "demo-nonce",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": "demo@example.com",
	})
	if err != nil {
		return err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return err
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		return err
	}

	ctx := context.Background()
	set, err := jwks.FetchKeySet(ctx, srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		return err
	}
	claims, err := jwt.Validate(ctx, token, set,
		jwt.WithExpectedIssuer("https://demo.example.com"),
		jwt.WithExpectedAudience("demo-client"),
		jwt.WithExpectedNonce("demo-nonce"),
	)
	if err != nil {
		return err
	}
	fmt.Println("Demo: minted and validated a token end to end.")
	printClaims(claims)
	return nil
}

func printClaims(c *jwt.Claims) {
	fmt.Println("Token is valid. Claims:")
	fmt.Printf("  iss=%s\n  sub=%s\n  aud=%v\n", c.Issuer, c.Subject, c.Audience)
	if c.Expiry != nil {
		fmt.Printf("  exp=%s\n", c.Expiry.UTC().Format(time.RFC3339))
	}
	if email, err := c.GetString("email"); err == nil {
		fmt.Printf("  email=%s\n", email)
	}
}
