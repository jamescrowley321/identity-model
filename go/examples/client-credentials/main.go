// Command client-credentials obtains an OAuth 2.0 access token via the client
// credentials grant (RFC 6749 §4.4).
//
// Against a real provider (token endpoint discovered from the issuer):
//
//	go run ./examples/client-credentials \
//	  -issuer https://accounts.example.com \
//	  -client-id my-id -client-secret my-secret -scopes "api read"
//
// With no -client-id, the example runs a self-contained demo: it serves a tiny
// token endpoint locally and exchanges credentials against it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer to discover the token endpoint")
	tokenEndpoint := flag.String("token-endpoint", "", "token endpoint (overrides discovery)")
	clientID := flag.String("client-id", "", "client ID (empty runs the self-contained demo)")
	clientSecret := flag.String("client-secret", "", "client secret")
	scopes := flag.String("scopes", "", "space-separated scopes")
	post := flag.Bool("post", false, "use client_secret_post instead of client_secret_basic")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// endpoints (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *clientID == "" {
		if err := runDemo(); err != nil {
			fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ctx := context.Background()
	endpoint := *tokenEndpoint
	if endpoint == "" {
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "-issuer or -token-endpoint is required")
			os.Exit(2)
		}
		discOpts := []discovery.Option{discovery.WithTimeout(*timeout)}
		if *insecureHTTP {
			discOpts = append(discOpts, discovery.WithInsecureAllowHTTP())
		}
		cfg, err := discovery.FetchConfiguration(ctx, *issuer, discOpts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "discovery failed: %v\n", err)
			os.Exit(1)
		}
		endpoint = cfg.TokenEndpoint
	}

	opts := []token.Option{token.WithTimeout(*timeout)}
	if *scopes != "" {
		opts = append(opts, token.WithScopes(strings.Fields(*scopes)...))
	}
	if *post {
		opts = append(opts, token.WithClientAuth(token.ClientSecretPost))
	}
	if *insecureHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}

	resp, err := token.ClientCredentials(ctx, endpoint, *clientID, *clientSecret, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client credentials failed: %v\n", err)
		os.Exit(1)
	}
	printToken(resp)
}

// runDemo serves a local token endpoint and exchanges credentials against it.
func runDemo() error {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "demo-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.PostForm.Get("scope"),
		})
	}))
	defer srv.Close()

	resp, err := token.ClientCredentials(context.Background(), srv.URL, "demo-id", "demo-secret",
		token.WithScopes("api"), token.WithInsecureAllowHTTP())
	if err != nil {
		return err
	}
	fmt.Println("Demo: obtained an access token via client credentials.")
	printToken(resp)
	return nil
}

func printToken(r *token.TokenResponse) {
	fmt.Printf("access_token=%s\ntoken_type=%s\nexpires_in=%d\nscope=%s\n",
		r.AccessToken, r.TokenType, r.ExpiresIn, r.Scope)
}
