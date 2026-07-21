// Command introspection queries an OAuth 2.0 token introspection endpoint
// (RFC 7662) to determine whether a token is active and to inspect its
// associated metadata.
//
// Against a real provider (the introspection endpoint discovered from the
// issuer):
//
//	go run ./examples/introspection \
//	  -issuer https://accounts.example.com \
//	  -client-id "$CLIENT_ID" \
//	  -client-secret "$CLIENT_SECRET" \
//	  -token "$ACCESS_TOKEN"
//
// With no -token, the example runs a self-contained demo: it serves a tiny
// introspection endpoint locally and introspects both an active and an inactive
// token against it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/introspection"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer to discover the introspection endpoint")
	endpoint := flag.String("introspection-endpoint", "", "introspection endpoint (overrides discovery)")
	clientID := flag.String("client-id", "", "introspecting client's id")
	clientSecret := flag.String("client-secret", "", "introspecting client's secret")
	token := flag.String("token", "", "token to introspect (empty runs the self-contained demo)")
	tokenTypeHint := flag.String("token-type-hint", "", "optional token_type_hint, e.g. access_token")
	postAuth := flag.Bool("client-secret-post", false, "authenticate with client_secret_post instead of client_secret_basic")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// endpoints (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *token == "" {
		runDemo()
		return
	}

	if *clientID == "" || *clientSecret == "" {
		fmt.Fprintln(os.Stderr, "-client-id and -client-secret are required to introspect")
		os.Exit(2)
	}

	// The context deadline bounds the whole call (discovery + introspect); no
	// need to also pass introspection.WithTimeout, which would re-apply it.
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := []introspection.Option{}
	if *insecureHTTP {
		opts = append(opts, introspection.WithInsecureAllowHTTP())
	}
	if *postAuth {
		opts = append(opts, introspection.WithClientAuth(introspection.ClientSecretPost))
	}
	if *tokenTypeHint != "" {
		opts = append(opts, introspection.WithTokenTypeHint(*tokenTypeHint))
	}

	target := *endpoint
	if target == "" {
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "either -issuer or -introspection-endpoint is required")
			os.Exit(2)
		}
		dopts := []discovery.Option{}
		if *insecureHTTP {
			dopts = append(dopts, discovery.WithInsecureAllowHTTP())
		}
		cfg, err := discovery.FetchConfiguration(ctx, *issuer, dopts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "discovery failed: %v\n", err)
			os.Exit(1)
		}
		target = cfg.IntrospectionEndpoint
		if target == "" {
			fmt.Fprintln(os.Stderr, "provider advertises no introspection_endpoint")
			os.Exit(1)
		}
	}

	result, err := introspection.Introspect(ctx, target, *clientID, *clientSecret, *token, opts...)
	if err != nil {
		var ie *introspection.IntrospectionError
		if errors.As(err, &ie) {
			fmt.Fprintf(os.Stderr, "endpoint rejected the request (HTTP %d): %s\n", ie.StatusCode, ie.Code)
		} else {
			fmt.Fprintf(os.Stderr, "introspection failed: %v\n", err)
		}
		os.Exit(1)
	}
	printResult(result)
}

// runDemo serves a tiny introspection endpoint locally and introspects an
// active and an inactive token against it, so the example is runnable with no
// real provider or token.
func runDemo() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real endpoint authenticates the introspecting client; the demo just
		// checks the pair is present.
		id, secret, ok := r.BasicAuth()
		if !ok || id != "demo-client" || secret != "demo-secret" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.PostFormValue("token") == "active-token" {
			_, _ = w.Write([]byte(`{
				"active": true,
				"scope": "read write",
				"client_id": "demo-client",
				"username": "jane.doe",
				"token_type": "Bearer",
				"exp": 1735689600,
				"iat": 1735686000,
				"sub": "248289761001",
				"aud": "https://api.example.com",
				"iss": "https://accounts.example.com",
				"jti": "abc-123",
				"tenant": "acme"
			}`))
			return
		}
		// RFC 7662 §2.2: an inactive token yields active=false and nothing else.
		_, _ = w.Write([]byte(`{"active": false}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("Self-contained demo — introspecting an active token:")
	active, err := introspection.Introspect(ctx, srv.URL, "demo-client", "demo-secret", "active-token",
		introspection.WithInsecureAllowHTTP(), introspection.WithTokenTypeHint("access_token"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo introspect (active) failed: %v\n", err)
		os.Exit(1)
	}
	printResult(active)

	fmt.Println("\nSelf-contained demo — introspecting an inactive token:")
	inactive, err := introspection.Introspect(ctx, srv.URL, "demo-client", "demo-secret", "revoked-token",
		introspection.WithInsecureAllowHTTP())
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo introspect (inactive) failed: %v\n", err)
		os.Exit(1)
	}
	printResult(inactive)
}

func printResult(r *introspection.Introspection) {
	fmt.Printf("active: %t\n", r.Active)
	if !r.Active {
		// RFC 7662 §2.2: no other members are guaranteed when active is false.
		return
	}
	if r.Scope != "" {
		fmt.Printf("scope:  %s\n", r.Scope)
	}
	if r.ClientID != "" {
		fmt.Printf("client: %s\n", r.ClientID)
	}
	if r.Sub != "" {
		fmt.Printf("sub:    %s\n", r.Sub)
	}
	if len(r.Extra) > 0 {
		fmt.Println("extra provider members:")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r.Extra)
	}
}
