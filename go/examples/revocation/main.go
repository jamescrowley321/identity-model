// Command revocation revokes an OAuth 2.0 token (RFC 7009) — the operation a
// client performs at logout to proactively invalidate a refresh token (and,
// with it, the tokens derived from it) rather than waiting for expiry.
//
// Against a real provider (the revocation endpoint discovered from the issuer):
//
//	go run ./examples/revocation \
//	  -issuer https://accounts.example.com \
//	  -client-id "$CLIENT_ID" \
//	  -client-secret "$CLIENT_SECRET" \
//	  -token "$REFRESH_TOKEN" \
//	  -token-type-hint refresh_token
//
// With no -token, the example runs a self-contained demo: it serves a tiny
// revocation endpoint locally and revokes a refresh token against it, showing
// the RFC 7009 §2.1 property that the endpoint answers HTTP 200 whether or not
// the token was valid.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/revocation"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer to discover the revocation endpoint")
	endpoint := flag.String("revocation-endpoint", "", "revocation endpoint (overrides discovery)")
	clientID := flag.String("client-id", "", "revoking client's id")
	clientSecret := flag.String("client-secret", "", "revoking client's secret")
	token := flag.String("token", "", "token to revoke (empty runs the self-contained demo)")
	tokenTypeHint := flag.String("token-type-hint", "refresh_token", "optional token_type_hint, e.g. refresh_token or access_token")
	postAuth := flag.Bool("client-secret-post", false, "authenticate with client_secret_post instead of client_secret_basic")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// endpoints (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *token == "" {
		runDemo()
		return
	}

	if *clientID == "" || *clientSecret == "" {
		fmt.Fprintln(os.Stderr, "-client-id and -client-secret are required to revoke")
		os.Exit(2)
	}

	// The context deadline bounds the whole call (discovery + revoke); no need to
	// also pass revocation.WithTimeout, which would re-apply it.
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := []revocation.Option{}
	if *insecureHTTP {
		opts = append(opts, revocation.WithInsecureAllowHTTP())
	}
	if *postAuth {
		opts = append(opts, revocation.WithClientAuth(revocation.ClientSecretPost))
	}
	if *tokenTypeHint != "" {
		opts = append(opts, revocation.WithTokenTypeHint(*tokenTypeHint))
	}

	target := *endpoint
	if target == "" {
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "either -issuer or -revocation-endpoint is required")
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
		target = cfg.RevocationEndpoint
		if target == "" {
			fmt.Fprintln(os.Stderr, "provider advertises no revocation_endpoint")
			os.Exit(1)
		}
	}

	if err := revocation.Revoke(ctx, target, *clientID, *clientSecret, *token, opts...); err != nil {
		var re *revocation.RevocationError
		if errors.As(err, &re) {
			fmt.Fprintf(os.Stderr, "endpoint rejected the request (HTTP %d): %s\n", re.StatusCode, re.Code)
		} else {
			fmt.Fprintf(os.Stderr, "revocation failed: %v\n", err)
		}
		os.Exit(1)
	}
	// RFC 7009 §2.2: a successful revocation carries no body — reaching here means
	// the token (and any tokens derived from it) is now invalidated.
	fmt.Println("token revoked")
}

// runDemo serves a tiny revocation endpoint locally and revokes a refresh token
// against it, so the example is runnable with no real provider or token. It
// demonstrates the logout flow: the client revokes the refresh token it was
// issued at login.
func runDemo() {
	// revoked records the tokens the demo endpoint was asked to revoke.
	revoked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real endpoint authenticates the revoking client; the demo just checks
		// the pair is present.
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
		revoked[r.PostFormValue("token")] = true
		// RFC 7009 §2.1: HTTP 200 regardless of whether the token was valid,
		// already revoked, or unknown — no body.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const refreshToken = "demo-refresh-token"

	fmt.Println("Self-contained demo — logout: revoking the refresh token issued at login:")
	if err := revocation.Revoke(ctx, srv.URL, "demo-client", "demo-secret", refreshToken,
		revocation.WithInsecureAllowHTTP(), revocation.WithTokenTypeHint("refresh_token")); err != nil {
		fmt.Fprintf(os.Stderr, "demo revoke failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  refresh token revoked (endpoint recorded revocation: %t)\n", revoked[refreshToken])

	fmt.Println("\nSelf-contained demo — revoking the same (now unknown) token again still returns 200:")
	if err := revocation.Revoke(ctx, srv.URL, "demo-client", "demo-secret", refreshToken,
		revocation.WithInsecureAllowHTTP()); err != nil {
		fmt.Fprintf(os.Stderr, "demo re-revoke failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  second revoke succeeded (RFC 7009 §2.1 anti-scanning: identical response)")
}
