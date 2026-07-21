// Command token-exchange exchanges one token for another at the OAuth 2.0 token
// endpoint using the RFC 8693 token exchange grant — the operation a service
// performs to obtain a scoped-down token for a downstream call (impersonation)
// or a token that records who is acting on whose behalf (delegation).
//
// Against a real provider (the token endpoint discovered from the issuer):
//
//	go run ./examples/token-exchange \
//	  -issuer https://accounts.example.com \
//	  -client-id "$CLIENT_ID" \
//	  -client-secret "$CLIENT_SECRET" \
//	  -subject-token "$SUBJECT_ACCESS_TOKEN" \
//	  -audience https://api.example.com
//
// Add -actor-token "$ACTOR_TOKEN" to run a delegation exchange instead of an
// impersonation exchange.
//
// With no -subject-token, the example runs a self-contained demo: it serves a
// tiny RFC 8693 token endpoint locally and performs both an impersonation and a
// delegation exchange against it.
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
	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer to discover the token endpoint")
	endpoint := flag.String("token-endpoint", "", "token endpoint (overrides discovery)")
	clientID := flag.String("client-id", "", "client id")
	clientSecret := flag.String("client-secret", "", "client secret")
	subjectToken := flag.String("subject-token", "", "the subject token to exchange (empty runs the self-contained demo)")
	subjectTokenType := flag.String("subject-token-type", token.TokenTypeAccessToken, "subject_token_type URI")
	actorToken := flag.String("actor-token", "", "optional actor token — its presence makes this a delegation exchange")
	actorTokenType := flag.String("actor-token-type", token.TokenTypeJWT, "actor_token_type URI (required when -actor-token is set)")
	audience := flag.String("audience", "", "optional target audience")
	resource := flag.String("resource", "", "optional target resource URI")
	post := flag.Bool("post", false, "use client_secret_post instead of client_secret_basic")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// endpoints (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *subjectToken == "" {
		runDemo()
		return
	}

	if *clientID == "" || *clientSecret == "" {
		fmt.Fprintln(os.Stderr, "-client-id and -client-secret are required")
		os.Exit(2)
	}

	// The context deadline bounds the whole call (discovery + exchange).
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := []token.Option{}
	if *insecureHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	if *post {
		opts = append(opts, token.WithClientAuth(token.ClientSecretPost))
	}
	if *actorToken != "" {
		opts = append(opts, token.WithActorToken(*actorToken, *actorTokenType))
	}
	if *audience != "" {
		opts = append(opts, token.WithAudience(*audience))
	}
	if *resource != "" {
		opts = append(opts, token.WithResource(*resource))
	}

	target := *endpoint
	if target == "" {
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "either -issuer or -token-endpoint is required")
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
		target = cfg.TokenEndpoint
	}

	resp, err := token.TokenExchange(ctx, target, *clientID, *clientSecret, *subjectToken, *subjectTokenType, opts...)
	if err != nil {
		var te *token.TokenError
		if errors.As(err, &te) {
			fmt.Fprintf(os.Stderr, "endpoint rejected the exchange (HTTP %d): %s\n", te.StatusCode, te.Code)
		} else {
			fmt.Fprintf(os.Stderr, "token exchange failed: %v\n", err)
		}
		os.Exit(1)
	}
	printResult(resp)
}

func printResult(resp *token.TokenResponse) {
	fmt.Printf("  access_token:      %s\n", resp.AccessToken)
	fmt.Printf("  issued_token_type: %s\n", resp.IssuedTokenType)
	fmt.Printf("  token_type:        %s\n", resp.TokenType)
	if resp.ExpiresIn > 0 {
		fmt.Printf("  expires_in:        %d\n", resp.ExpiresIn)
	}
	if resp.Scope != "" {
		fmt.Printf("  scope:             %s\n", resp.Scope)
	}
}

// runDemo serves a tiny RFC 8693 token endpoint locally and performs both an
// impersonation and a delegation exchange against it, so the example is runnable
// with no real provider or token.
func runDemo() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "demo-client" || secret != "demo-secret" {
			writeError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "malformed body")
			return
		}
		if r.PostFormValue("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			writeError(w, http.StatusBadRequest, "unsupported_grant_type", "only token-exchange is supported")
			return
		}
		if r.PostFormValue("subject_token") == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
			return
		}
		// A delegation exchange carries an actor token; reflect that in the scope
		// so the demo output distinguishes the two flows.
		scope := "https://api.example.com/read"
		if r.PostFormValue("actor_token") != "" {
			scope = "https://api.example.com/read https://api.example.com/act-on-behalf"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "issued-" + r.PostFormValue("subject_token"),
			"issued_token_type": token.TokenTypeAccessToken,
			"token_type":        "Bearer",
			"expires_in":        3600,
			"scope":             scope,
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Println("Self-contained demo — impersonation exchange (subject token only):")
	resp, err := token.TokenExchange(ctx, srv.URL, "demo-client", "demo-secret",
		"user-access-token", token.TokenTypeAccessToken,
		token.WithInsecureAllowHTTP(),
		token.WithAudience("https://api.example.com"),
		token.WithRequestedTokenType(token.TokenTypeAccessToken))
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo impersonation failed: %v\n", err)
		os.Exit(1)
	}
	printResult(resp)

	fmt.Println("\nSelf-contained demo — delegation exchange (subject + actor token):")
	resp, err = token.TokenExchange(ctx, srv.URL, "demo-client", "demo-secret",
		"user-access-token", token.TokenTypeAccessToken,
		token.WithInsecureAllowHTTP(),
		token.WithActorToken("service-jwt", token.TokenTypeJWT))
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo delegation failed: %v\n", err)
		os.Exit(1)
	}
	printResult(resp)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
