// Command userinfo fetches an end-user's claims from the OpenID Connect
// UserInfo endpoint (OIDC Core 1.0 §5.3) using an access token.
//
// Against a real provider (the UserInfo endpoint discovered from the issuer):
//
//	go run ./examples/userinfo \
//	  -issuer https://accounts.example.com \
//	  -access-token "$ACCESS_TOKEN" \
//	  -expected-sub 248289761001
//
// With no -access-token, the example runs a self-contained demo: it serves a
// tiny UserInfo endpoint locally and fetches claims from it.
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
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer to discover the userinfo endpoint")
	endpoint := flag.String("userinfo-endpoint", "", "userinfo endpoint (overrides discovery)")
	accessToken := flag.String("access-token", "", "access token (empty runs the self-contained demo)")
	expectedSub := flag.String("expected-sub", "", "require the userinfo sub to equal this value")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// endpoints (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	if *accessToken == "" {
		runDemo()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := []userinfo.Option{userinfo.WithTimeout(*timeout)}
	if *insecureHTTP {
		opts = append(opts, userinfo.WithInsecureAllowHTTP())
	}
	if *expectedSub != "" {
		opts = append(opts, userinfo.WithSubjectValidation(*expectedSub))
	}

	target := *endpoint
	if target == "" {
		if *issuer == "" {
			fmt.Fprintln(os.Stderr, "either -issuer or -userinfo-endpoint is required")
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
		target = cfg.UserInfoEndpoint
		if target == "" {
			fmt.Fprintln(os.Stderr, "provider advertises no userinfo_endpoint")
			os.Exit(1)
		}
	}

	resp, err := userinfo.Fetch(ctx, target, *accessToken, opts...)
	if err != nil {
		var ue *userinfo.UserInfoError
		if errors.As(err, &ue) {
			fmt.Fprintf(os.Stderr, "userinfo rejected (HTTP %d): %s\n", ue.StatusCode, ue.WWWAuthenticate)
		} else {
			fmt.Fprintf(os.Stderr, "userinfo failed: %v\n", err)
		}
		os.Exit(1)
	}
	printClaims(resp)
}

// runDemo serves a tiny UserInfo endpoint locally and fetches claims from it,
// so the example is runnable with no real provider or token.
func runDemo() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-token" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sub": "248289761001",
			"name": "Jane Doe",
			"preferred_username": "j.doe",
			"email": "janedoe@example.com",
			"email_verified": true,
			"department": "Engineering"
		}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := userinfo.Fetch(ctx, srv.URL, "demo-token",
		userinfo.WithInsecureAllowHTTP(),
		userinfo.WithSubjectValidation("248289761001"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo fetch failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Self-contained demo — subject validation passed.")
	printClaims(resp)
}

func printClaims(resp *userinfo.UserInfoResponse) {
	fmt.Printf("sub:   %s\n", resp.Sub)
	fmt.Printf("name:  %s\n", resp.Name)
	fmt.Printf("email: %s\n", resp.Email)
	fmt.Println("all claims:")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp.Claims())
}
