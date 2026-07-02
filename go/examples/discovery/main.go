// Command discovery fetches and prints an OpenID Connect provider configuration
// for a given issuer URL.
//
// Usage:
//
//	go run ./examples/discovery -issuer https://accounts.google.com
//
// Against the local infra/ provider (node-oidc-provider over plain HTTP):
//
//	go run ./examples/discovery -issuer http://localhost:9000 -insecure-http
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

func main() {
	issuer := flag.String("issuer", "https://accounts.google.com", "OIDC issuer URL")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// issuer (development only)")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	flag.Parse()

	opts := []discovery.Option{discovery.WithTimeout(*timeout)}
	if *insecureHTTP {
		opts = append(opts, discovery.WithInsecureAllowHTTP())
	}

	cfg, err := discovery.FetchConfiguration(context.Background(), *issuer, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Issuer:                 %s\n", cfg.Issuer)
	fmt.Printf("Authorization endpoint: %s\n", cfg.AuthorizationEndpoint)
	fmt.Printf("Token endpoint:         %s\n", cfg.TokenEndpoint)
	fmt.Printf("UserInfo endpoint:      %s\n", cfg.UserInfoEndpoint)
	fmt.Printf("JWKS URI:               %s\n", cfg.JWKSURI)
	fmt.Printf("Response types:         %v\n", cfg.ResponseTypesSupported)
	fmt.Printf("Subject types:          %v\n", cfg.SubjectTypesSupported)
	fmt.Printf("ID token signing algs:  %v\n", cfg.IDTokenSigningAlgValuesSupported)
}
