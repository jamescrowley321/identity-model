// Command jwks fetches a JSON Web Key Set and resolves a key by its kid.
//
// Usage:
//
//	go run ./examples/jwks -jwks-uri https://www.googleapis.com/oauth2/v3/certs
//	go run ./examples/jwks -jwks-uri https://www.googleapis.com/oauth2/v3/certs -kid <kid>
//
// Against the local infra/ provider (node-oidc-provider over plain HTTP):
//
//	go run ./examples/jwks -jwks-uri http://localhost:9000/jwks -insecure-http
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

func main() {
	jwksURI := flag.String("jwks-uri", "https://www.googleapis.com/oauth2/v3/certs", "JWKS URI")
	kid := flag.String("kid", "", "kid to resolve (defaults to the first key)")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// jwks_uri (development only)")
	timeout := flag.Duration("timeout", 10*time.Second, "request timeout")
	flag.Parse()

	opts := []jwks.Option{jwks.WithTimeout(*timeout)}
	if *insecureHTTP {
		opts = append(opts, jwks.WithInsecureAllowHTTP())
	}

	set, err := jwks.FetchKeySet(context.Background(), *jwksURI, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch jwks failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Fetched %d key(s) from %s:\n", len(set.Keys), *jwksURI)
	for _, k := range set.Keys {
		fmt.Printf("  kid=%-24q kty=%-4s use=%-3s alg=%s\n", k.Kid, k.Kty, k.Use, k.Alg)
	}

	var key *jwks.JSONWebKey
	switch {
	case *kid != "":
		k, ok := set.ResolveKey(*kid)
		if !ok {
			fmt.Fprintf(os.Stderr, "\nno key found for kid %q\n", *kid)
			os.Exit(1)
		}
		key = k
	case len(set.Keys) > 0:
		// No -kid given: demonstrate against the first key directly rather than
		// resolving by an empty kid, which is ambiguous when several keys omit
		// the kid parameter.
		first := set.Keys[0]
		key = &first
	default:
		fmt.Fprintln(os.Stderr, "\nkey set is empty")
		os.Exit(1)
	}
	fmt.Printf("\nResolved key by kid %q: kty=%s alg=%s\n", key.Kid, key.Kty, key.Alg)
}
