// Command pkce demonstrates the PKCE pieces of the authorization code flow
// (RFC 7636): generating a code verifier, deriving the S256 challenge, building
// the authorization request URL, and exchanging the returned code with the
// verifier.
//
// With no -token-endpoint the example prints the generated verifier/challenge
// and a sample authorization URL. Given a -token-endpoint, -client-id, -code
// and -redirect-uri (and the verifier produced earlier via -verifier), it
// performs the token exchange.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/token"
)

func main() {
	authzEndpoint := flag.String("authorize-endpoint", "https://accounts.example.com/authorize", "authorization endpoint for the sample URL")
	tokenEndpoint := flag.String("token-endpoint", "", "token endpoint (when set, exchanges -code)")
	clientID := flag.String("client-id", "example-client", "client ID")
	redirectURI := flag.String("redirect-uri", "http://localhost:8080/callback", "redirect URI")
	scopes := flag.String("scopes", "openid profile", "space-separated scopes for the authorization URL")
	code := flag.String("code", "", "authorization code to exchange")
	verifier := flag.String("verifier", "", "code verifier (generated if empty)")
	insecureHTTP := flag.Bool("insecure-http", false, "allow http:// token endpoint (development only)")
	timeout := flag.Duration("timeout", 15*time.Second, "request timeout")
	flag.Parse()

	// Step 1: obtain a code verifier and its S256 challenge.
	v := *verifier
	if v == "" {
		gen, err := token.GenerateCodeVerifier()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate verifier: %v\n", err)
			os.Exit(1)
		}
		v = gen
	}
	challenge := token.S256Challenge(v)
	fmt.Printf("code_verifier=%s\ncode_challenge=%s\ncode_challenge_method=%s\n", v, challenge, token.ChallengeMethodS256)

	// Step 2: build the authorization request URL the user agent would visit.
	authURL := buildAuthorizeURL(*authzEndpoint, *clientID, *redirectURI, *scopes, challenge)
	fmt.Printf("authorize_url=%s\n", authURL)

	// Step 3 (optional): exchange the returned code with the verifier.
	if *tokenEndpoint == "" || *code == "" {
		fmt.Println("\n(no -token-endpoint/-code supplied; skipping exchange)")
		return
	}

	opts := []token.Option{token.WithCodeVerifier(v), token.WithTimeout(*timeout)}
	if *insecureHTTP {
		opts = append(opts, token.WithInsecureAllowHTTP())
	}
	resp, err := token.AuthorizationCode(context.Background(), *tokenEndpoint, *clientID, *code, *redirectURI, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exchange failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\naccess_token=%s\ntoken_type=%s\nid_token=%s\n", resp.AccessToken, resp.TokenType, resp.IDToken)
}

// buildAuthorizeURL assembles an RFC 6749 §4.1.1 authorization request carrying
// the PKCE S256 challenge (RFC 7636 §4.3).
func buildAuthorizeURL(endpoint, clientID, redirectURI, scopes, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scopes)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", token.ChallengeMethodS256)
	sep := "?"
	if u, err := url.Parse(endpoint); err == nil && u.RawQuery != "" {
		sep = "&"
	}
	return endpoint + sep + q.Encode()
}
