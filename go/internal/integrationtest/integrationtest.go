// Package integrationtest centralizes provider configuration for the
// -tags=integration suites so the same tests run unchanged against the local
// docker compose providers (infra/: node-oidc-provider, IdentityServer) and
// cloud providers (Ory, Descope). Configuration follows the TEST_*
// environment convention shared with py-identity-model; the Makefile loads a
// per-provider profile from the repo-root .env.* files.
package integrationtest

import (
	"os"
	"strings"
)

const wellKnownSuffix = "/.well-known/openid-configuration"

// Default profile: the infra/ node-oidc-provider, so a bare
// `go test -tags=integration ./...` keeps working after
// `cd infra && docker compose up -d`.
const (
	defaultDiscoveryAddress = "http://localhost:9000" + wellKnownSuffix
	defaultClientID         = "test-client-credentials"
	defaultClientSecret     = "test-client-credentials-secret"
	defaultScope            = "api"
	defaultPublicClientID   = "test-pkce-public"
	defaultRedirectURI      = "http://localhost:8080/callback"
)

// Config selects the provider under test. With TEST_DISCO_ADDRESS unset the
// full node-oidc-provider default profile applies. Once it is set, every
// other field comes only from its own TEST_* variable so that a provider
// profile never inherits local-fixture values; tests requiring an unset
// field must skip.
type Config struct {
	DiscoveryAddress string // TEST_DISCO_ADDRESS: full discovery document URL
	Issuer           string // derived: DiscoveryAddress minus the well-known suffix
	JWKSURI          string // TEST_JWKS_ADDRESS: optional direct JWKS URL
	ClientID         string // TEST_CLIENT_ID: confidential client_credentials client
	ClientSecret     string // TEST_CLIENT_SECRET
	Scope            string // TEST_SCOPE: space-separated scopes for token requests
	PublicClientID   string // TEST_PKCE_PUBLIC_CLIENT_ID: public PKCE client
	RedirectURI      string // TEST_REDIRECT_URI: registered redirect for code flows
	AllowHTTP        bool   // derived: issuer is plain HTTP (local fixtures only)
}

// Load reads the provider profile from the environment.
func Load() Config {
	disco := os.Getenv("TEST_DISCO_ADDRESS")
	if disco == "" {
		return Config{
			DiscoveryAddress: defaultDiscoveryAddress,
			Issuer:           issuerFrom(defaultDiscoveryAddress),
			ClientID:         defaultClientID,
			ClientSecret:     defaultClientSecret,
			Scope:            defaultScope,
			PublicClientID:   defaultPublicClientID,
			RedirectURI:      defaultRedirectURI,
			AllowHTTP:        true,
		}
	}
	issuer := issuerFrom(disco)
	return Config{
		DiscoveryAddress: disco,
		Issuer:           issuer,
		JWKSURI:          os.Getenv("TEST_JWKS_ADDRESS"),
		ClientID:         os.Getenv("TEST_CLIENT_ID"),
		ClientSecret:     os.Getenv("TEST_CLIENT_SECRET"),
		Scope:            os.Getenv("TEST_SCOPE"),
		PublicClientID:   os.Getenv("TEST_PKCE_PUBLIC_CLIENT_ID"),
		RedirectURI:      os.Getenv("TEST_REDIRECT_URI"),
		AllowHTTP:        strings.HasPrefix(issuer, "http://"),
	}
}

// Scopes splits Scope for the packages' variadic WithScopes options.
func (c Config) Scopes() []string {
	return strings.Fields(c.Scope)
}

func issuerFrom(discoveryAddress string) string {
	issuer := strings.TrimSuffix(discoveryAddress, wellKnownSuffix)
	return strings.TrimSuffix(issuer, "/")
}
