// Package discovery implements an OpenID Connect Discovery 1.0 client.
//
// It fetches the provider metadata document from
// {issuer}/.well-known/openid-configuration, validates it, and caches the
// parsed result.
//
// A [Client] holds its options and owns its cache:
//
//	client, err := discovery.NewClient(discovery.WithTimeout(10 * time.Second))
//	if err != nil {
//		return err // a *ConfigError naming each invalid option
//	}
//	cfg, err := client.FetchConfiguration(ctx, "https://accounts.example.com")
//	if err != nil {
//		return err
//	}
//	fmt.Println(cfg.TokenEndpoint)
//
// The package-level [FetchConfiguration] uses a client built from the
// defaults. Settings, defaults and ranges are those of spec/config.md; the
// package reads no environment.
//
// Behaviour is governed by the cross-language conformance contract in
// spec/vectors/discovery.json (test IDs DISC-001..DISC-010) and the
// capability definitions in spec/capabilities.md:
//
//   - The response MUST contain the required metadata fields issuer,
//     authorization_endpoint, token_endpoint, jwks_uri,
//     response_types_supported, subject_types_supported and
//     id_token_signing_alg_values_supported (OIDC Discovery 1.0 §3).
//   - The response issuer MUST exactly match the requested issuer (§4.3).
//   - Results are cached for the response's Cache-Control max-age (clamped to
//     60 s – 24 h), else [WithCacheTTL]; a no-store or no-cache response is not
//     cached. A cache hit makes no network request and concurrent fetches for
//     the same issuer are deduplicated.
//   - A 429, a 5xx or a transport error is retried with exponential backoff
//     ([WithRetryMaxAttempts], [WithRetryBaseDelay]).
//   - Transport failures, non-JSON bodies and missing required fields surface
//     as distinct, typed errors. Unknown extra fields are ignored, not
//     rejected.
//
// RFC / spec references: OpenID Connect Discovery 1.0 §3, §4.
package discovery
