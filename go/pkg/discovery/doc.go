// Package discovery implements an OpenID Connect Discovery 1.0 client.
//
// It fetches the provider metadata document from
// {issuer}/.well-known/openid-configuration, validates it, and caches the
// parsed result with a configurable TTL.
//
// The entry point is [FetchConfiguration]:
//
//	cfg, err := discovery.FetchConfiguration(ctx, "https://accounts.example.com")
//	if err != nil {
//		return err
//	}
//	fmt.Println(cfg.TokenEndpoint)
//
// Behaviour is governed by the cross-language conformance contract in
// spec/conformance/discovery.json (test IDs DISC-001..DISC-010) and the
// capability definitions in spec/capabilities.md:
//
//   - The response MUST contain the required metadata fields issuer,
//     authorization_endpoint, token_endpoint, jwks_uri,
//     response_types_supported, subject_types_supported and
//     id_token_signing_alg_values_supported (OIDC Discovery 1.0 §3).
//   - The response issuer MUST exactly match the requested issuer (§4.3).
//   - Results are cached with a configurable TTL; a cache hit makes no network
//     request and concurrent fetches for the same issuer are deduplicated.
//   - Transport failures, non-JSON bodies and missing required fields surface
//     as distinct, typed errors. Unknown extra fields are ignored, not
//     rejected.
//
// RFC / spec references: OpenID Connect Discovery 1.0 §3, §4.
package discovery
