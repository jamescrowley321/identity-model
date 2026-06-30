// Package jwks implements a JSON Web Key Set (JWKS) client: it fetches, caches
// and resolves the signing keys an OIDC provider publishes at its jwks_uri so a
// caller can verify JWT signatures without re-fetching keys on every request.
//
// The entry point is [FetchKeySet]:
//
//	set, err := jwks.FetchKeySet(ctx, cfg.JWKSURI)
//	if err != nil {
//		return err
//	}
//	key, ok := set.ResolveKey("rsa-sig-key")
//
// Behaviour is governed by the cross-language conformance contract in
// spec/conformance/jwks.json (test IDs JWKS-001..JWKS-007) and the capability
// definitions in spec/capabilities.md:
//
//   - The key set is fetched and parsed into typed [JSONWebKey] values, each
//     exposing kty/kid/use/alg plus the key-type material (RSA n/e, EC crv/x/y)
//     per RFC 7517 §4–§5.
//   - [JSONWebKeySet.ResolveKey] looks a key up by kid in memory (§4.5);
//     [JSONWebKeySet.ResolveKeyWithRefresh] forces one refresh and retries on a
//     miss before reporting key-not-found (handles key rotation).
//   - [JSONWebKeySet.ForceRefresh] invalidates and re-fetches the set after a
//     signature failure.
//   - Results are cached with a configurable TTL; a cache hit makes no network
//     request and concurrent fetches for the same URI are deduplicated.
//   - Transport failures, non-JSON bodies, invalid keys and empty key sets
//     surface as distinct, typed errors. Unknown extra parameters are
//     preserved in [JSONWebKey.Extra], not rejected.
//
// The functional-options surface ([WithCacheTTL], [WithHTTPClient],
// [WithTimeout], [WithInsecureAllowHTTP]) mirrors the discovery client.
//
// RFC / spec references: RFC 7517 (JWK), RFC 7518 (JWA).
package jwks
