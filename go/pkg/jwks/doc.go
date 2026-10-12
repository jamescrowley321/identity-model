// Package jwks implements a JSON Web Key Set (JWKS) client: it fetches, caches
// and resolves the signing keys an OIDC provider publishes at its jwks_uri so a
// caller can verify JWT signatures without re-fetching keys on every request.
//
// A [Client] holds its options and owns its cache and kid-miss cooldown:
//
//	client, err := jwks.NewClient(jwks.WithMaxKeys(20))
//	if err != nil {
//		return err // a *ConfigError naming each invalid option
//	}
//	set, err := client.FetchKeySet(ctx, cfg.JWKSURI)
//	if err != nil {
//		return err
//	}
//	key, ok := set.ResolveKey("rsa-sig-key")
//
// The package-level [FetchKeySet] uses a client built from the defaults.
// Settings, defaults and ranges are those of spec/config.md; the package reads
// no environment.
//
// Behaviour is governed by the cross-language conformance contract in
// spec/vectors/jwks.json (test IDs JWKS-001..JWKS-010) and the capability
// definitions in spec/capabilities.md:
//
//   - The key set is fetched and parsed into typed [JSONWebKey] values, each
//     exposing kty/kid/use/alg plus the key-type material (RSA n/e, EC crv/x/y)
//     per RFC 7517 §4–§5.
//   - [JSONWebKeySet.ResolveKey] looks a key up by kid in memory (§4.5);
//     [JSONWebKeySet.ResolveKeyWithRefresh] forces one refresh and retries on a
//     miss before reporting key-not-found (handles key rotation).
//   - [JSONWebKeySet.ResolveSigningKey] resolves the key for a token header:
//     by kid when present; with no kid, the single key left after narrowing
//     the in-memory set by use, alg and kty, with no refresh, and a typed
//     [AmbiguousKeyError] when more than one remains (JWKS-009). A key that
//     declares an alg other than the header alg is a typed
//     [KeyAlgorithmMismatchError] either way (JWKS-010).
//   - [JSONWebKeySet.ForceRefresh] invalidates and re-fetches the set after a
//     signature failure.
//   - Results are cached for the response's Cache-Control max-age (clamped to
//     60 s – 24 h), else [WithCacheTTL]; no-store and no-cache are ignored
//     (#396). A cache hit makes no network request and concurrent fetches for
//     the same URI are deduplicated.
//   - A response over [WithMaxSize] bytes or with more than [WithMaxKeys] keys
//     is a [ParseError].
//   - Transport failures, non-JSON bodies, invalid keys and empty key sets
//     surface as distinct, typed errors. Unknown extra parameters are
//     preserved in [JSONWebKey.Extra], not rejected.
//
// The transport options ([WithTimeout], [WithRetryMaxAttempts],
// [WithRetryBaseDelay], [WithCABundle], [WithHTTPClient],
// [WithInsecureAllowHTTP]) mirror the discovery client.
//
// RFC / spec references: RFC 7517 (JWK), RFC 7518 (JWA).
package jwks
