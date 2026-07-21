// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession (DPoP,
// RFC 9449), which binds an access token to a client-held key pair so a stolen
// token cannot be replayed by an attacker who does not possess the private key
// (sender-constrained tokens, without mTLS).
//
// The building blocks:
//
//   - [Key] is a DPoP key pair. [GenerateKey] creates one for [ES256] (EC P-256)
//     or [RS256] (RSA 2048), and [KeyFromJWK]/[KeyFromPEM] plus
//     [Key.MarshalPrivateJWK]/[Key.MarshalPKCS8PEM] persist and reload one so it
//     survives restarts and can be rotated without invalidating already-issued
//     bound tokens (RFC 9449 §4.1).
//   - [Key.Proof] builds and signs a DPoP proof JWT for a request
//     (typ=dpop+jwt, embedded public jwk, jti/htm/htu/iat claims; RFC 9449 §4.2).
//     [WithAth] adds the ath claim for resource requests (RFC 9449 §7) and
//     [WithNonce] the nonce claim after a challenge (RFC 9449 §8). [Key.Thumbprint]
//     returns the RFC 7638 thumbprint an authorization server binds to via
//     cnf.jkt (RFC 9449 §6).
//   - [Transport] is an [net/http.RoundTripper] that attaches a proof to every
//     request and transparently handles the use_dpop_nonce retry. In resource
//     mode ([WithAccessToken]) it also sends the token with the DPoP
//     authorization scheme — Authorization: DPoP <token>, not Bearer.
//   - [VerifyProof] validates a proof on the resource-server side (RFC 9449 §4.3).
//
// Example — acquire a DPoP-bound token, then call a protected resource:
//
//	key, _ := dpop.GenerateKey(dpop.ES256)
//
//	// Token request: the proof travels in the DPoP header (no ath).
//	tokenClient := &http.Client{Transport: dpop.NewTransport(key)}
//	// ... POST to the token endpoint with tokenClient; the response is
//	// token_type=DPoP with a cnf.jkt equal to key.Thumbprint().
//
//	// Resource request: present the token with the DPoP scheme and an
//	// ath-bearing proof.
//	rsClient := &http.Client{Transport: dpop.NewTransport(key, dpop.WithAccessToken(accessToken))}
//	resp, _ := rsClient.Get("https://resource.example.com/protectedresource")
//
// The conformance suite for this package is spec/conformance/dpop.json
// (DPOP-001..008).
package dpop
