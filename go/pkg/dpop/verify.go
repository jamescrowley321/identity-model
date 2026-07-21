package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// asymmetricSigAlgs is the DPoP proof-verification allowlist: the EC and RSA JWS
// algorithms whose keys the embedded-jwk check below accepts. Symmetric
// algorithms (HS*) and the unsecured "none" are absent, so [jose.ParseSigned]
// rejects a proof that claims one before any other check (RFC 9449 §4.2 forbids
// symmetric algorithms).
var asymmetricSigAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
}

// defaultMaxIATAge bounds how far a proof's iat may be from now during
// verification (RFC 9449 §4.3 requires iat within an acceptable window).
const defaultMaxIATAge = 60 * time.Second

// Proof is a verified DPoP proof (RFC 9449 §4.2): its header parameters, payload
// claims, and the RFC 7638 thumbprint of the signing key. A resource server
// compares Thumbprint against the bound token's cnf.jkt (RFC 9449 §6).
type Proof struct {
	Typ        string
	Alg        string
	JWK        jose.JSONWebKey
	Thumbprint string

	JTI   string
	HTM   string
	HTU   string
	IAT   int64
	Ath   string
	Nonce string
}

// verifyConfig holds resolved [VerifyOption] settings.
type verifyConfig struct {
	maxIATAge     time.Duration
	now           func() time.Time
	expectAth     string
	haveExpectAth bool
	expectNonce   string
	haveNonce     bool
}

// VerifyOption customises proof verification.
type VerifyOption func(*verifyConfig)

// WithMaxIATAge sets how far a proof's iat may be from the current time before
// it is rejected. The default is 60s.
func WithMaxIATAge(d time.Duration) VerifyOption {
	return func(c *verifyConfig) { c.maxIATAge = d }
}

// WithNow overrides the verification clock (test seam).
func WithNow(now func() time.Time) VerifyOption {
	return func(c *verifyConfig) { c.now = now }
}

// WithExpectedAth requires the proof's ath claim to equal Ath(accessToken),
// binding a resource-request proof to the presented token (RFC 9449 §7).
func WithExpectedAth(accessToken string) VerifyOption {
	return func(c *verifyConfig) {
		c.expectAth = Ath(accessToken)
		c.haveExpectAth = true
	}
}

// WithExpectedNonce requires the proof's nonce claim to equal nonce
// (RFC 9449 §8).
func WithExpectedNonce(nonce string) VerifyOption {
	return func(c *verifyConfig) {
		c.expectNonce = nonce
		c.haveNonce = true
	}
}

// VerifyProof validates a DPoP proof JWT for a request whose method is
// expectedHTM and whose URI is expectedHTU (RFC 9449 §4.3). It rejects a proof
// signed with a symmetric or "none" algorithm, one missing the embedded public
// jwk, one whose signature does not verify against that jwk, one that is not
// typ=dpop+jwt, one missing a required claim, and one whose htm or htu does not
// match the request. On success it returns the parsed [Proof]; on failure a
// [VerificationError] naming the offending field.
//
// VerifyProof does not perform replay detection: RFC 9449 §4.3 expects the
// server to reject a proof whose jti has already been seen within the iat
// window. That is the caller's responsibility — dedupe on the returned
// [Proof.JTI] against a short-lived store.
func VerifyProof(proof, expectedHTM, expectedHTU string, opts ...VerifyOption) (*Proof, error) {
	cfg := &verifyConfig{maxIATAge: defaultMaxIATAge, now: time.Now}
	for _, opt := range opts {
		opt(cfg)
	}

	jws, err := jose.ParseSigned(proof, asymmetricSigAlgs)
	if err != nil {
		return nil, &VerificationError{Field: "alg", Reason: "not a DPoP proof signed with a supported asymmetric algorithm: " + err.Error()}
	}
	if len(jws.Signatures) != 1 {
		return nil, &VerificationError{Field: "signature", Reason: "a DPoP proof must carry exactly one signature"}
	}
	sig := jws.Signatures[0]

	// The public key MUST be embedded in the header (RFC 9449 §4.2). Reject a
	// missing jwk or one carrying private material or a non-asymmetric key.
	jwk := sig.Header.JSONWebKey
	if jwk == nil {
		return nil, &VerificationError{Field: "jwk", Reason: "proof header is missing the embedded jwk"}
	}
	if !jwk.IsPublic() {
		return nil, &VerificationError{Field: "jwk", Reason: "embedded jwk must contain only the public key"}
	}
	switch jwk.Key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
	default:
		return nil, &VerificationError{Field: "jwk", Reason: "embedded jwk is not an asymmetric key"}
	}

	// typ MUST be dpop+jwt (RFC 9449 §4.2), guarding against a plain JWT (e.g. an
	// access token) being replayed as a proof.
	if typ, _ := sig.Header.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return nil, &VerificationError{Field: "typ", Reason: `header typ must be "dpop+jwt"`}
	}

	// Verify the signature against the embedded key: this is the proof of
	// possession (RFC 9449 §4.3).
	payload, err := jws.Verify(jwk)
	if err != nil {
		return nil, &VerificationError{Field: "signature", Reason: err.Error()}
	}

	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, &VerificationError{Field: "payload", Reason: "proof payload is not valid JSON: " + err.Error()}
	}

	if claims.Jti == "" {
		return nil, &VerificationError{Field: "jti", Reason: "missing required jti claim"}
	}
	if claims.Htm != expectedHTM {
		return nil, &VerificationError{Field: "htm", Reason: "proof htm does not match the request method"}
	}
	wantHTU, err := normalizeHTU(expectedHTU)
	if err != nil {
		return nil, &VerificationError{Field: "htu", Reason: "invalid expected request URI: " + err.Error()}
	}
	if claims.Htu != wantHTU {
		return nil, &VerificationError{Field: "htu", Reason: "proof htu does not match the request URI"}
	}
	if claims.Iat == 0 {
		return nil, &VerificationError{Field: "iat", Reason: "missing required iat claim"}
	}
	age := cfg.now().Sub(time.Unix(claims.Iat, 0))
	if age > cfg.maxIATAge || age < -cfg.maxIATAge {
		return nil, &VerificationError{Field: "iat", Reason: "proof iat is outside the acceptable window"}
	}
	if cfg.haveExpectAth && claims.Ath != cfg.expectAth {
		return nil, &VerificationError{Field: "ath", Reason: "proof ath does not match the access token hash"}
	}
	if cfg.haveNonce && claims.Nonce != cfg.expectNonce {
		return nil, &VerificationError{Field: "nonce", Reason: "proof nonce does not match the expected nonce"}
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, &VerificationError{Field: "jwk", Reason: "cannot compute thumbprint: " + err.Error()}
	}
	typ, _ := sig.Header.ExtraHeaders[jose.HeaderType].(string)
	return &Proof{
		Typ:        typ,
		Alg:        sig.Header.Algorithm,
		JWK:        *jwk,
		Thumbprint: base64.RawURLEncoding.EncodeToString(tp),
		JTI:        claims.Jti,
		HTM:        claims.Htm,
		HTU:        claims.Htu,
		IAT:        claims.Iat,
		Ath:        claims.Ath,
		Nonce:      claims.Nonce,
	}, nil
}
