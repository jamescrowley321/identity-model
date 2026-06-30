package jwt

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// joseHeader is the subset of the JWS protected header this validator inspects
// before any cryptographic work (RFC 7515 §4.1).
type joseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Validate verifies the signature and claims of a compact-serialized JWT and
// returns its typed [Claims].
//
// The flow is: parse the compact JWS, reject the "none" algorithm before any
// crypto (JWT-003), confirm the header alg is in the allowlist (defeating
// algorithm-confusion attacks), resolve the signing key from keySet by the
// header kid — forcing one JWKS refresh on a miss (JWT-010) — verify the
// signature (JWT-001/009), then validate the registered and configured claims
// (JWT-002/004/005/006/007/008/011/012/013).
//
// Behaviour is configured with the With* options; see [Option].
func Validate(ctx context.Context, rawToken string, keySet *jwks.JSONWebKeySet, opts ...Option) (*Claims, error) {
	cfg := newConfig(opts...)

	if keySet == nil {
		return nil, &MalformedTokenError{Reason: "nil key set"}
	}

	token := strings.TrimSpace(rawToken)
	header, err := parseHeader(token)
	if err != nil {
		return nil, err
	}

	// JWT-003: reject the unsecured "none" algorithm unconditionally, before any
	// key resolution or signature work (RFC 7519 §7.2).
	if strings.EqualFold(header.Alg, "none") {
		return nil, &AlgNoneError{}
	}
	if header.Alg == "" {
		return nil, &MalformedTokenError{Reason: "header is missing the \"alg\" parameter"}
	}
	if !algAllowed(header.Alg, cfg.allowedAlgs) {
		return nil, &UnsupportedAlgorithmError{Alg: header.Alg}
	}

	// JWT-001/010: resolve the verification key by kid, forcing one JWKS refresh
	// and retry if the kid is not cached (RFC 7515 §4.1, RFC 7517 §4.5). A
	// genuine miss surfaces the descriptive jwks key-not-found error.
	key, err := keySet.ResolveKeyWithRefresh(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	pub, err := toPublicKey(key)
	if err != nil {
		return nil, &KeyConversionError{Kid: header.Kid, Err: err}
	}

	// JWT-001/009: parse and verify the signature. ParseSigned re-enforces the
	// algorithm allowlist as a second line of defence against alg confusion.
	jws, err := jose.ParseSigned(token, toSignatureAlgorithms(cfg.allowedAlgs))
	if err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("parse compact JWS: %v", err)}
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, &SignatureError{Err: err}
	}

	claims, err := parseClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := claims.validate(cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

// parseHeader decodes the protected header of a compact JWS without verifying
// it, so the algorithm and kid can be inspected first (JWT-003).
func parseHeader(token string) (*joseHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("compact JWS must have 3 segments, got %d", len(parts))}
	}
	if parts[0] == "" {
		return nil, &MalformedTokenError{Reason: "empty header segment"}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("decode header: %v", err)}
	}
	var h joseHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, &MalformedTokenError{Reason: fmt.Sprintf("parse header JSON: %v", err)}
	}
	return &h, nil
}

// toPublicKey converts a jwks.JSONWebKey into a crypto.PublicKey by re-encoding
// its standard JWK parameters and decoding them through go-jose's vetted JWK
// parser, reusing its base64url and curve handling.
func toPublicKey(k *jwks.JSONWebKey) (crypto.PublicKey, error) {
	fields := map[string]string{"kty": k.Kty}
	for name, val := range map[string]string{
		"kid": k.Kid, "use": k.Use, "alg": k.Alg,
		"n": k.N, "e": k.E,
		"crv": k.Crv, "x": k.X, "y": k.Y,
	} {
		if val != "" {
			fields[name] = val
		}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encode jwk: %w", err)
	}
	var jk jose.JSONWebKey
	if err := jk.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("decode jwk: %w", err)
	}
	if jk.Key == nil {
		return nil, fmt.Errorf("jwk produced no key material")
	}
	return jk.Key, nil
}

// algAllowed reports whether alg is in the configured allowlist.
func algAllowed(alg string, allowed []string) bool {
	for _, a := range allowed {
		if a == alg {
			return true
		}
	}
	return false
}

// toSignatureAlgorithms converts the allowlist into go-jose types, dropping the
// unsecured "none" algorithm which is never accepted (JWT-003).
func toSignatureAlgorithms(algs []string) []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(algs))
	for _, a := range algs {
		if a == "" || strings.EqualFold(a, "none") {
			continue
		}
		out = append(out, jose.SignatureAlgorithm(a))
	}
	return out
}
