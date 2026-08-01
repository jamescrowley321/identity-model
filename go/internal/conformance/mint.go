package conformance

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ephemeralKeyBits is the size of throwaway signing keys minted for
// bad-signature vectors. 2048 matches the fixture key.
const ephemeralKeyBits = 2048

// timeClaims are minted relative to the vector's Options.Now so tokens carrying
// them stay fresh regardless of when the suite runs.
var timeClaims = map[string]struct{}{"exp": {}, "nbf": {}, "iat": {}}

// SigningKeyFromBytes parses the shared RSA private signing-key fixture.
func SigningKeyFromBytes(b []byte) (*jose.JSONWebKey, error) {
	var jk jose.JSONWebKey
	if err := jk.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return &jk, nil
}

// MintToken realises a minting TokenSpec into a compact JWS. Callers handle
// TokenSpec.Static (a committed fixture token) themselves; this function only
// mints from TokenSpec.Claims. now is the reference clock for time claims.
func MintToken(spec TokenSpec, fixtureKey *jose.JSONWebKey, now time.Time) (string, error) {
	alg := spec.Alg
	if alg == "" {
		alg = "RS256"
	}

	signingKey, err := signingKeyFor(spec, fixtureKey, alg)
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: signingKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("new signer: %w", err)
	}

	claims, err := resolveClaims(spec.Claims, now)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}
	return tok, nil
}

// signingKeyFor returns the JWK to sign with. go-jose emits the header kid from
// the key's KeyID, so the returned key's KeyID controls the header kid.
func signingKeyFor(spec TokenSpec, fixtureKey *jose.JSONWebKey, alg string) (*jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	switch spec.SigningKey {
	case "", "fixture":
		if fixtureKey == nil {
			return nil, fmt.Errorf("fixture signing key not loaded")
		}
		key = *fixtureKey // copy so a header_kid override never mutates the shared key
	case "ephemeral":
		priv, err := rsa.GenerateKey(rand.Reader, ephemeralKeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		key = jose.JSONWebKey{Key: priv, Algorithm: alg, Use: "sig"}
	default:
		return nil, fmt.Errorf("unknown signing_key %q", spec.SigningKey)
	}
	if spec.HeaderKid != "" {
		key.KeyID = spec.HeaderKid
	}
	return &key, nil
}

// resolveClaims copies the claim map, converting exp/nbf/iat duration strings
// into absolute NumericDate (seconds) relative to now.
func resolveClaims(in map[string]any, now time.Time) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if _, isTime := timeClaims[k]; !isTime {
			out[k] = v
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("claim %q must be a duration string, got %T", k, v)
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("claim %q duration %q: %w", k, s, err)
		}
		out[k] = now.Add(d).Unix()
	}
	return out, nil
}
