package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE code challenge methods (RFC 7636 §4.3).
const (
	// ChallengeMethodS256 is the SHA-256 transform, which all clients capable of
	// it MUST use (RFC 7636 §4.2).
	ChallengeMethodS256 = "S256"
	// ChallengeMethodPlain is the no-op transform (RFC 7636 §4.4). Prefer S256.
	ChallengeMethodPlain = "plain"
)

const (
	// codeVerifierBytes is the entropy of a generated verifier. 32 bytes encode
	// to 43 base64url characters with no padding — the RFC 7636 §4.1 minimum.
	codeVerifierBytes = 32
	// minCodeVerifierLength and maxCodeVerifierLength bound a valid verifier
	// (RFC 7636 §4.1).
	minCodeVerifierLength = 43
	maxCodeVerifierLength = 128
)

// GenerateCodeVerifier returns a cryptographically random PKCE code verifier of
// 43 characters drawn from the unreserved set, using crypto/rand
// (RFC 7636 §4.1). The base64url alphabet ([A-Za-z0-9-_]) is a subset of the
// RFC's unreserved set [A-Za-z0-9-._~], so the result is always valid.
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, codeVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token: generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// S256Challenge computes the PKCE "S256" code challenge for verifier as
// BASE64URL-ENCODE(SHA256(ASCII(verifier))) (RFC 7636 §4.2).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validCodeVerifier reports whether v satisfies the RFC 7636 §4.1 length and
// charset rules: 43-128 characters, each from the unreserved set
// [A-Za-z0-9-._~].
func validCodeVerifier(v string) bool {
	if len(v) < minCodeVerifierLength || len(v) > maxCodeVerifierLength {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
