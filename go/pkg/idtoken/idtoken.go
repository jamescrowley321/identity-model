package idtoken

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// ValidateIDToken validates an OpenID Connect ID Token (OIDC Core §3.1.3.7 /
// §3.3.2.11). It runs the standard JWT validation via [jwt.Validate]
// (signature, iss, aud, iat and exp) — supply [WithClientID] so the aud check
// binds the token to the RP and [WithIssuer] for the OP issuer — then applies
// the ID-Token profile: required sub, the azp authorized-party rules, and the
// opt-in nonce / max_age / at_hash / c_hash bindings checked only when the
// corresponding option is supplied.
//
// It returns the validated [jwt.Claims] on success. Base-validation failures
// surface the jwt package's error types; profile failures surface a
// *[ProfileError] (matched by errors.Is against [ErrIDTokenProfile]).
func ValidateIDToken(ctx context.Context, rawToken string, keySet *jwks.JSONWebKeySet, opts ...Option) (*jwt.Claims, error) {
	cfg := newConfig(opts...)

	claims, err := jwt.Validate(ctx, rawToken, keySet, cfg.jwtOptions()...)
	if err != nil {
		return nil, err
	}

	// The signature verified over the protected header and payload, so both the
	// header alg and the decoded claims are now authenticated. Re-reading the
	// alg from the verified header (rather than an option) mirrors the reference
	// implementation: the hash for at_hash/c_hash MUST be the one the signature
	// was verified with, never an unauthenticated caller-supplied value.
	claimsMap, headerAlg, err := decodeVerified(rawToken)
	if err != nil {
		return nil, err
	}

	if err := validateProfile(claimsMap, headerAlg, cfg); err != nil {
		return nil, err
	}
	return claims, nil
}

// ValidateClaims applies the ID-Token profile rules to an already-decoded claim
// set, without any network or signature work. It assumes the JWT signature,
// iss, aud, iat and exp have ALREADY been verified (e.g. by [jwt.Validate]) and
// that the caller's client_id has been enforced as an aud member there.
//
// claims is the decoded claim set (as produced by json.Unmarshal into a
// map[string]any: JSON numbers are float64, arrays are []any). headerAlg is the
// verified alg of the ID Token's JOSE header, used to select the SHA-2 variant
// for at_hash/c_hash. It returns a *[ProfileError] on the first violation.
//
// This is the network-free entry point the cross-language conformance vectors
// (spec/conformance/id-token.json) drive; it is the Go analog of the reference
// validate_id_token_claims.
func ValidateClaims(claims map[string]any, headerAlg string, opts ...Option) error {
	return validateProfile(claims, headerAlg, newConfig(opts...))
}

// validateProfile is the shared core enforcing the ID-Token-specific rules, in
// the same order as the reference implementation so the first-reported reason
// matches across languages.
func validateProfile(claims map[string]any, headerAlg string, cfg *config) error {
	// §2 / §3.1.3.7 — sub is REQUIRED and must be a non-empty string.
	if sub, ok := claims["sub"].(string); !ok || sub == "" {
		return profileErr(ReasonMissingSub, "ID token is missing the required non-empty 'sub' claim")
	}

	// §3.1.3.7 steps 4-6 — authorized-party (azp) rules.
	if err := validateAZP(claims, cfg.clientID); err != nil {
		return err
	}

	// §3.1.3.7 step 11 — nonce binding (only when the caller supplied one).
	if cfg.nonceSet {
		tokenNonce, ok := claims["nonce"].(string)
		if !ok || !constantTimeEqual(tokenNonce, cfg.nonce) {
			return profileErr(ReasonNonceMismatch, "ID token 'nonce' claim does not match the expected value")
		}
	}

	// §3.1.3.7 step 12 — auth_time freshness (only when max_age was requested).
	if cfg.maxAgeSet {
		if err := validateAuthTime(claims, cfg); err != nil {
			return err
		}
	}

	// §3.3.2.11 — at_hash binding (only when an access token was supplied).
	if cfg.accessTokenSet {
		expected, err := leftHalfHash(cfg.accessToken, headerAlg)
		if err != nil {
			return err
		}
		if atHash, ok := claims["at_hash"].(string); !ok || !constantTimeEqual(atHash, expected) {
			return profileErr(ReasonAtHashMismatch, "ID token 'at_hash' claim does not match the access token")
		}
	}

	// §3.3.2.11 — c_hash binding (only when an authorization code was supplied).
	if cfg.codeSet {
		expected, err := leftHalfHash(cfg.code, headerAlg)
		if err != nil {
			return err
		}
		if cHash, ok := claims["c_hash"].(string); !ok || !constantTimeEqual(cHash, expected) {
			return profileErr(ReasonCHashMismatch, "ID token 'c_hash' claim does not match the authorization code")
		}
	}

	return nil
}

// validateAZP enforces §3.1.3.7 steps 4-6. A JSON null azp is treated as absent,
// matching the reference (claims.get("azp") is None).
func validateAZP(claims map[string]any, clientID string) error {
	audMultiElement := false
	if arr, ok := claims["aud"].([]any); ok && len(arr) > 1 {
		audMultiElement = true
	}

	azpRaw, azpPresent := claims["azp"]
	azpStr, _ := azpRaw.(string)
	azpFalsy := !azpPresent || azpRaw == nil || azpStr == ""

	// Step 4: with multiple audiences an azp claim MUST be present.
	if audMultiElement && azpFalsy {
		return profileErr(ReasonAZPRequiredMultiAud, "ID token with multiple audiences must contain an 'azp' claim")
	}

	// Step 6: when present, azp MUST identify this client.
	if azpPresent && azpRaw != nil && clientID != "" && azpStr != clientID {
		return profileErr(ReasonAZPMismatch, "ID token 'azp' claim does not match the configured client_id")
	}
	return nil
}

// validateAuthTime enforces §3.1.3.7 step 12. auth_time must be a JSON number
// (bool is excluded — a JSON bool decodes to Go bool, not float64) and recent
// enough. The comparison is done in float seconds to match the reference.
func validateAuthTime(claims map[string]any, cfg *config) error {
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		return profileErr(ReasonAuthTimeMissing, "ID token is missing the required numeric 'auth_time' claim for the max_age check")
	}
	nowSec := float64(cfg.now().UnixNano()) / 1e9
	if nowSec-authTime > cfg.maxAge.Seconds()+cfg.leeway.Seconds() {
		return profileErr(ReasonAuthTimeStale, "ID token 'auth_time' is older than the permitted max_age")
	}
	return nil
}

// leftHalfHash computes the OIDC §3.3.2.11 at_hash/c_hash of value under the ID
// Token's header alg: base64url-no-pad of the left-most half of H(value), where
// H is the SHA-2 variant implied by alg (RS/ES/PS/HS-256→SHA-256, -384→SHA-384,
// -512→SHA-512, EdDSA/Ed25519→SHA-512). value is an OAuth artifact (access token
// or authorization code) and thus ASCII, so its UTF-8 bytes are its ASCII octets.
//
// It fails closed: a missing alg is ReasonAlgRequired and an unmappable alg is
// ReasonUnsupportedAlg — an unknown alg is an error, never a skipped hash check.
func leftHalfHash(value, alg string) (string, error) {
	var digest []byte
	switch a := strings.TrimSpace(alg); {
	case a == "":
		return "", profileErr(ReasonAlgRequired, "ID token header 'alg' is required to validate at_hash/c_hash")
	case a == "EdDSA" || a == "Ed25519":
		// Assumes Ed25519 (SHA-512). Ed448 also carries alg "EdDSA" but hashes
		// with SHAKE256; it is unsupported here and fails closed on the mismatch.
		d := sha512.Sum512([]byte(value))
		digest = d[:]
	case strings.HasSuffix(a, "256"):
		d := sha256.Sum256([]byte(value))
		digest = d[:]
	case strings.HasSuffix(a, "384"):
		d := sha512.Sum384([]byte(value))
		digest = d[:]
	case strings.HasSuffix(a, "512"):
		d := sha512.Sum512([]byte(value))
		digest = d[:]
	default:
		return "", profileErr(ReasonUnsupportedAlg, fmt.Sprintf("unsupported ID token 'alg' %q for at_hash/c_hash validation", alg))
	}
	left := digest[:len(digest)/2]
	return base64.RawURLEncoding.EncodeToString(left), nil
}

// constantTimeEqual compares two ASCII strings in constant time, for the
// nonce/at_hash/c_hash bindings.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// decodeVerified splits an already-verified compact JWT and returns its payload
// as a map[string]any (numbers as float64, matching the conformance loader) plus
// the header alg. It is only called after [jwt.Validate] has authenticated the
// token, so the header and payload it re-decodes are trusted.
func decodeVerified(rawToken string) (map[string]any, string, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("idtoken: verified token is not a 3-part compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("idtoken: decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, "", fmt.Errorf("idtoken: parse header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("idtoken: decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, "", fmt.Errorf("idtoken: parse payload: %w", err)
	}
	return claims, header.Alg, nil
}
