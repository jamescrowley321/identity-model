package jwt

import (
	"errors"
	"fmt"
)

// MalformedTokenError reports that the raw token is not a well-formed compact
// JWS — wrong number of segments, undecodable header, or an unparsable claims
// body (RFC 7515 §3.1).
type MalformedTokenError struct {
	Reason string
}

func (e *MalformedTokenError) Error() string {
	return fmt.Sprintf("jwt: malformed token: %s", e.Reason)
}

// AlgNoneError reports that the token header declared the "none" algorithm,
// which is rejected unconditionally (JWT-003, RFC 7519 §7.2).
type AlgNoneError struct{}

func (e *AlgNoneError) Error() string {
	return "jwt: unsecured token with alg \"none\" is rejected"
}

// UnsupportedAlgorithmError reports that the header alg is not in the accepted
// set. Restricting algorithms to an asymmetric allowlist defeats algorithm
// confusion attacks (e.g. an HMAC token verified with a public key).
type UnsupportedAlgorithmError struct {
	Alg string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("jwt: unsupported or disallowed algorithm %q", e.Alg)
}

// SignatureError reports that the JWS signature did not verify against the
// resolved key (JWT-009, RFC 7515 §5.2).
type SignatureError struct {
	Err error
}

func (e *SignatureError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("jwt: signature verification failed: %v", e.Err)
	}
	return "jwt: signature verification failed"
}

func (e *SignatureError) Unwrap() error { return e.Err }

// KeyConversionError reports that a resolved JWK could not be converted into a
// usable public key for verification.
type KeyConversionError struct {
	Kid string
	Err error
}

func (e *KeyConversionError) Error() string {
	return fmt.Sprintf("jwt: convert key %q: %v", e.Kid, e.Err)
}

func (e *KeyConversionError) Unwrap() error { return e.Err }

// ClaimValidationError reports that a registered or required claim failed
// validation (JWT-002/004/005/006/007/008/012/013, RFC 7519 §4.1). Claim names
// the offending claim; Reason explains the failure.
type ClaimValidationError struct {
	Claim  string
	Reason string
}

func (e *ClaimValidationError) Error() string {
	return fmt.Sprintf("jwt: claim %q invalid: %s", e.Claim, e.Reason)
}

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrMalformedToken matches any [MalformedTokenError].
	ErrMalformedToken = errors.New("jwt: malformed token")
	// ErrAlgNone matches any [AlgNoneError].
	ErrAlgNone = errors.New("jwt: alg none rejected")
	// ErrUnsupportedAlgorithm matches any [UnsupportedAlgorithmError].
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")
	// ErrSignature matches any [SignatureError].
	ErrSignature = errors.New("jwt: signature verification failed")
	// ErrKeyConversion matches any [KeyConversionError].
	ErrKeyConversion = errors.New("jwt: key conversion failed")
	// ErrClaimValidation matches any [ClaimValidationError].
	ErrClaimValidation = errors.New("jwt: claim validation failed")
)

func (e *MalformedTokenError) Is(target error) bool       { return target == ErrMalformedToken }
func (e *AlgNoneError) Is(target error) bool              { return target == ErrAlgNone }
func (e *UnsupportedAlgorithmError) Is(target error) bool { return target == ErrUnsupportedAlgorithm }
func (e *SignatureError) Is(target error) bool            { return target == ErrSignature }
func (e *KeyConversionError) Is(target error) bool        { return target == ErrKeyConversion }
func (e *ClaimValidationError) Is(target error) bool      { return target == ErrClaimValidation }
