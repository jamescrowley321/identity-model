package dpop

import (
	"errors"
	"fmt"
)

// UnsupportedAlgorithmError reports a request to generate, load, or use a DPoP
// key with an algorithm this package does not support. DPoP proofs MUST use an
// asymmetric algorithm (RFC 9449 §4.2); symmetric algorithms such as HS256 and
// the unsecured "none" are never accepted.
type UnsupportedAlgorithmError struct {
	Alg string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("dpop: unsupported algorithm %q (want ES256 or RS256)", e.Alg)
}

// VerificationError reports that a DPoP proof failed validation on a resource
// server (RFC 9449 §4.3). Field names the offending proof member (e.g. "htm",
// "htu", "typ", "jwk", "iat", "ath", "nonce", "signature", "alg") so a caller
// can distinguish a method/URI mismatch from a signature or structural failure.
type VerificationError struct {
	Field  string
	Reason string
}

func (e *VerificationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("dpop: proof verification failed for %q: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("dpop: proof verification failed: %s", e.Reason)
}

// KeyError reports a failure loading, parsing, or serializing a DPoP key. Op
// names the failing step.
type KeyError struct {
	Op  string
	Err error
}

func (e *KeyError) Error() string { return fmt.Sprintf("dpop: %s: %v", e.Op, e.Err) }
func (e *KeyError) Unwrap() error { return e.Err }

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrUnsupportedAlgorithm matches any [UnsupportedAlgorithmError].
	ErrUnsupportedAlgorithm = errors.New("dpop: unsupported algorithm")
	// ErrVerification matches any [VerificationError] (a rejected proof).
	ErrVerification = errors.New("dpop: proof verification failed")
	// ErrKey matches any [KeyError] (key load/parse/serialize failure).
	ErrKey = errors.New("dpop: key error")
)

func (e *UnsupportedAlgorithmError) Is(target error) bool {
	return target == ErrUnsupportedAlgorithm
}
func (e *VerificationError) Is(target error) bool { return target == ErrVerification }
func (e *KeyError) Is(target error) bool          { return target == ErrKey }
