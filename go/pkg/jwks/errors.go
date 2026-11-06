package jwks

import (
	"errors"
	"fmt"
)

// ParseError reports that the JWKS response body could not be decoded as a
// JSON Web Key Set (JWKS-007, RFC 7517 §5).
type ParseError struct {
	Err error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("jwks: parse response: %v", e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// HTTPError reports a non-2xx response from the jwks_uri endpoint.
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("jwks: unexpected HTTP status %d from %s", e.StatusCode, e.URL)
}

// HTTPSRequiredError reports that an http:// jwks_uri was used without
// [WithInsecureAllowHTTP].
type HTTPSRequiredError struct {
	URI string
}

func (e *HTTPSRequiredError) Error() string {
	return fmt.Sprintf("jwks: uri %q must use https (use WithInsecureAllowHTTP for development)", e.URI)
}

// EmptyKeySetError reports that the JWKS document contained no keys (JWKS-007,
// RFC 7517 §5: a key set with an empty or absent "keys" member yields no
// usable keys).
type EmptyKeySetError struct {
	URI string
}

func (e *EmptyKeySetError) Error() string {
	return fmt.Sprintf("jwks: key set from %s contains no keys", e.URI)
}

// KeyNotFoundError reports that no key matching Kid was present, even after a
// forced refresh (JWKS-004, RFC 7517 §4.5).
type KeyNotFoundError struct {
	Kid string
}

func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("jwks: no key found for kid %q", e.Kid)
}

// AmbiguousKeyError reports that a token with no kid could be verified by more
// than one key in the set (JWKS-009). With no kid, the set is narrowed to
// signing keys (use absent or "sig", RFC 7517 §4.2), then to keys whose alg is
// absent or equals the header alg (§4.4) and whose kty matches it, each step
// applied only when it leaves a key; Count keys were left. Kids lists the ids of those that have one. It is distinct from
// [KeyNotFoundError], which reports a kid that matches no key.
type AmbiguousKeyError struct {
	Alg   string
	Kids  []string
	Count int
}

func (e *AmbiguousKeyError) Error() string {
	return fmt.Sprintf("jwks: token has no kid and %d keys could verify alg %q %v", e.Count, e.Alg, e.Kids)
}

// KeyAlgorithmMismatchError reports that the key resolved for a token declares
// an alg (KeyAlg, RFC 7517 §4.4) other than the token header alg (Alg), so it
// is not used (JWKS-010). It applies whether the key was found by kid or
// selected without one, and is distinct from [KeyNotFoundError] and
// [AmbiguousKeyError].
type KeyAlgorithmMismatchError struct {
	Kid    string
	KeyAlg string
	Alg    string
}

func (e *KeyAlgorithmMismatchError) Error() string {
	return fmt.Sprintf("jwks: key %q declares alg %q, token alg is %q", e.Kid, e.KeyAlg, e.Alg)
}

// InvalidKeyError reports that a key failed parameter validation (JWKS-002,
// RFC 7517 §4). A fetch returns it only when no key in the set is usable
// (JWKS-008). Kid identifies the offending key when present; Reason explains
// the failure.
type InvalidKeyError struct {
	Kid    string
	Reason string
}

func (e *InvalidKeyError) Error() string {
	if e.Kid != "" {
		return fmt.Sprintf("jwks: invalid key %q: %s", e.Kid, e.Reason)
	}
	return fmt.Sprintf("jwks: invalid key: %s", e.Reason)
}

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrParse matches any [ParseError].
	ErrParse = errors.New("jwks: parse response")
	// ErrHTTPStatus matches any [HTTPError].
	ErrHTTPStatus = errors.New("jwks: unexpected HTTP status")
	// ErrHTTPSRequired matches any [HTTPSRequiredError].
	ErrHTTPSRequired = errors.New("jwks: https required")
	// ErrEmptyKeySet matches any [EmptyKeySetError].
	ErrEmptyKeySet = errors.New("jwks: empty key set")
	// ErrKeyNotFound matches any [KeyNotFoundError].
	ErrKeyNotFound = errors.New("jwks: key not found")
	// ErrInvalidKey matches any [InvalidKeyError].
	ErrInvalidKey = errors.New("jwks: invalid key")
	// ErrAmbiguousKey matches any [AmbiguousKeyError].
	ErrAmbiguousKey = errors.New("jwks: ambiguous key")
	// ErrKeyAlgorithmMismatch matches any [KeyAlgorithmMismatchError].
	ErrKeyAlgorithmMismatch = errors.New("jwks: key algorithm mismatch")
)

func (e *ParseError) Is(target error) bool         { return target == ErrParse }
func (e *HTTPError) Is(target error) bool          { return target == ErrHTTPStatus }
func (e *HTTPSRequiredError) Is(target error) bool { return target == ErrHTTPSRequired }
func (e *EmptyKeySetError) Is(target error) bool   { return target == ErrEmptyKeySet }
func (e *KeyNotFoundError) Is(target error) bool   { return target == ErrKeyNotFound }
func (e *InvalidKeyError) Is(target error) bool    { return target == ErrInvalidKey }
func (e *AmbiguousKeyError) Is(target error) bool  { return target == ErrAmbiguousKey }
func (e *KeyAlgorithmMismatchError) Is(target error) bool {
	return target == ErrKeyAlgorithmMismatch
}
