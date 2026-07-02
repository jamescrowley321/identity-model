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

// InvalidKeyError reports that a key failed parameter validation (JWKS-002,
// RFC 7517 §4). Kid identifies the offending key when present; Reason explains
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
)

func (e *ParseError) Is(target error) bool         { return target == ErrParse }
func (e *HTTPError) Is(target error) bool          { return target == ErrHTTPStatus }
func (e *HTTPSRequiredError) Is(target error) bool { return target == ErrHTTPSRequired }
func (e *EmptyKeySetError) Is(target error) bool   { return target == ErrEmptyKeySet }
func (e *KeyNotFoundError) Is(target error) bool   { return target == ErrKeyNotFound }
func (e *InvalidKeyError) Is(target error) bool    { return target == ErrInvalidKey }
