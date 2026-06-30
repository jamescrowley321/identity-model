package discovery

import (
	"errors"
	"fmt"
	"strings"
)

// MissingFieldsError reports required metadata fields absent from a discovery
// document (DISC-008). Fields lists the missing JSON field names in spec order.
type MissingFieldsError struct {
	Fields []string
}

func (e *MissingFieldsError) Error() string {
	return fmt.Sprintf("discovery: missing required field(s): %s", strings.Join(e.Fields, ", "))
}

// IssuerMismatchError reports that the issuer in the discovery document differs
// from the requested issuer (DISC-003, OIDC Discovery 1.0 §4.3).
type IssuerMismatchError struct {
	Requested string
	Returned  string
}

func (e *IssuerMismatchError) Error() string {
	return fmt.Sprintf("discovery: issuer mismatch: requested %q but document declares %q", e.Requested, e.Returned)
}

// HTTPError reports a non-2xx response from the discovery endpoint (DISC-006).
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("discovery: unexpected HTTP status %d from %s", e.StatusCode, e.URL)
}

// ParseError reports that the discovery response body could not be decoded as
// JSON (DISC-007).
type ParseError struct {
	Err error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("discovery: parse response: %v", e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// HTTPSRequiredError reports that an http:// issuer was used without
// [WithInsecureAllowHTTP] (DISC-010).
type HTTPSRequiredError struct {
	Issuer string
}

func (e *HTTPSRequiredError) Error() string {
	return fmt.Sprintf("discovery: issuer %q must use https (use WithInsecureAllowHTTP for development)", e.Issuer)
}

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrMissingFields matches any [MissingFieldsError].
	ErrMissingFields = errors.New("discovery: missing required field(s)")
	// ErrIssuerMismatch matches any [IssuerMismatchError].
	ErrIssuerMismatch = errors.New("discovery: issuer mismatch")
	// ErrHTTPStatus matches any [HTTPError].
	ErrHTTPStatus = errors.New("discovery: unexpected HTTP status")
	// ErrParse matches any [ParseError].
	ErrParse = errors.New("discovery: parse response")
	// ErrHTTPSRequired matches any [HTTPSRequiredError].
	ErrHTTPSRequired = errors.New("discovery: https required")
)

func (e *MissingFieldsError) Is(target error) bool  { return target == ErrMissingFields }
func (e *IssuerMismatchError) Is(target error) bool { return target == ErrIssuerMismatch }
func (e *HTTPError) Is(target error) bool           { return target == ErrHTTPStatus }
func (e *ParseError) Is(target error) bool          { return target == ErrParse }
func (e *HTTPSRequiredError) Is(target error) bool  { return target == ErrHTTPSRequired }
