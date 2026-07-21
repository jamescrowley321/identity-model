package introspection

import (
	"errors"
	"fmt"
)

// IntrospectionError is a typed OAuth 2.0 error returned by the introspection
// endpoint (RFC 7662 §2.3). It is produced when the endpoint replies with a
// non-2xx status carrying a recognised OAuth error body — most commonly an
// HTTP 401 invalid_client when the introspecting client fails authentication.
type IntrospectionError struct {
	// Code is the RFC 6749 §5.2 "error" code, e.g. "invalid_client".
	Code string `json:"error"`
	// ErrorDescription is the human-readable "error_description", if present.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is the "error_uri" pointing at documentation, if present.
	ErrorURI string `json:"error_uri,omitempty"`
	// StatusCode is the HTTP status of the error response.
	StatusCode int `json:"-"`
}

func (e *IntrospectionError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("introspection: endpoint error %q: %s (HTTP %d)", e.Code, e.ErrorDescription, e.StatusCode)
	}
	return fmt.Sprintf("introspection: endpoint error %q (HTTP %d)", e.Code, e.StatusCode)
}

// RequestError reports a transport-level failure, a malformed response, or a
// non-2xx response that did not carry a recognisable OAuth error body. Op names
// the failing step.
type RequestError struct {
	Op         string
	StatusCode int
	Err        error
}

func (e *RequestError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("introspection: %s (HTTP %d): %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("introspection: %s: %v", e.Op, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrIntrospectionResponse matches any [IntrospectionError] (an OAuth error
	// response from the introspection endpoint).
	ErrIntrospectionResponse = errors.New("introspection: endpoint error response")
	// ErrRequest matches any [RequestError] (transport or decode failure).
	ErrRequest = errors.New("introspection: request failed")
)

func (e *IntrospectionError) Is(target error) bool { return target == ErrIntrospectionResponse }
func (e *RequestError) Is(target error) bool       { return target == ErrRequest }
