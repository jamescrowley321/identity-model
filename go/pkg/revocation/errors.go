package revocation

import (
	"errors"
	"fmt"
)

// RevocationError is a typed OAuth 2.0 error returned by the revocation endpoint
// (RFC 7009 §2.2.1). It is produced when the endpoint replies with a non-2xx
// status carrying a recognised OAuth error body — most commonly an HTTP 401
// invalid_client when the revoking client fails authentication, or an HTTP 400
// unsupported_token_type when the server does not support revoking the presented
// token type.
type RevocationError struct {
	// Code is the RFC 6749 §5.2 "error" code, e.g. "invalid_client" or
	// "unsupported_token_type".
	Code string `json:"error"`
	// ErrorDescription is the human-readable "error_description", if present.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is the "error_uri" pointing at documentation, if present.
	ErrorURI string `json:"error_uri,omitempty"`
	// StatusCode is the HTTP status of the error response.
	StatusCode int `json:"-"`
}

func (e *RevocationError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("revocation: endpoint error %q: %s (HTTP %d)", e.Code, e.ErrorDescription, e.StatusCode)
	}
	return fmt.Sprintf("revocation: endpoint error %q (HTTP %d)", e.Code, e.StatusCode)
}

// RequestError reports a transport-level failure, a configuration error, or a
// non-2xx response that did not carry a recognisable OAuth error body. Op names
// the failing step.
type RequestError struct {
	Op         string
	StatusCode int
	Err        error
}

func (e *RequestError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("revocation: %s (HTTP %d): %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("revocation: %s: %v", e.Op, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrRevocationResponse matches any [RevocationError] (an OAuth error
	// response from the revocation endpoint).
	ErrRevocationResponse = errors.New("revocation: endpoint error response")
	// ErrRequest matches any [RequestError] (transport or configuration failure).
	ErrRequest = errors.New("revocation: request failed")
)

func (e *RevocationError) Is(target error) bool { return target == ErrRevocationResponse }
func (e *RequestError) Is(target error) bool    { return target == ErrRequest }
