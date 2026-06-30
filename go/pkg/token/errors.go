package token

import (
	"errors"
	"fmt"
)

// TokenError is a typed OAuth 2.0 token endpoint error response (RFC 6749 §5.2).
// It is returned when the endpoint replies with a non-2xx status carrying a
// recognised OAuth error body.
type TokenError struct {
	// Code is the RFC 6749 §5.2 "error" code, e.g. "invalid_client".
	Code string `json:"error"`
	// ErrorDescription is the human-readable "error_description", if present.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is the "error_uri" pointing at documentation, if present.
	ErrorURI string `json:"error_uri,omitempty"`
	// StatusCode is the HTTP status of the error response.
	StatusCode int `json:"-"`
}

func (e *TokenError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("token: endpoint error %q: %s (HTTP %d)", e.Code, e.ErrorDescription, e.StatusCode)
	}
	return fmt.Sprintf("token: endpoint error %q (HTTP %d)", e.Code, e.StatusCode)
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
		return fmt.Sprintf("token: %s (HTTP %d): %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("token: %s: %v", e.Op, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrTokenResponse matches any [TokenError] (an OAuth error response).
	ErrTokenResponse = errors.New("token: endpoint error response")
	// ErrRequest matches any [RequestError] (transport or decode failure).
	ErrRequest = errors.New("token: request failed")
	// ErrInvalidCodeVerifier reports a PKCE code_verifier outside the
	// 43-128 unreserved-character range required by RFC 7636 §4.1.
	ErrInvalidCodeVerifier = errors.New("token: invalid code verifier")
)

func (e *TokenError) Is(target error) bool   { return target == ErrTokenResponse }
func (e *RequestError) Is(target error) bool { return target == ErrRequest }
