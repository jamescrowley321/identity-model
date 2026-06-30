package userinfo

import (
	"errors"
	"fmt"
)

// UserInfoError is returned when the UserInfo endpoint replies with a non-2xx
// status (OIDC Core 1.0 §5.3.3). It captures the HTTP status and the
// WWW-Authenticate challenge header, which a Bearer-protected resource uses to
// describe the error (RFC 6750 §3).
type UserInfoError struct {
	// StatusCode is the HTTP status of the error response.
	StatusCode int
	// WWWAuthenticate is the WWW-Authenticate challenge header, if present.
	WWWAuthenticate string
	// Body is a short snippet of the response body for diagnostics.
	Body string
}

func (e *UserInfoError) Error() string {
	if e.WWWAuthenticate != "" {
		return fmt.Sprintf("userinfo: endpoint error (HTTP %d): %s", e.StatusCode, e.WWWAuthenticate)
	}
	return fmt.Sprintf("userinfo: endpoint error (HTTP %d): %s", e.StatusCode, e.Body)
}

// SubjectMismatchError reports that the UserInfo "sub" did not match the
// expected subject supplied via [WithSubjectValidation] (OIDC Core 1.0 §5.3.2).
// Using a UserInfo response whose sub differs from the ID token's sub is a
// security risk (token substitution), so the mismatch is surfaced as an error.
type SubjectMismatchError struct {
	Expected string
	Actual   string
}

func (e *SubjectMismatchError) Error() string {
	return fmt.Sprintf("userinfo: subject mismatch: expected %q, got %q", e.Expected, e.Actual)
}

// RequestError reports a transport-level failure, a malformed or non-JSON
// response, a missing subject, or a rejected (non-https) endpoint. Op names the
// failing step.
type RequestError struct {
	Op         string
	StatusCode int
	Err        error
}

func (e *RequestError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("userinfo: %s (HTTP %d): %v", e.Op, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("userinfo: %s: %v", e.Op, e.Err)
}

func (e *RequestError) Unwrap() error { return e.Err }

// Sentinel errors for callers that prefer errors.Is over type assertions.
var (
	// ErrUserInfoResponse matches any [UserInfoError] (a non-2xx response).
	ErrUserInfoResponse = errors.New("userinfo: endpoint error response")
	// ErrSubjectMismatch matches any [SubjectMismatchError].
	ErrSubjectMismatch = errors.New("userinfo: subject mismatch")
	// ErrRequest matches any [RequestError] (transport, decode, or config failure).
	ErrRequest = errors.New("userinfo: request failed")
)

func (e *UserInfoError) Is(target error) bool        { return target == ErrUserInfoResponse }
func (e *SubjectMismatchError) Is(target error) bool { return target == ErrSubjectMismatch }
func (e *RequestError) Is(target error) bool         { return target == ErrRequest }
