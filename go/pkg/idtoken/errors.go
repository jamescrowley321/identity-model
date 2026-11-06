package idtoken

import (
	"errors"
	"fmt"
)

// CanonicalError is the language-neutral error family the shared conformance
// vectors (spec/vectors/id-token.json) assign to every ID-Token profile
// rejection. Each language maps it to its own error type; in Go that type is
// [ProfileError].
const CanonicalError = "id_token_profile"

// Stable, language-neutral reason labels for ID-Token profile rejections. They
// match the "reason" field of the shared conformance vectors exactly, so the Go
// runner agrees with the Python reference on the cause of every rejection.
const (
	// ReasonMissingSub: sub is absent or empty (§2 / §3.1.3.7).
	ReasonMissingSub = "missing_sub"
	// ReasonMissingAud: aud is absent, null or holds only empty strings (§2).
	ReasonMissingAud = "missing_aud"
	// ReasonUntrustedAudience: aud contains a value that is neither the
	// client_id nor an audience the client trusts (§3.1.3.7 step 3).
	ReasonUntrustedAudience = "untrusted_audience"
	// ReasonAZPRequiredMultiAud: multiple audiences but no azp, with
	// [WithAZPValidation] (Core 1.0 (2014) §3.1.3.7 step 4).
	ReasonAZPRequiredMultiAud = "azp_required_multi_aud"
	// ReasonAZPMismatch: azp present but not this client, with
	// [WithAZPValidation] (§3.1.3.7 step 5).
	ReasonAZPMismatch = "azp_mismatch"
	// ReasonNonceMismatch: token nonce absent or not equal to the expected nonce
	// (§3.1.3.7 step 11).
	ReasonNonceMismatch = "nonce_mismatch"
	// ReasonAuthTimeStale: now-auth_time exceeds max_age+leeway (§3.1.3.7 step 12).
	ReasonAuthTimeStale = "auth_time_stale"
	// ReasonAuthTimeMissing: max_age requested but auth_time absent (§3.1.3.7
	// step 12).
	ReasonAuthTimeMissing = "auth_time_missing"
	// ReasonAtHashMissing: at_hash absent although the access token came in the
	// same authorization response as the ID Token (the default unless
	// [WithAccessTokenIssuedWithIDToken] is false, §3.2.2.10, §3.3.2.11).
	ReasonAtHashMissing = "at_hash_missing"
	// ReasonAtHashMismatch: at_hash present but not the access token's
	// left-half hash (§3.3.2.11).
	ReasonAtHashMismatch = "at_hash_mismatch"
	// ReasonCHashMissing: c_hash absent although the code came in the same
	// authorization response as the ID Token (the default unless
	// [WithCodeIssuedWithIDToken] is false, §3.3.2.11).
	ReasonCHashMissing = "c_hash_missing"
	// ReasonCHashMismatch: c_hash present but not the authorization code's
	// left-half hash (§3.3.2.11).
	ReasonCHashMismatch = "c_hash_mismatch"
	// ReasonUnsupportedAlg: the header alg cannot be mapped to a hash for an
	// at_hash/c_hash check (§3.3.2.11) — fails closed.
	ReasonUnsupportedAlg = "unsupported_alg"
	// ReasonAlgRequired: an at_hash/c_hash check was requested but the header
	// alg is missing (§3.3.2.11) — fails closed.
	ReasonAlgRequired = "alg_required"
)

// ErrIDTokenProfile is the sentinel matched by errors.Is for any ID-Token
// profile violation, for callers that prefer errors.Is over a type assertion.
var ErrIDTokenProfile = errors.New("idtoken: id-token profile validation failed")

// ProfileError reports that an ID-Token profile rule (OIDC Core §3.1.3.7 /
// §3.3.2.11) was violated. Reason is one of the stable Reason* labels above;
// Message is a human-readable explanation.
type ProfileError struct {
	Reason  string
	Message string
}

func (e *ProfileError) Error() string {
	return fmt.Sprintf("idtoken: id-token profile violation (%s): %s", e.Reason, e.Message)
}

// Is reports ProfileError as matching the ErrIDTokenProfile sentinel.
func (e *ProfileError) Is(target error) bool { return target == ErrIDTokenProfile }

// profileErr builds a *ProfileError for the given reason.
func profileErr(reason, message string) *ProfileError {
	return &ProfileError{Reason: reason, Message: message}
}
