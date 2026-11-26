package main

import (
	"errors"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// Reason classes recorded as "<reason>: <detail>" in a module's outcome. The
// runner compares the reason with the "reasons" the plan's entry in
// conformance/expected_modules.json lists, and they match the Python harness's
// classes (py-identity-model TokenValidationErrorKind and conformance/app.py).
const (
	reasonInvalidIssuer      = "invalid_issuer"
	reasonInvalidAudience    = "invalid_audience"
	reasonInvalidExpiration  = "invalid_expiration"
	reasonInvalidIssuedAt    = "invalid_issued_at"
	reasonInvalidSubject     = "invalid_subject"
	reasonInvalidSignature   = "invalid_signature"
	reasonKeySelection       = "key_selection"
	reasonInvalidAlgorithm   = "invalid_algorithm"
	reasonAlgNone            = "alg_none"
	reasonNonceMismatch      = "nonce_mismatch"
	reasonInvalidAtHash      = "invalid_at_hash"
	reasonInvalidCHash       = "invalid_c_hash"
	reasonIDTokenValidation  = "id_token_validation"
	reasonIssuerMismatch     = "issuer_mismatch"
	reasonDiscoveryFailed    = "discovery_failed"
	reasonJWKSFailed         = "jwks_failed"
	reasonTokenExchange      = "token_exchange"
	reasonUserInfoValidation = "userinfo_validation"
	reasonStateValidation    = "state_validation"
	reasonMissingCode        = "missing_code"
	reasonMissingEndpoint    = "missing_endpoint"
	reasonUnsupportedFlow    = "unsupported_flow"
	reasonRPError            = "rp_error"
)

// claimReasons maps the claim a jwt.ClaimValidationError names to its reason.
var claimReasons = map[string]string{
	"iss":   reasonInvalidIssuer,
	"aud":   reasonInvalidAudience,
	"iat":   reasonInvalidIssuedAt,
	"exp":   reasonInvalidExpiration,
	"nbf":   reasonInvalidExpiration,
	"nonce": reasonNonceMismatch,
	"sub":   reasonInvalidSubject,
}

// profileReasons maps an idtoken.ProfileError reason label to its reason.
var profileReasons = map[string]string{
	idtoken.ReasonMissingSub:          reasonInvalidSubject,
	idtoken.ReasonMissingAud:          reasonInvalidAudience,
	idtoken.ReasonUntrustedAudience:   reasonInvalidAudience,
	idtoken.ReasonAZPRequiredMultiAud: reasonInvalidAudience,
	idtoken.ReasonAZPMismatch:         reasonInvalidAudience,
	idtoken.ReasonNonceMismatch:       reasonNonceMismatch,
	idtoken.ReasonAtHashMissing:       reasonInvalidAtHash,
	idtoken.ReasonAtHashMismatch:      reasonInvalidAtHash,
	idtoken.ReasonCHashMissing:        reasonInvalidCHash,
	idtoken.ReasonCHashMismatch:       reasonInvalidCHash,
	idtoken.ReasonUnsupportedAlg:      reasonInvalidAlgorithm,
	idtoken.ReasonAlgRequired:         reasonInvalidAlgorithm,
}

// classify returns the reason class for err, matched on the library's typed
// errors (never on message text). An error of no recognised type, such as a
// transport failure, gets fallback.
func classify(err error, fallback string) string {
	var (
		claimErr     *jwt.ClaimValidationError
		profileErr   *idtoken.ProfileError
		algNone      *jwt.AlgNoneError
		unsupported  *jwt.UnsupportedAlgorithmError
		sigErr       *jwt.SignatureError
		malformed    *jwt.MalformedTokenError
		ambiguous    *jwks.AmbiguousKeyError
		notFound     *jwks.KeyNotFoundError
		keyAlg       *jwks.KeyAlgorithmMismatchError
		weakKey      *jwt.WeakKeyError
		keyConv      *jwt.KeyConversionError
		issuerMM     *discovery.IssuerMismatchError
		discoHTTP    *discovery.HTTPError
		discoParse   *discovery.ParseError
		discoMissing *discovery.MissingFieldsError
		discoHTTPS   *discovery.HTTPSRequiredError
		subMismatch  *userinfo.SubjectMismatchError
		userinfoErr  *userinfo.UserInfoError
		userinfoReq  *userinfo.RequestError
		tokenErr     *token.TokenError
		tokenReq     *token.RequestError
		jwksHTTP     *jwks.HTTPError
		jwksParse    *jwks.ParseError
		jwksEmpty    *jwks.EmptyKeySetError
	)
	switch {
	case errors.As(err, &claimErr):
		if reason, ok := claimReasons[claimErr.Claim]; ok {
			return reason
		}
		return reasonIDTokenValidation
	case errors.As(err, &profileErr):
		if reason, ok := profileReasons[profileErr.Reason]; ok {
			return reason
		}
		return reasonIDTokenValidation
	case errors.As(err, &algNone):
		return reasonAlgNone
	case errors.As(err, &unsupported):
		return reasonInvalidAlgorithm
	case errors.As(err, &sigErr):
		return reasonInvalidSignature
	case errors.As(err, &ambiguous), errors.As(err, &notFound), errors.As(err, &keyAlg),
		errors.As(err, &weakKey), errors.As(err, &keyConv):
		return reasonKeySelection
	case errors.As(err, &malformed):
		return reasonIDTokenValidation
	case errors.As(err, &issuerMM):
		return reasonIssuerMismatch
	case errors.As(err, &discoHTTP), errors.As(err, &discoParse), errors.As(err, &discoMissing),
		errors.As(err, &discoHTTPS):
		return reasonDiscoveryFailed
	case errors.As(err, &subMismatch), errors.As(err, &userinfoErr), errors.As(err, &userinfoReq):
		return reasonUserInfoValidation
	case errors.As(err, &tokenErr), errors.As(err, &tokenReq):
		return reasonTokenExchange
	case errors.As(err, &jwksHTTP), errors.As(err, &jwksParse), errors.As(err, &jwksEmpty):
		return reasonJWKSFailed
	}
	return fallback
}
