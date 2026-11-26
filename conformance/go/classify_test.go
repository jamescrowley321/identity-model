package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jamescrowley321/identity-model/go/pkg/discovery"
	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// The reason classes the OIDF manifest names (conformance/expected_modules.json)
// for basic-rp, config-rp and form-post-basic-rp, plus the classes the harness
// records for failures outside ID Token validation.
func TestClassify(t *testing.T) {
	cases := map[string]struct {
		err      error
		fallback string
		want     string
	}{
		"iss claim":             {err: &jwt.ClaimValidationError{Claim: "iss"}, want: reasonInvalidIssuer},
		"aud claim":             {err: &jwt.ClaimValidationError{Claim: "aud"}, want: reasonInvalidAudience},
		"iat claim":             {err: &jwt.ClaimValidationError{Claim: "iat"}, want: reasonInvalidIssuedAt},
		"exp claim":             {err: &jwt.ClaimValidationError{Claim: "exp"}, want: reasonInvalidExpiration},
		"nbf claim":             {err: &jwt.ClaimValidationError{Claim: "nbf"}, want: reasonInvalidExpiration},
		"nonce claim":           {err: &jwt.ClaimValidationError{Claim: "nonce"}, want: reasonNonceMismatch},
		"sub claim":             {err: &jwt.ClaimValidationError{Claim: "sub"}, want: reasonInvalidSubject},
		"other claim":           {err: &jwt.ClaimValidationError{Claim: "acr"}, want: reasonIDTokenValidation},
		"missing sub":           {err: &idtoken.ProfileError{Reason: idtoken.ReasonMissingSub}, want: reasonInvalidSubject},
		"nonce mismatch":        {err: &idtoken.ProfileError{Reason: idtoken.ReasonNonceMismatch}, want: reasonNonceMismatch},
		"missing aud":           {err: &idtoken.ProfileError{Reason: idtoken.ReasonMissingAud}, want: reasonInvalidAudience},
		"untrusted aud":         {err: &idtoken.ProfileError{Reason: idtoken.ReasonUntrustedAudience}, want: reasonInvalidAudience},
		"at_hash":               {err: &idtoken.ProfileError{Reason: idtoken.ReasonAtHashMismatch}, want: reasonInvalidAtHash},
		"c_hash":                {err: &idtoken.ProfileError{Reason: idtoken.ReasonCHashMissing}, want: reasonInvalidCHash},
		"other profile":         {err: &idtoken.ProfileError{Reason: idtoken.ReasonAuthTimeStale}, want: reasonIDTokenValidation},
		"alg none":              {err: &jwt.AlgNoneError{}, want: reasonAlgNone},
		"unsupported alg":       {err: &jwt.UnsupportedAlgorithmError{Alg: "HS256"}, want: reasonInvalidAlgorithm},
		"signature":             {err: &jwt.SignatureError{Err: errors.New("bad")}, want: reasonInvalidSignature},
		"malformed":             {err: &jwt.MalformedTokenError{Reason: "x"}, want: reasonIDTokenValidation},
		"ambiguous key":         {err: &jwks.AmbiguousKeyError{Count: 2}, want: reasonKeySelection},
		"key not found":         {err: &jwks.KeyNotFoundError{Kid: "k"}, want: reasonKeySelection},
		"key alg mismatch":      {err: &jwks.KeyAlgorithmMismatchError{Kid: "k"}, want: reasonKeySelection},
		"issuer mismatch":       {err: &discovery.IssuerMismatchError{Requested: "a", Returned: "b"}, want: reasonIssuerMismatch},
		"discovery http":        {err: &discovery.HTTPError{StatusCode: 404}, want: reasonDiscoveryFailed},
		"userinfo sub":          {err: &userinfo.SubjectMismatchError{Expected: "a", Actual: "b"}, want: reasonUserInfoValidation},
		"userinfo http":         {err: &userinfo.UserInfoError{StatusCode: 401}, want: reasonUserInfoValidation},
		"token error":           {err: &token.TokenError{Code: "invalid_grant"}, want: reasonTokenExchange},
		"wrapped issuer":        {err: fmt.Errorf("authorize: %w", &jwt.ClaimValidationError{Claim: "iss"}), want: reasonInvalidIssuer},
		"untyped uses fallback": {err: errors.New("dial tcp: refused"), fallback: reasonJWKSFailed, want: reasonJWKSFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classify(tc.err, tc.fallback); got != tc.want {
				t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
