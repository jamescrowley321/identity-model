package idtoken_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/idtoken"
	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// Fixed clock matching the shared conformance vectors, so the real
// at_hash/c_hash and auth_time values below are reusable.
const fixedNowUnix = 1_700_000_000

func fixedNow() time.Time { return time.Unix(fixedNowUnix, 0).UTC() }

// Real OIDC §3.3.2.11 left-half hashes, taken from the shared vectors
// (spec/conformance/id-token.json). Reused here so the unit tests assert the
// production hash construction, not a self-consistent fixture.
const (
	rs256AccessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KntU"
	rs256AtHash      = "T7VF8gELfbwjUBkK04GEhg" // base64url(left-half SHA-256(access token))

	es512AccessToken = "YmExYzZmZTgtZXM1MTItYWNjZXNzLXRva2VuLWV4YW1wbGU"
	es512AtHash      = "2azZeYx02zZttjvAxgBshVhQxqEJ6Ku0oRgkegwI9Ww" // left-half SHA-512

	rs256Code  = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
	rs256CHash = "LDktKdoQak3Pk0cnXxCltA" // matches the OIDC Core §3.3.2.11 worked example

	es512Code  = "Y29kZS1lczUxMi1hdXRob3JpemF0aW9uLWNvZGUtZXhhbXBsZQ"
	es512CHash = "5ZRO6ySh8Y5x73OPd63wcyIunjtbSNZh9sQvDCegRDY"
)

const testClientID = "s6BhdRkqt3"

// baseClaims is a minimal, valid ID-Token claim set (single audience equal to
// the client_id, non-empty sub) that individual cases extend or override.
func baseClaims() map[string]any {
	return map[string]any{
		"iss": "https://op.example.com",
		"sub": "248289761001",
		"aud": testClientID,
		"iat": float64(fixedNowUnix - 100),
		"exp": float64(fixedNowUnix + 3600),
	}
}

// with returns a copy of baseClaims() with the given overrides applied. A nil
// value deletes the key (to model an absent claim).
func with(overrides map[string]any) map[string]any {
	c := baseClaims()
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

// assertReason asserts err is a *ProfileError with the wanted reason (and the
// ErrIDTokenProfile sentinel). An empty want means "expect no error".
func assertReason(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("expected accept, got %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected reject (%s), got nil", want)
	}
	if !errors.Is(err, idtoken.ErrIDTokenProfile) {
		t.Fatalf("error %v does not match ErrIDTokenProfile", err)
	}
	var pe *idtoken.ProfileError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *idtoken.ProfileError, got %T (%v)", err, err)
	}
	if pe.Reason != want {
		t.Fatalf("reason = %q, want %q", pe.Reason, want)
	}
}

// TestValidateClaims_Profile table-drives each ID-Token profile rule in its
// present / absent / mismatch permutations.
func TestValidateClaims_Profile(t *testing.T) {
	clock := idtoken.WithNow(fixedNow)

	cases := []struct {
		name       string
		claims     map[string]any
		headerAlg  string
		opts       []idtoken.Option
		wantReason string // "" => accept
	}{
		// sub (§2 / §3.1.3.7).
		{
			name:   "valid baseline",
			claims: baseClaims(),
			opts:   []idtoken.Option{idtoken.WithClientID(testClientID)},
		},
		{
			name:       "sub absent",
			claims:     with(map[string]any{"sub": nil}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID)},
			wantReason: idtoken.ReasonMissingSub,
		},
		{
			name:       "sub empty",
			claims:     with(map[string]any{"sub": ""}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID)},
			wantReason: idtoken.ReasonMissingSub,
		},

		// azp (§3.1.3.7 steps 4-6).
		{
			name:   "single-element aud list, no azp",
			claims: with(map[string]any{"aud": []any{testClientID}}),
			opts:   []idtoken.Option{idtoken.WithClientID(testClientID)},
		},
		{
			name:       "multiple audiences, azp absent",
			claims:     with(map[string]any{"aud": []any{testClientID, "other-client-9x"}}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID)},
			wantReason: idtoken.ReasonAZPRequiredMultiAud,
		},
		{
			name:   "multiple audiences, azp identifies this client",
			claims: with(map[string]any{"aud": []any{testClientID, "other-client-9x"}, "azp": testClientID}),
			opts:   []idtoken.Option{idtoken.WithClientID(testClientID)},
		},
		{
			name:       "multiple audiences, azp is a different client",
			claims:     with(map[string]any{"aud": []any{testClientID, "other-client-9x"}, "azp": "other-client-9x"}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID)},
			wantReason: idtoken.ReasonAZPMismatch,
		},
		{
			name:       "single audience, azp present but mismatched",
			claims:     with(map[string]any{"azp": "impostor-client"}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID)},
			wantReason: idtoken.ReasonAZPMismatch,
		},

		// nonce (§3.1.3.7 step 11).
		{
			name:   "nonce matches",
			claims: with(map[string]any{"nonce": "n-0S6_WzA2Mj"}),
			opts:   []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithNonce("n-0S6_WzA2Mj")},
		},
		{
			name:       "nonce differs",
			claims:     with(map[string]any{"nonce": "n-0S6_WzA2Mj"}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithNonce("different")},
			wantReason: idtoken.ReasonNonceMismatch,
		},
		{
			name:       "nonce expected but absent",
			claims:     baseClaims(),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithNonce("n-0S6_WzA2Mj")},
			wantReason: idtoken.ReasonNonceMismatch,
		},

		// auth_time / max_age (§3.1.3.7 step 12).
		{
			name:   "auth_time within max_age",
			claims: with(map[string]any{"auth_time": float64(fixedNowUnix - 100)}),
			opts:   []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithMaxAge(3600 * time.Second)},
		},
		{
			name:   "auth_time past max_age but within leeway",
			claims: with(map[string]any{"auth_time": float64(fixedNowUnix - 3610)}),
			opts: []idtoken.Option{
				idtoken.WithClientID(testClientID),
				idtoken.WithMaxAge(3600 * time.Second),
				idtoken.WithClockSkew(60 * time.Second),
			},
		},
		{
			name:       "auth_time older than max_age",
			claims:     with(map[string]any{"auth_time": float64(fixedNowUnix - 7200)}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithMaxAge(3600 * time.Second)},
			wantReason: idtoken.ReasonAuthTimeStale,
		},
		{
			name:       "max_age requested but auth_time absent",
			claims:     baseClaims(),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithMaxAge(3600 * time.Second)},
			wantReason: idtoken.ReasonAuthTimeMissing,
		},
		{
			name:       "auth_time as JSON bool is not numeric",
			claims:     with(map[string]any{"auth_time": true}),
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithMaxAge(3600 * time.Second)},
			wantReason: idtoken.ReasonAuthTimeMissing,
		},

		// at_hash (§3.3.2.11) — real RS256 hash.
		{
			name:      "at_hash matches (RS256)",
			claims:    with(map[string]any{"at_hash": rs256AtHash}),
			headerAlg: "RS256",
			opts:      []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
		},
		{
			name:       "at_hash mismatched (RS256)",
			claims:     with(map[string]any{"at_hash": "DyAleB7ctGQvU9M3DbMBYQ"}),
			headerAlg:  "RS256",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
			wantReason: idtoken.ReasonAtHashMismatch,
		},
		{
			name:       "access token supplied but at_hash absent",
			claims:     baseClaims(),
			headerAlg:  "RS256",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
			wantReason: idtoken.ReasonAtHashMismatch,
		},
		{
			name:      "at_hash present but not checked when access token omitted",
			claims:    with(map[string]any{"at_hash": rs256AtHash}),
			headerAlg: "RS256",
			opts:      []idtoken.Option{idtoken.WithClientID(testClientID)},
		},
		// at_hash under ES512 — the alg selects SHA-512.
		{
			name:      "at_hash matches (ES512)",
			claims:    with(map[string]any{"at_hash": es512AtHash}),
			headerAlg: "ES512",
			opts:      []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(es512AccessToken)},
		},
		{
			name:       "SHA-256-sized at_hash rejected under ES512",
			claims:     with(map[string]any{"at_hash": rs256AtHash}),
			headerAlg:  "ES512",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
			wantReason: idtoken.ReasonAtHashMismatch,
		},

		// c_hash (§3.3.2.11) — real RS256 and ES512 hashes.
		{
			name:      "c_hash matches (RS256)",
			claims:    with(map[string]any{"c_hash": rs256CHash}),
			headerAlg: "RS256",
			opts:      []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithCode(rs256Code)},
		},
		{
			name:       "c_hash mismatched (RS256)",
			claims:     with(map[string]any{"c_hash": "DyAleB7ctGQvU9M3DbMBYQ"}),
			headerAlg:  "RS256",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithCode(rs256Code)},
			wantReason: idtoken.ReasonCHashMismatch,
		},
		{
			name:      "c_hash matches (ES512)",
			claims:    with(map[string]any{"c_hash": es512CHash}),
			headerAlg: "ES512",
			opts:      []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithCode(es512Code)},
		},

		// Fail-closed alg handling (§3.3.2.11).
		{
			name:       "unknown alg on at_hash check",
			claims:     with(map[string]any{"at_hash": rs256AtHash}),
			headerAlg:  "UNKNOWN",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
			wantReason: idtoken.ReasonUnsupportedAlg,
		},
		{
			name:       "missing alg on at_hash check",
			claims:     with(map[string]any{"at_hash": rs256AtHash}),
			headerAlg:  "",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithAccessToken(rs256AccessToken)},
			wantReason: idtoken.ReasonAlgRequired,
		},
		{
			name:       "unknown alg on c_hash check",
			claims:     with(map[string]any{"c_hash": rs256CHash}),
			headerAlg:  "RS999",
			opts:       []idtoken.Option{idtoken.WithClientID(testClientID), idtoken.WithCode(rs256Code)},
			wantReason: idtoken.ReasonUnsupportedAlg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]idtoken.Option{clock}, tc.opts...)
			err := idtoken.ValidateClaims(tc.claims, tc.headerAlg, opts...)
			assertReason(t, err, tc.wantReason)
		})
	}
}

// TestValidateClaims_DoesNotRejectAccessTokenShape confirms the profile
// positively validates an ID Token and does not reject a claim set merely
// because it also looks like an access token (no id-vs-access discrimination
// here — that belongs in middleware).
func TestValidateClaims_DoesNotRejectAccessTokenShape(t *testing.T) {
	claims := with(map[string]any{"scope": "openid profile", "client_id": testClientID})
	err := idtoken.ValidateClaims(claims, "RS256", idtoken.WithNow(fixedNow), idtoken.WithClientID(testClientID))
	if err != nil {
		t.Fatalf("expected accept for an id-token profile with access-token-like extras, got %v", err)
	}
}

// ---- ValidateIDToken (full network entry point) ----

func fixtureDir() string {
	return filepath.Join("..", "..", "..", "spec", "test-fixtures", "validation")
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// loadSigningKey loads the shared RSA signing key (kid=test-key-1).
func loadSigningKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	var jk jose.JSONWebKey
	if err := jk.UnmarshalJSON(readFixture(t, "signing-key.jwk.json")); err != nil {
		t.Fatalf("parse signing key: %v", err)
	}
	return &jk
}

// fixtureKeySet serves the public JWKS fixture over httptest and fetches it
// through the real jwks client, matching the jwt package tests.
func fixtureKeySet(t *testing.T) *jwks.JSONWebKeySet {
	t.Helper()
	body := readFixture(t, "jwks.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	set, err := jwks.FetchKeySet(context.Background(), srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch key set: %v", err)
	}
	return set
}

// signIDToken mints a compact RS256 JWS over claims using the fixture key.
func signIDToken(t *testing.T, key *jose.JSONWebKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tok, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return tok
}

const wrapperIssuer = "https://op.example.com"

// TestValidateIDToken_BaseProfile mints a genuine RS256 ID Token and validates
// it end-to-end (base signature/iss/aud/iat/exp via jwt.Validate, then the
// profile). This also proves the wrapper sources the hash alg from the *verified*
// header (RS256 → SHA-256) for the at_hash binding rather than an option.
func TestValidateIDToken_BaseProfile(t *testing.T) {
	key := loadSigningKey(t)
	set := fixtureKeySet(t)

	tok := signIDToken(t, key, map[string]any{
		"iss":       wrapperIssuer,
		"sub":       "248289761001",
		"aud":       testClientID,
		"iat":       fixedNowUnix - 100,
		"exp":       fixedNowUnix + 3600,
		"at_hash":   rs256AtHash,
		"auth_time": fixedNowUnix - 100,
	})

	claims, err := idtoken.ValidateIDToken(context.Background(), tok, set,
		idtoken.WithIssuer(wrapperIssuer),
		idtoken.WithClientID(testClientID),
		idtoken.WithAccessToken(rs256AccessToken),
		idtoken.WithMaxAge(3600*time.Second),
		idtoken.WithNow(fixedNow),
	)
	if err != nil {
		t.Fatalf("ValidateIDToken: %v", err)
	}
	if claims.Subject != "248289761001" {
		t.Errorf("sub = %q, want %q", claims.Subject, "248289761001")
	}
	if claims.Issuer != wrapperIssuer {
		t.Errorf("iss = %q, want %q", claims.Issuer, wrapperIssuer)
	}
	if !claims.Audience.Contains(testClientID) {
		t.Errorf("aud %v does not contain %q", claims.Audience, testClientID)
	}
}

// TestValidateIDToken_WrongAudience confirms the base validation rejects an ID
// Token audienced to a different client (a jwt claim-validation error, not a
// profile error).
func TestValidateIDToken_WrongAudience(t *testing.T) {
	key := loadSigningKey(t)
	set := fixtureKeySet(t)

	tok := signIDToken(t, key, map[string]any{
		"iss": wrapperIssuer,
		"sub": "248289761001",
		"aud": testClientID,
		"iat": fixedNowUnix - 100,
		"exp": fixedNowUnix + 3600,
	})

	_, err := idtoken.ValidateIDToken(context.Background(), tok, set,
		idtoken.WithIssuer(wrapperIssuer),
		idtoken.WithClientID("some-other-client"),
		idtoken.WithNow(fixedNow),
	)
	if !errors.Is(err, jwt.ErrClaimValidation) {
		t.Fatalf("err = %v, want jwt.ErrClaimValidation for wrong audience", err)
	}
}

// TestValidateIDToken_ProfileFailure confirms a profile violation on a genuinely
// signed token surfaces a *ProfileError after the base validation passes.
func TestValidateIDToken_ProfileFailure(t *testing.T) {
	key := loadSigningKey(t)
	set := fixtureKeySet(t)

	// Signature/iss/aud/exp are all valid; the nonce binding fails.
	tok := signIDToken(t, key, map[string]any{
		"iss":   wrapperIssuer,
		"sub":   "248289761001",
		"aud":   testClientID,
		"iat":   fixedNowUnix - 100,
		"exp":   fixedNowUnix + 3600,
		"nonce": "the-real-nonce",
	})

	_, err := idtoken.ValidateIDToken(context.Background(), tok, set,
		idtoken.WithIssuer(wrapperIssuer),
		idtoken.WithClientID(testClientID),
		idtoken.WithNonce("not-the-nonce"),
		idtoken.WithNow(fixedNow),
	)
	var pe *idtoken.ProfileError
	if !errors.As(err, &pe) || pe.Reason != idtoken.ReasonNonceMismatch {
		t.Fatalf("err = %v, want *ProfileError{nonce_mismatch}", err)
	}
}
