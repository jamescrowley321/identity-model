package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "test-client"
	testKid      = "test-key-1"
)

// fixedNow is the deterministic clock for time-based claim tests.
var fixedNow = time.Unix(1_700_000_000, 0).UTC()

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

// loadSigningKey loads the RSA private signing key shared by the conformance
// fixtures (kid=test-key-1).
func loadSigningKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	var jk jose.JSONWebKey
	if err := jk.UnmarshalJSON(readFixture(t, "signing-key.jwk.json")); err != nil {
		t.Fatalf("parse signing key: %v", err)
	}
	if jk.KeyID != testKid {
		t.Fatalf("fixture kid = %q, want %q", jk.KeyID, testKid)
	}
	return &jk
}

// keySetFromJSON serves jwksJSON over httptest and fetches it through the real
// jwks client, so resolution and forced refresh exercise production code.
func keySetFromJSON(t *testing.T, jwksJSON []byte) *jwks.JSONWebKeySet {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(srv.Close)
	set, err := jwks.FetchKeySet(context.Background(), srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch key set: %v", err)
	}
	return set
}

// fixtureKeySet builds a key set from the public JWKS fixture (matches the
// fixture signing key). JWT-001/002.
func fixtureKeySet(t *testing.T) *jwks.JSONWebKeySet {
	return keySetFromJSON(t, readFixture(t, "jwks.json"))
}

// jwksJSON renders a public JWKS document from go-jose keys.
func jwksJSON(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// signWith mints a compact JWS over claims, signed by key with alg. The kid is
// taken from the key, so a key whose KeyID differs from its material lets a test
// forge a header kid (bad-signature case).
func signWith(t *testing.T, key *jose.JSONWebKey, alg jose.SignatureAlgorithm, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
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

// validClaims returns a baseline claim set valid at fixedNow.
func validClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"sub": "user-123",
		"aud": testAudience,
		"exp": fixedNow.Add(time.Hour).Unix(),
		"nbf": fixedNow.Add(-time.Minute).Unix(),
		"iat": fixedNow.Add(-time.Minute).Unix(),
	}
}

func withFixedNow() Option { return WithNow(func() time.Time { return fixedNow }) }

// JWT-001, JWT-002: a valid RS256 token verifies and yields typed claims.
func TestValidate_ValidToken(t *testing.T) {
	set := fixtureKeySet(t)
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())

	claims, err := Validate(context.Background(), token, set,
		WithExpectedIssuer(testIssuer), WithExpectedAudience(testAudience), withFixedNow())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Issuer != testIssuer {
		t.Errorf("iss = %q, want %q", claims.Issuer, testIssuer)
	}
	if claims.Subject != "user-123" {
		t.Errorf("sub = %q, want user-123", claims.Subject)
	}
	if !claims.Audience.Contains(testAudience) {
		t.Errorf("aud = %v, want to contain %q", claims.Audience, testAudience)
	}
	if claims.IssuedAt == nil || claims.Expiry == nil {
		t.Errorf("iat/exp not populated: iat=%v exp=%v", claims.IssuedAt, claims.Expiry)
	}
}

// JWT-001: an ES256 token verifies against an EC key (algorithm coverage).
func TestValidate_ValidToken_ES256(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv := &jose.JSONWebKey{Key: ecPriv, KeyID: "ec-key-1", Algorithm: "ES256", Use: "sig"}
	pub := jose.JSONWebKey{Key: &ecPriv.PublicKey, KeyID: "ec-key-1", Algorithm: "ES256", Use: "sig"}
	set := keySetFromJSON(t, jwksJSON(t, pub))

	token := signWith(t, priv, jose.ES256, validClaims())
	if _, err := Validate(context.Background(), token, set, withFixedNow()); err != nil {
		t.Fatalf("Validate ES256: %v", err)
	}
}

// JWT-003: alg "none" is rejected unconditionally (static fixture token).
func TestValidate_AlgNone_Rejected(t *testing.T) {
	set := fixtureKeySet(t)
	token := string(readFixture(t, "alg-none-token.txt"))

	_, err := Validate(context.Background(), token, set, withFixedNow())
	if !errors.Is(err, ErrAlgNone) {
		t.Fatalf("err = %v, want ErrAlgNone", err)
	}
}

// JWT-004: nonce is validated when WithExpectedNonce is supplied.
func TestValidate_Nonce(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["nonce"] = "n-abc"
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	if _, err := Validate(context.Background(), token, set, WithExpectedNonce("n-abc"), withFixedNow()); err != nil {
		t.Fatalf("matching nonce: %v", err)
	}

	_, err := Validate(context.Background(), token, set, WithExpectedNonce("n-wrong"), withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "nonce" {
		t.Fatalf("err = %v, want ClaimValidationError on nonce", err)
	}
}

// JWT-005: an expired token is rejected.
func TestValidate_Expired(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["exp"] = fixedNow.Add(-time.Hour).Unix()
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	_, err := Validate(context.Background(), token, set, withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "exp" {
		t.Fatalf("err = %v, want ClaimValidationError on exp", err)
	}
}

// JWT-006: a not-yet-valid token (nbf in the future) is rejected.
func TestValidate_NotYetValid(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["nbf"] = fixedNow.Add(time.Hour).Unix()
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	_, err := Validate(context.Background(), token, set, withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "nbf" {
		t.Fatalf("err = %v, want ClaimValidationError on nbf", err)
	}
}

// JWT-007: a wrong issuer is rejected.
func TestValidate_WrongIssuer(t *testing.T) {
	set := fixtureKeySet(t)
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())

	_, err := Validate(context.Background(), token, set, WithExpectedIssuer("https://evil.example.com"), withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "iss" {
		t.Fatalf("err = %v, want ClaimValidationError on iss", err)
	}
}

// JWT-008: a wrong or absent audience is rejected.
func TestValidate_WrongAudience(t *testing.T) {
	set := fixtureKeySet(t)
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())

	_, err := Validate(context.Background(), token, set, WithExpectedAudience("other-client"), withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "aud" {
		t.Fatalf("err = %v, want ClaimValidationError on aud", err)
	}
}

// JWT-008: aud as a JSON array is accepted when it contains the expected value.
func TestValidate_AudienceArray(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["aud"] = []string{"other-client", testAudience}
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	c, err := Validate(context.Background(), token, set, WithExpectedAudience(testAudience), withFixedNow())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(c.Audience) != 2 {
		t.Errorf("aud = %v, want 2 entries", c.Audience)
	}
}

// JWT-009: a token signed by the wrong key fails signature verification.
func TestValidate_BadSignature(t *testing.T) {
	set := fixtureKeySet(t)
	// A different RSA key but forging the fixture kid in its header, so it
	// resolves the real public key — which will not verify the signature.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := &jose.JSONWebKey{Key: other, KeyID: testKid, Algorithm: "RS256"}
	token := signWith(t, forged, jose.RS256, validClaims())

	_, err = Validate(context.Background(), token, set, withFixedNow())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// JWT-010: a kid absent from the cached set triggers a forced refresh, after
// which the now-published key resolves and verification succeeds.
func TestValidate_KidNotFound_ForcesRefresh(t *testing.T) {
	signing := loadSigningKey(t)
	freshJWKS := readFixture(t, "jwks.json")

	// Stale set: a valid key set that lacks test-key-1 (a placeholder kid).
	placeholder, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	staleJWKS := jwksJSON(t, jose.JSONWebKey{Key: &placeholder.PublicKey, KeyID: "stale-key", Algorithm: "RS256", Use: "sig"})

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_, _ = w.Write(staleJWKS) // first fetch: kid not present
		} else {
			_, _ = w.Write(freshJWKS) // after forced refresh: kid present
		}
	}))
	t.Cleanup(srv.Close)

	set, err := jwks.FetchKeySet(context.Background(), srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch key set: %v", err)
	}

	token := signWith(t, signing, jose.RS256, validClaims())
	if _, err := Validate(context.Background(), token, set, withFixedNow()); err != nil {
		t.Fatalf("Validate after refresh: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected a forced refresh (>=2 fetches), got %d", calls)
	}
}

// JWT-010: a kid that never appears surfaces the descriptive key-not-found error.
func TestValidate_KidNeverFound(t *testing.T) {
	placeholder, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := keySetFromJSON(t, jwksJSON(t, jose.JSONWebKey{Key: &placeholder.PublicKey, KeyID: "stale-key", Algorithm: "RS256", Use: "sig"}))
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())

	_, err = Validate(context.Background(), token, set, withFixedNow())
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("err = %v, want jwks.ErrKeyNotFound", err)
	}
}

// JWT-011: clock skew tolerance admits a token just past expiry.
func TestValidate_ClockSkew(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["exp"] = fixedNow.Add(-30 * time.Second).Unix() // expired 30s ago
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	// Without skew: rejected.
	if _, err := Validate(context.Background(), token, set, withFixedNow()); !errors.Is(err, ErrClaimValidation) {
		t.Fatalf("no-skew err = %v, want ErrClaimValidation", err)
	}
	// With 60s skew: accepted.
	if _, err := Validate(context.Background(), token, set, WithClockSkew(60*time.Second), withFixedNow()); err != nil {
		t.Fatalf("with skew: %v", err)
	}
}

// JWT-012: custom required claims are enforced.
func TestValidate_RequiredClaims(t *testing.T) {
	set := fixtureKeySet(t)

	// Missing the required claim.
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())
	_, err := Validate(context.Background(), token, set, WithRequiredClaims("scope"), withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "scope" {
		t.Fatalf("err = %v, want ClaimValidationError on scope", err)
	}

	// Present: passes and is reachable via accessors.
	claims := validClaims()
	claims["scope"] = "openid profile"
	token = signWith(t, loadSigningKey(t), jose.RS256, claims)
	c, err := Validate(context.Background(), token, set, WithRequiredClaims("scope"), withFixedNow())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, err := c.GetString("scope"); err != nil || got != "openid profile" {
		t.Errorf("GetString(scope) = %q, %v", got, err)
	}
}

// JWT-013: a token missing iat is rejected.
func TestValidate_MissingIat(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	delete(claims, "iat")
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	_, err := Validate(context.Background(), token, set, withFixedNow())
	var cve *ClaimValidationError
	if !errors.As(err, &cve) || cve.Claim != "iat" {
		t.Fatalf("err = %v, want ClaimValidationError on iat", err)
	}
}

// A malformed token (not three segments) is rejected before any crypto.
func TestValidate_Malformed(t *testing.T) {
	set := fixtureKeySet(t)
	_, err := Validate(context.Background(), "not.a.valid.jwt.token", set, withFixedNow())
	if !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

// An algorithm outside the allowlist is rejected (alg confusion defence).
func TestValidate_UnsupportedAlgorithm(t *testing.T) {
	set := fixtureKeySet(t)
	token := signWith(t, loadSigningKey(t), jose.RS256, validClaims())

	// Restrict the allowlist to ES256 only; the RS256 token is then disallowed.
	_, err := Validate(context.Background(), token, set, WithAllowedAlgorithms("ES256"), withFixedNow())
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// A nil key set is reported as a malformed-input error rather than panicking.
func TestValidate_NilKeySet(t *testing.T) {
	_, err := Validate(context.Background(), "a.b.c", nil)
	if !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

// Claims accessors expose custom claims and presence.
func TestClaims_Accessors(t *testing.T) {
	set := fixtureKeySet(t)
	claims := validClaims()
	claims["email"] = "a@example.com"
	token := signWith(t, loadSigningKey(t), jose.RS256, claims)

	c, err := Validate(context.Background(), token, set, withFixedNow())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !c.Has("email") || !c.Has("iss") {
		t.Errorf("Has: email/iss not reported present")
	}
	if c.Has("groups") {
		t.Errorf("Has(groups) = true, want false")
	}
	if _, ok := c.Extra["email"]; !ok {
		t.Errorf("Extra missing email")
	}
	if _, ok := c.Extra["iss"]; ok {
		t.Errorf("Extra should not contain modelled claim iss")
	}
	if raw, ok := c.GetClaim("email"); !ok || len(raw) == 0 {
		t.Errorf("GetClaim(email) not found")
	}
}

// Audience unmarshals from both a string and an array.
func TestAudience_Unmarshal(t *testing.T) {
	var a Audience
	if err := json.Unmarshal([]byte(`"single"`), &a); err != nil || len(a) != 1 || a[0] != "single" {
		t.Fatalf("string aud: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`["x","y"]`), &a); err != nil || len(a) != 2 {
		t.Fatalf("array aud: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`123`), &a); err == nil {
		t.Fatalf("numeric aud should error")
	}
}

// A JSON null audience must yield an empty audience, not a slice holding one
// empty string (which would spuriously "contain" an expected "" audience).
func TestAudience_Null(t *testing.T) {
	a := Audience{"stale"}
	if err := json.Unmarshal([]byte(`null`), &a); err != nil {
		t.Fatalf("null aud: %v", err)
	}
	if a != nil {
		t.Errorf("null aud = %#v, want nil", a)
	}
}

// An out-of-range numeric date (e.g. exp = 1e30) must be rejected rather than
// silently overflowing int64 into a garbage time that defeats the expiry check.
func TestNumericDate_OutOfRange(t *testing.T) {
	for _, in := range []string{`1e30`, `-1e30`, `9.3e18`} {
		var n NumericDate
		if err := json.Unmarshal([]byte(in), &n); err == nil {
			t.Errorf("numeric date %s: expected out-of-range error, got %v", in, n.Time)
		}
	}
	// A normal timestamp still decodes, preserving sub-second precision.
	var n NumericDate
	if err := json.Unmarshal([]byte(`1700000000.5`), &n); err != nil {
		t.Fatalf("valid numeric date: %v", err)
	}
	if got := n.UnixNano(); got != 1_700_000_000_500_000_000 {
		t.Errorf("decoded ns = %d, want 1700000000500000000", got)
	}
}

// A payload with a duplicate top-level claim must be rejected: encoding/json
// would otherwise resolve it last-wins, letting an attacker smuggle a second
// iss/aud past the modelled fields.
func TestParseClaims_DuplicateKey(t *testing.T) {
	_, err := parseClaims([]byte(`{"iss":"good","aud":"x","iss":"evil"}`))
	var mErr *MalformedTokenError
	if !errors.As(err, &mErr) {
		t.Fatalf("duplicate claim: err = %v, want *MalformedTokenError", err)
	}
	// A nested object may legitimately repeat a key name at its own level.
	if _, err := parseClaims([]byte(`{"iss":"good","ctx":{"k":1},"sub":"s","iat":1700000000}`)); err != nil {
		t.Errorf("nested object wrongly rejected: %v", err)
	}
}

// toPublicKey rejects an unsupported key type rather than emitting a key with no
// material.
func TestToPublicKey_UnsupportedKty(t *testing.T) {
	if _, err := toPublicKey(&jwks.JSONWebKey{Kty: "oct"}); err == nil {
		t.Error("expected error for unsupported kty")
	}
}
