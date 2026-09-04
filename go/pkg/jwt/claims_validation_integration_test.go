//go:build integration

package jwt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
	"github.com/jamescrowley321/identity-model/go/pkg/jwt"
)

// These integration tests drive the injectable claims validators through the
// REAL jwt.Validate pipeline: a token is signed with the shared conformance
// signing key, its public JWKS is served over HTTP and fetched through the real
// jwks client, and jwt.Validate verifies the signature and the registered claims
// before the injected validator runs. That proves the WithClaimsValidator hook
// executes only on an otherwise-valid, genuinely-signed token — which the unit
// tests (calling the validators directly) cannot show. Self-contained: no Docker
// or live provider, mirroring the Python mock-OP integration.

const (
	itIssuer   = "https://issuer.example.com"
	itAudience = "test-client"
	itKid      = "test-key-1"
)

func itFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "test-fixtures", "validation", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// itKeySet serves the public JWKS fixture over httptest and fetches it through
// the real jwks client, so signature verification uses production key resolution.
func itKeySet(t *testing.T) *jwks.JSONWebKeySet {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(itFixture(t, "jwks.json"))
	}))
	t.Cleanup(srv.Close)
	set, err := jwks.FetchKeySet(context.Background(), srv.URL, jwks.WithInsecureAllowHTTP())
	if err != nil {
		t.Fatalf("fetch key set: %v", err)
	}
	return set
}

// itSignedToken mints a genuinely-signed RS256 token carrying claims, valid now.
func itSignedToken(t *testing.T, extra map[string]any) string {
	t.Helper()
	var priv jose.JSONWebKey
	if err := priv.UnmarshalJSON(itFixture(t, "signing-key.jwk.json")); err != nil {
		t.Fatalf("parse signing key: %v", err)
	}
	if priv.KeyID != itKid {
		t.Fatalf("fixture kid = %q, want %q", priv.KeyID, itKid)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": itIssuer,
		"sub": "mock-subject",
		"aud": itAudience,
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &priv}, (&jose.SignerOptions{}).WithType("JWT"))
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

// requireClaims / requireScopes construct the fallible validators for the
// external test package.
func itRequireClaims(t *testing.T, names ...string) jwt.ClaimsValidator {
	t.Helper()
	v, err := jwt.RequireClaims(names...)
	if err != nil {
		t.Fatalf("RequireClaims: %v", err)
	}
	return v
}

func itRequireScopes(t *testing.T, scopes ...string) jwt.ClaimsValidator {
	t.Helper()
	v, err := jwt.RequireScopes(scopes...)
	if err != nil {
		t.Fatalf("RequireScopes: %v", err)
	}
	return v
}

func itValidate(t *testing.T, token string, v jwt.ClaimsValidator, extra ...jwt.Option) (*jwt.Claims, error) {
	t.Helper()
	opts := append([]jwt.Option{
		jwt.WithExpectedIssuer(itIssuer),
		jwt.WithExpectedAudience(itAudience),
		jwt.WithClaimsValidator(v),
	}, extra...)
	return jwt.Validate(context.Background(), token, itKeySet(t), opts...)
}

// The injected validator accepts a real, signed, otherwise-valid token.
func TestIntegration_PassingValidator_AcceptsRealToken(t *testing.T) {
	token := itSignedToken(t, map[string]any{"scope": "read"})
	claims, err := itValidate(t, token, itRequireScopes(t, "read"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "mock-subject" {
		t.Errorf("sub = %q, want mock-subject", claims.Subject)
	}
}

// The token is genuinely valid (signature/aud/iss all pass) — only the injected
// validator rejects it, proving the hook runs in the real pipeline.
func TestIntegration_RejectingValidator_RejectsAfterStandardChecks(t *testing.T) {
	token := itSignedToken(t, map[string]any{"scope": "read"})
	_, err := itValidate(t, token, itRequireScopes(t, "admin"))
	var cve *jwt.ClaimsValidationError
	if !errors.As(err, &cve) {
		t.Fatalf("err = %v, want *ClaimsValidationError", err)
	}
	if cve.Claim != "scope" || !bytes.Contains([]byte(cve.Reason), []byte("admin")) {
		t.Errorf("err = %+v, want scope/admin rejection", cve)
	}
}

// Composed validators run through the real pipeline.
func TestIntegration_CombinedValidators_ThroughRealPipeline(t *testing.T) {
	token := itSignedToken(t, map[string]any{"scope": "read"})
	validator, err := jwt.CombineClaimsValidators([]jwt.ClaimsValidator{
		itRequireClaims(t, "sub"),
		jwt.RequireClaimValue("iss", itIssuer),
		itRequireScopes(t, "read"),
	}, jwt.CombineAll)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	claims, err := itValidate(t, token, validator)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, err := claims.GetString("scope"); err != nil || got != "read" {
		t.Errorf("scope = %q, %v", got, err)
	}
}

// The structured rejection is logged server-side even though it propagates
// unwrapped (parity with the Python pipeline logging).
func TestIntegration_RejectionIsLoggedServerSide(t *testing.T) {
	token := itSignedToken(t, nil)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	_, err := itValidate(t, token, itRequireClaims(t, "nonexistent_claim"), jwt.WithLogger(logger))
	if !errors.Is(err, jwt.ErrClaimsValidation) {
		t.Fatalf("err = %v, want a claims-validation rejection", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("claims validation rejected")) {
		t.Errorf("log %q missing rejection message", out)
	}
	if !bytes.Contains([]byte(out), []byte("nonexistent_claim")) {
		t.Errorf("log %q missing the specific reason", out)
	}
}

// A signature failure short-circuits before the injected validator runs, so a
// validator that would otherwise accept never masks an invalid signature
// (ordering proof: application policy sees only cryptographically-valid tokens).
func TestIntegration_ValidatorNotReachedWhenSignatureFails(t *testing.T) {
	// A token whose kid is absent from the served JWKS fails key resolution.
	var priv jose.JSONWebKey
	if err := priv.UnmarshalJSON(itFixture(t, "signing-key.jwk.json")); err != nil {
		t.Fatalf("parse signing key: %v", err)
	}
	priv.KeyID = "unpublished-kid"
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &priv}, (&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": itIssuer, "sub": "s", "aud": itAudience,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	obj, _ := signer.Sign(payload)
	token, _ := obj.CompactSerialize()

	var reached bool
	v := jwt.ClaimsValidatorFunc(func(*jwt.Claims) error { reached = true; return nil })
	if _, err := itValidate(t, token, v); err == nil {
		t.Fatal("expected key-resolution failure, got nil")
	}
	if reached {
		t.Error("claims validator ran despite a failed signature/key resolution")
	}
}
