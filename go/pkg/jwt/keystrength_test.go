package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// The default allowlist matches Python's DEFAULT_ALLOWED_ALGORITHMS, EdDSA
// included (#952).
func TestDefaultAllowedAlgorithms_IncludeEdDSA(t *testing.T) {
	want := []string{
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA",
	}
	if !reflect.DeepEqual(defaultAllowedAlgorithms, want) {
		t.Fatalf("defaultAllowedAlgorithms = %v, want %v", defaultAllowedAlgorithms, want)
	}
}

// JWT-015: an Ed25519 token verifies under the default allowlist.
func TestValidate_EdDSA_DefaultAllowlist(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &jose.JSONWebKey{Key: priv, KeyID: "ed-key-1", Algorithm: "EdDSA", Use: "sig"}
	set := keySetFromJSON(t, jwksJSON(t, jose.JSONWebKey{Key: pub, KeyID: "ed-key-1", Use: "sig"}))

	token := signWith(t, signer, jose.EdDSA, validClaims())
	claims, err := Validate(context.Background(), token, set, withFixedNow())
	if err != nil {
		t.Fatalf("Validate EdDSA: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("sub = %q, want user-123", claims.Subject)
	}
}

// An Ed25519 token whose signature doesn't verify is a signature error, not a
// key conversion error: the OKP key converts.
func TestValidate_EdDSA_BadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &jose.JSONWebKey{Key: other, KeyID: "ed-key-1", Algorithm: "EdDSA"}
	set := keySetFromJSON(t, jwksJSON(t, jose.JSONWebKey{Key: pub, KeyID: "ed-key-1", Use: "sig"}))

	_, err = Validate(context.Background(), signWith(t, signer, jose.EdDSA, validClaims()), set, withFixedNow())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// JWT-014: a token whose kid resolves to a weak key fails with a typed
// WeakKeyError and does not refresh the JWK Set.
func TestValidate_WeakKey_Rejected(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  WeakKeyError
	}{
		{"rsa-1024", "weak-rsa-1024-token.txt", WeakKeyError{Kid: "weak-rsa-1024", Kty: "RSA", Bits: 1024, MinBits: MinRSAKeyBits}},
		{"ec-p192", "weak-ec-p192-token.txt", WeakKeyError{Kid: "weak-ec-p192", Kty: "EC", Bits: 192, MinBits: MinECKeyBits}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, fetches := countingKeySet(t, readFixture(t, "jwks.json"))
			token := strings.TrimSpace(string(readFixture(t, tc.token)))

			_, err := Validate(context.Background(), token, set, withFixedNow())
			if !errors.Is(err, ErrWeakKey) {
				t.Fatalf("err = %v, want ErrWeakKey", err)
			}
			var weak *WeakKeyError
			if !errors.As(err, &weak) {
				t.Fatalf("err = %T, want *WeakKeyError", err)
			}
			if *weak != tc.want {
				t.Errorf("WeakKeyError = %+v, want %+v", *weak, tc.want)
			}
			if *fetches != 1 {
				t.Errorf("JWKS fetched %d times, want 1 (a weak key is not a kid miss)", *fetches)
			}
		})
	}
}

// weakRSAKeySet serves the JWT-014 1024-bit RSA key with its n member
// rewritten by edit, counting JWKS fetches.
func weakRSAKeySet(t *testing.T, edit func(n string) string) (*jwks.JSONWebKeySet, *int) {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(readFixture(t, "jwks.json"), &doc); err != nil {
		t.Fatalf("parse jwks fixture: %v", err)
	}
	for _, k := range doc.Keys {
		if k["kid"] == "weak-rsa-1024" {
			k["n"] = edit(k["n"].(string))
			b, err := json.Marshal(map[string]any{"keys": []map[string]any{k}})
			if err != nil {
				t.Fatalf("encode jwks: %v", err)
			}
			return countingKeySet(t, b)
		}
	}
	t.Fatal("jwks fixture has no weak-rsa-1024 key")
	return nil, nil
}

// A weak modulus never verifies, however its n member is spelled: the floor
// measures the converted key, so a base64url spelling the JWK check and key
// conversion read differently cannot skip it (CWE-326).
func TestValidate_WeakKey_PaddedModulusNeverVerifies(t *testing.T) {
	set, fetches := weakRSAKeySet(t, func(n string) string { return n + "=" })
	token := strings.TrimSpace(string(readFixture(t, "weak-rsa-1024-token.txt")))

	_, err := Validate(context.Background(), token, set, withFixedNow())
	if !errors.Is(err, ErrWeakKey) && !errors.Is(err, ErrKeyConversion) {
		t.Fatalf("err = %v, want ErrWeakKey or ErrKeyConversion", err)
	}
	if *fetches != 1 {
		t.Errorf("JWKS fetched %d times, want 1", *fetches)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// modulus returns a big-endian modulus of exactly bits bits, left-padded to
// size octets.
func modulus(bits, size int) string {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return b64(n.FillBytes(make([]byte, size)))
}

func TestCheckKeyStrength(t *testing.T) {
	coord := func(octets int) string { return b64(make([]byte, octets)) }
	cases := []struct {
		name string
		key  jwks.JSONWebKey
		want *WeakKeyError
	}{
		{"ec-p224", jwks.JSONWebKey{Kty: "EC", Crv: "P-224", X: coord(28), Y: coord(28)}, nil},
		{"ec-p521", jwks.JSONWebKey{Kty: "EC", Crv: "P-521", X: coord(66), Y: coord(66)}, nil},
		{"ec-p192", jwks.JSONWebKey{Kid: "k", Kty: "EC", Crv: "P-192", X: coord(24), Y: coord(24)},
			&WeakKeyError{Kid: "k", Kty: "EC", Bits: 192, MinBits: MinECKeyBits}},
		// RSA is measured after conversion; OKP is fixed-size and oct isn't
		// asymmetric. Missing or undecodable material is left to key
		// conversion, as in Python and Rust.
		{"rsa", jwks.JSONWebKey{Kty: "RSA", N: modulus(1024, 128), E: "AQAB"}, nil},
		{"okp", jwks.JSONWebKey{Kty: "OKP", Crv: "Ed25519", X: coord(1)}, nil},
		{"oct", jwks.JSONWebKey{Kty: "oct"}, nil},
		{"ec-undecodable-x", jwks.JSONWebKey{Kty: "EC", Crv: "P-256", X: "!!", Y: coord(32)}, nil},
		{"ec-empty-x", jwks.JSONWebKey{Kty: "EC", Crv: "P-256", Y: coord(32)}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertWeakKey(t, checkKeyStrength(&tc.key), tc.want)
		})
	}
}

func TestCheckConvertedKeyStrength(t *testing.T) {
	bigN := func(bits int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) }
	ecKey := func(c elliptic.Curve) *ecdsa.PublicKey { return &ecdsa.PublicKey{Curve: c} }
	okp, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		kty  string
		pub  crypto.PublicKey
		want *WeakKeyError
	}{
		{"rsa-2048", "RSA", &rsa.PublicKey{N: bigN(2048), E: 65537}, nil},
		{"rsa-2047", "RSA", &rsa.PublicKey{N: bigN(2047), E: 65537},
			&WeakKeyError{Kid: "k", Kty: "RSA", Bits: 2047, MinBits: MinRSAKeyBits}},
		{"rsa-1024", "RSA", &rsa.PublicKey{N: bigN(1024), E: 65537},
			&WeakKeyError{Kid: "k", Kty: "RSA", Bits: 1024, MinBits: MinRSAKeyBits}},
		{"ec-p224", "EC", ecKey(elliptic.P224()), nil},
		{"ec-p256", "EC", ecKey(elliptic.P256()), nil},
		{"okp", "OKP", okp, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := jwks.JSONWebKey{Kid: "k", Kty: tc.kty}
			assertWeakKey(t, checkConvertedKeyStrength(&k, tc.pub), tc.want)
		})
	}
}

func assertWeakKey(t *testing.T, err error, want *WeakKeyError) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		return
	}
	var weak *WeakKeyError
	if !errors.As(err, &weak) {
		t.Fatalf("err = %v, want *WeakKeyError", err)
	}
	if *weak != *want {
		t.Errorf("WeakKeyError = %+v, want %+v", *weak, *want)
	}
}

func TestMinimumKeyBits(t *testing.T) {
	if MinRSAKeyBits != 2048 || MinECKeyBits != 224 {
		t.Fatalf("floors = (%d, %d), want (2048, 224)", MinRSAKeyBits, MinECKeyBits)
	}
}

func TestToPublicKey_OKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := toPublicKey(&jwks.JSONWebKey{Kty: "OKP", Crv: "Ed25519", X: b64(pub)})
	if err != nil {
		t.Fatalf("toPublicKey: %v", err)
	}
	if !reflect.DeepEqual(got, pub) {
		t.Errorf("toPublicKey = %v, want %v", got, pub)
	}
}
