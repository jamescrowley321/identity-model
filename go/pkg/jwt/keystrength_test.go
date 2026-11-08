package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
		{"rsa-2048", jwks.JSONWebKey{Kty: "RSA", N: modulus(2048, 256), E: "AQAB"}, nil},
		// Octet counts don't decide: a leading zero octet is ignored, and a
		// 2047-bit modulus in 256 octets is weak.
		{"rsa-2048-leading-zero", jwks.JSONWebKey{Kty: "RSA", N: modulus(2048, 257), E: "AQAB"}, nil},
		{"rsa-2047", jwks.JSONWebKey{Kid: "k", Kty: "RSA", N: modulus(2047, 256), E: "AQAB"},
			&WeakKeyError{Kid: "k", Kty: "RSA", Bits: 2047, MinBits: MinRSAKeyBits}},
		{"ec-p224", jwks.JSONWebKey{Kty: "EC", Crv: "P-224", X: coord(28), Y: coord(28)}, nil},
		{"ec-p521", jwks.JSONWebKey{Kty: "EC", Crv: "P-521", X: coord(66), Y: coord(66)}, nil},
		{"ec-p192", jwks.JSONWebKey{Kty: "EC", Crv: "P-192", X: coord(24), Y: coord(24)},
			&WeakKeyError{Kty: "EC", Bits: 192, MinBits: MinECKeyBits}},
		// OKP is fixed-size and oct isn't asymmetric; material that doesn't
		// decode is left to key conversion.
		{"okp", jwks.JSONWebKey{Kty: "OKP", Crv: "Ed25519", X: coord(1)}, nil},
		{"oct", jwks.JSONWebKey{Kty: "oct"}, nil},
		{"rsa-undecodable-n", jwks.JSONWebKey{Kty: "RSA", N: "!!", E: "AQAB"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeyStrength(&tc.key)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("checkKeyStrength = %v, want nil", err)
				}
				return
			}
			var weak *WeakKeyError
			if !errors.As(err, &weak) {
				t.Fatalf("checkKeyStrength = %v, want *WeakKeyError", err)
			}
			if *weak != *tc.want {
				t.Errorf("WeakKeyError = %+v, want %+v", *weak, *tc.want)
			}
		})
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
