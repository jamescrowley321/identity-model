package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// Minimum verification key sizes. RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an
// RSA key of 2048 bits or larger; FAPI 2.0 Security Profile §5.4.1 requires at
// least 224 bits for elliptic curve keys.
const (
	MinRSAKeyBits = 2048
	MinECKeyBits  = 224
)

// checkKeyStrength rejects, before conversion, an EC verification key below the
// floor with a [WeakKeyError]. go-jose converts only P-256, P-384 and P-521, so a
// smaller curve is measured on the JWK: 8 times the octet length of the x
// coordinate, which RFC 7518 §6.2.1.2 requires to be the full coordinate size
// for the curve. RSA keys are measured after conversion by
// [checkConvertedKeyStrength]. Material that is missing or doesn't decode is
// left to key conversion.
func checkKeyStrength(k *jwks.JSONWebKey) error {
	if k.Kty != "EC" {
		return nil
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) == 0 {
		return nil
	}
	return floor(k, len(x)*8, MinECKeyBits)
}

// checkConvertedKeyStrength rejects a converted verification key below the
// floor with a [WeakKeyError]. It measures the key that verifies the
// signature — the RSA modulus bit length and the EC curve size — so no
// spelling of the JWK members can skip the floor (CWE-326). OKP keys are fixed
// size and have no floor.
func checkConvertedKeyStrength(k *jwks.JSONWebKey, pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return floor(k, key.N.BitLen(), MinRSAKeyBits)
	case *ecdsa.PublicKey:
		return floor(k, key.Curve.Params().BitSize, MinECKeyBits)
	default:
		return nil
	}
}

func floor(k *jwks.JSONWebKey, bits, minBits int) error {
	if bits < minBits {
		return &WeakKeyError{Kid: k.Kid, Kty: k.Kty, Bits: bits, MinBits: minBits}
	}
	return nil
}
