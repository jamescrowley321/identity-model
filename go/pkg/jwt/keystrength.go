package jwt

import (
	"encoding/base64"
	"math/big"

	"github.com/jamescrowley321/identity-model/go/pkg/jwks"
)

// Minimum verification key sizes. RFC 7518 §3.3 (RS*) and §3.5 (PS*) require an
// RSA key of 2048 bits or larger; FAPI 2.0 Security Profile §5.4.1 requires at
// least 224 bits for elliptic curve keys.
const (
	MinRSAKeyBits = 2048
	MinECKeyBits  = 224
)

// checkKeyStrength rejects an RSA or EC verification key below the floor with a
// [WeakKeyError]. RSA strength is the bit length of the modulus n; EC strength is
// 8 times the octet length of the x coordinate, which RFC 7518 §6.2.1.2 requires
// to be the full coordinate size for the curve. OKP keys (fixed size) and oct
// keys have no floor, and material that doesn't decode is left to key
// conversion.
func checkKeyStrength(k *jwks.JSONWebKey) error {
	var bits, minBits int
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil
		}
		bits, minBits = new(big.Int).SetBytes(n).BitLen(), MinRSAKeyBits
	case "EC":
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil
		}
		bits, minBits = len(x)*8, MinECKeyBits
	default:
		return nil
	}
	if bits < minBits {
		return &WeakKeyError{Kid: k.Kid, Kty: k.Kty, Bits: bits, MinBits: minBits}
	}
	return nil
}
