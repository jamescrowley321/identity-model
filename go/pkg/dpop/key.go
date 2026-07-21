package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// Algorithm identifies a DPoP proof signing algorithm. DPoP requires an
// asymmetric algorithm (RFC 9449 §4.2); this package supports the two the spec
// mandates every implementation provide (RFC 9449 §4.1).
type Algorithm string

const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4). Keys are EC P-256.
	ES256 Algorithm = "ES256"
	// RS256 is RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3). Keys are RSA of
	// at least 2048 bits.
	RS256 Algorithm = "RS256"
)

// rsaKeyBits is the modulus size for a generated RS256 key. RFC 7518 §3.3
// requires at least 2048 bits; DPOP-007 asserts the minimum.
const rsaKeyBits = 2048

// Key is a DPoP key pair: the private key used to sign proof JWTs plus its
// algorithm. The public half is embedded in every proof's jwk header
// (RFC 9449 §4.2) and its RFC 7638 thumbprint is the value an authorization
// server binds a token to via cnf.jkt (RFC 9449 §6).
type Key struct {
	alg Algorithm
	jwk *jose.JSONWebKey // private key, Algorithm and Use set
}

// GenerateKey generates a fresh DPoP key pair for alg. ES256 produces an EC
// P-256 key and RS256 a 2048-bit RSA key (RFC 9449 §4.1, DPOP-007). Any other
// algorithm returns an [UnsupportedAlgorithmError].
func GenerateKey(alg Algorithm) (*Key, error) {
	var priv crypto.PrivateKey
	switch alg {
	case ES256:
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, &KeyError{Op: "generate ES256 key", Err: err}
		}
		priv = ec
	case RS256:
		rk, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, &KeyError{Op: "generate RS256 key", Err: err}
		}
		priv = rk
	default:
		return nil, &UnsupportedAlgorithmError{Alg: string(alg)}
	}
	return newKey(priv, alg)
}

// newKey wraps a raw private key in a Key, validating that its type matches alg.
func newKey(priv crypto.PrivateKey, alg Algorithm) (*Key, error) {
	if err := validateKeyType(priv, alg); err != nil {
		return nil, err
	}
	return &Key{
		alg: alg,
		jwk: &jose.JSONWebKey{Key: priv, Algorithm: string(alg), Use: "sig"},
	}, nil
}

// validateKeyType confirms priv is the concrete key type alg requires, so a
// caller cannot load, say, an RSA key and label it ES256.
func validateKeyType(priv crypto.PrivateKey, alg Algorithm) error {
	switch alg {
	case ES256:
		ec, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return &KeyError{Op: "load key", Err: fmt.Errorf("ES256 requires an EC P-256 key, got %T", priv)}
		}
		if ec.Curve != elliptic.P256() {
			return &KeyError{Op: "load key", Err: fmt.Errorf("ES256 requires curve P-256")}
		}
		return nil
	case RS256:
		rk, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return &KeyError{Op: "load key", Err: fmt.Errorf("RS256 requires an RSA key, got %T", priv)}
		}
		if rk.N.BitLen() < rsaKeyBits {
			return &KeyError{Op: "load key", Err: fmt.Errorf("RS256 requires a modulus of at least %d bits, got %d", rsaKeyBits, rk.N.BitLen())}
		}
		return nil
	default:
		return &UnsupportedAlgorithmError{Alg: string(alg)}
	}
}

// Algorithm returns the key's DPoP signing algorithm.
func (k *Key) Algorithm() Algorithm { return k.alg }

// Public returns the crypto.PublicKey half of the pair.
func (k *Key) Public() crypto.PublicKey { return k.jwk.Public().Key }

// PublicJWK returns the public key as a go-jose JSON Web Key, the form embedded
// in a proof's jwk header (RFC 9449 §4.2). It carries no private material.
func (k *Key) PublicJWK() jose.JSONWebKey { return k.jwk.Public() }

// Thumbprint returns the RFC 7638 SHA-256 JWK Thumbprint of the public key,
// base64url-encoded without padding. This is the value an authorization server
// places in a DPoP-bound token's cnf.jkt (RFC 9449 §6, DPOP-005).
func (k *Key) Thumbprint() (string, error) {
	pub := k.jwk.Public()
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", &KeyError{Op: "compute thumbprint", Err: err}
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// KeyFromJWK loads a DPoP key pair from a private-key JWK (RFC 7517). The JWK's
// alg member, when present, selects the algorithm; otherwise it is inferred from
// the key type (EC → ES256, RSA → RS256).
func KeyFromJWK(data []byte) (*Key, error) {
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		return nil, &KeyError{Op: "parse JWK", Err: err}
	}
	if jwk.IsPublic() {
		return nil, &KeyError{Op: "parse JWK", Err: fmt.Errorf("JWK contains no private key material")}
	}
	alg, err := algForJWK(&jwk)
	if err != nil {
		return nil, err
	}
	return newKey(jwk.Key, alg)
}

// algForJWK resolves the DPoP algorithm for a loaded JWK from its alg member, or
// from the underlying key type when alg is absent.
func algForJWK(jwk *jose.JSONWebKey) (Algorithm, error) {
	switch jwk.Algorithm {
	case string(ES256):
		return ES256, nil
	case string(RS256):
		return RS256, nil
	case "":
		switch jwk.Key.(type) {
		case *ecdsa.PrivateKey:
			return ES256, nil
		case *rsa.PrivateKey:
			return RS256, nil
		}
	}
	return "", &UnsupportedAlgorithmError{Alg: jwk.Algorithm}
}

// MarshalPrivateJWK serializes the full key pair (including private material) as
// a JWK, for persistence. Pair it with [KeyFromJWK] to reload.
func (k *Key) MarshalPrivateJWK() ([]byte, error) {
	b, err := k.jwk.MarshalJSON()
	if err != nil {
		return nil, &KeyError{Op: "marshal JWK", Err: err}
	}
	return b, nil
}

// KeyFromPEM loads a DPoP key pair from a PEM-encoded PKCS#8 (or PKCS#1 RSA / SEC1
// EC) private key, tagging it with alg. The key type must match alg.
func KeyFromPEM(data []byte, alg Algorithm) (*Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &KeyError{Op: "parse PEM", Err: fmt.Errorf("no PEM block found")}
	}
	priv, err := parsePEMPrivateKey(block)
	if err != nil {
		return nil, &KeyError{Op: "parse PEM", Err: err}
	}
	return newKey(priv, alg)
}

// parsePEMPrivateKey decodes the DER in a PEM block, trying the PKCS#8, PKCS#1
// (RSA) and SEC1 (EC) encodings so any standard private-key PEM loads.
func parsePEMPrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unrecognized private key PEM (tried PKCS#8, PKCS#1, SEC1)")
}

// MarshalPKCS8PEM serializes the private key as a PKCS#8 PEM block, for
// persistence. Pair it with [KeyFromPEM] to reload.
func (k *Key) MarshalPKCS8PEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.jwk.Key)
	if err != nil {
		return nil, &KeyError{Op: "marshal PKCS#8", Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
