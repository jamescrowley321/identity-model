package conformance

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/jamescrowley321/identity-model/go/pkg/dpop"
)

// proofIATWindow bounds how far a freshly built proof's iat may be from now.
const proofIATWindow = 60

// logicString returns a string input field, or "" when absent.
func logicString(v logicVector, key string) string {
	s, _ := v.Input[key].(string)
	return s
}

// readFixture decodes a spec/test-fixtures file into out.
func readFixture(t *testing.T, name string, out any) {
	t.Helper()
	if err := json.Unmarshal(mustReadFixture(t, name), out); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

// fixtureKey loads the private JWK of a key-pair fixture.
func fixtureKey(t *testing.T, name string) *dpop.Key {
	t.Helper()
	var kp struct {
		Private json.RawMessage `json:"private"`
	}
	readFixture(t, name, &kp)
	key, err := dpop.KeyFromJWK(kp.Private)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return key
}

// proofJTI returns the jti claim of a compact proof, without verifying it.
func proofJTI(t *testing.T, label, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("%s: proof is not a compact JWS", label)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("%s: decode payload: %v", label, err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return claims.JTI
}

// assertProof verifies proof against key, then compares its decoded header and
// payload with want. jti and iat are generated, so they are only checked for
// presence and freshness.
func assertProof(t *testing.T, label, proof string, key *dpop.Key, want map[string]any) {
	t.Helper()
	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		t.Fatalf("%s: parse proof: %v", label, err)
	}
	payloadJSON, err := jws.Verify(key.Public())
	if err != nil {
		t.Fatalf("%s: proof signature: %v", label, err)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[0])
	if err != nil {
		t.Fatalf("%s: decode header: %v", label, err)
	}
	var header, payload map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if !reflect.DeepEqual(header, want["header"]) {
		t.Errorf("%s: header = %v, want %v", label, header, want["header"])
	}
	if jti, _ := payload["jti"].(string); jti == "" {
		t.Errorf("%s: jti = %v, want a non-empty string", label, payload["jti"])
	}
	if iat, _ := payload["iat"].(float64); math.Abs(iat-float64(time.Now().Unix())) > proofIATWindow {
		t.Errorf("%s: iat = %v, not within %ds of now", label, payload["iat"], proofIATWindow)
	}
	delete(payload, "jti")
	delete(payload, "iat")
	if !reflect.DeepEqual(payload, want["payload"]) {
		t.Errorf("%s: payload = %v, want %v", label, payload, want["payload"])
	}
}

func runCreateProofVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	key := fixtureKey(t, logicString(v, "key"))
	var opts []dpop.ProofOption
	if at := logicString(v, "access_token"); at != "" {
		opts = append(opts, dpop.WithAth(at))
	}
	// Build two proofs: each must match the vector, and their jti must differ.
	jtis := map[string]bool{}
	for range 2 {
		proof, err := key.Proof(logicString(v, "htm"), logicString(v, "htu"), opts...)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		assertProof(t, label, proof, key, v.Expect.Result)
		jti := proofJTI(t, label, proof)
		if jtis[jti] {
			t.Errorf("%s: jti %q reused across proofs", label, jti)
		}
		jtis[jti] = true
	}
}

func runAthVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	var fx struct {
		Pairs []struct {
			AccessToken string `json:"access_token"`
			Ath         string `json:"ath"`
		} `json:"pairs"`
	}
	readFixture(t, logicString(v, "pairs"), &fx)
	if len(fx.Pairs) == 0 {
		t.Fatalf("%s: no pairs in %s", label, logicString(v, "pairs"))
	}
	for _, p := range fx.Pairs {
		if got := dpop.Ath(p.AccessToken); got != p.Ath {
			t.Errorf("%s: ath(%q) = %q, want %q", label, p.AccessToken, got, p.Ath)
		}
	}
}

func runThumbprintVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	got, err := fixtureKey(t, logicString(v, "key")).Thumbprint()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if want := v.Expect.Result["thumbprint"]; got != want {
		t.Errorf("%s: thumbprint = %q, want %v", label, got, want)
	}
	if bound := logicString(v, "bound_token"); bound != "" {
		var tok struct {
			Payload struct {
				Cnf struct {
					Jkt string `json:"jkt"`
				} `json:"cnf"`
			} `json:"payload"`
		}
		readFixture(t, bound, &tok)
		if tok.Payload.Cnf.Jkt != got {
			t.Errorf("%s: cnf.jkt = %q, want the key thumbprint %q", label, tok.Payload.Cnf.Jkt, got)
		}
	}
}

func runVerifyProofVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	nowSec, _ := v.Input["now"].(float64)
	now := time.Unix(int64(nowSec), 0)
	opts := []dpop.VerifyOption{dpop.WithNow(func() time.Time { return now })}
	if at, ok := v.Input["access_token"].(string); ok {
		opts = append(opts, dpop.WithExpectedAth(at))
	}
	if nonce, ok := v.Input["nonce"].(string); ok {
		opts = append(opts, dpop.WithExpectedNonce(nonce))
	}
	p, err := dpop.VerifyProof(logicString(v, "proof"), logicString(v, "htm"), logicString(v, "htu"), opts...)

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		got := map[string]any{
			"jti": p.JTI, "htm": p.HTM, "htu": p.HTU, "iat": float64(p.IAT), "thumbprint": p.Thumbprint,
		}
		if !reflect.DeepEqual(got, v.Expect.Result) {
			t.Errorf("%s: proof = %v, want %v", label, got, v.Expect.Result)
		}
	case OutcomeReject:
		if v.Expect.Error != "invalid_dpop_proof" {
			t.Fatalf("%s: unknown expected error %q", label, v.Expect.Error)
		}
		var ve *dpop.VerificationError
		if !errors.As(err, &ve) {
			t.Fatalf("%s: expected VerificationError, got %v", label, err)
		}
		if got := []string{ve.Field}; !slices.Equal(got, v.Expect.Fields) {
			t.Errorf("%s: fields = %v, want %v", label, got, v.Expect.Fields)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
}

func runGenerateKeyVector(t *testing.T, label string, v logicVector) {
	t.Helper()
	key, err := dpop.GenerateKey(dpop.Algorithm(logicString(v, "alg")))

	switch v.Expect.Outcome {
	case OutcomeAccept:
		if err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		pub := key.PublicJWK()
		b, err := pub.MarshalJSON()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var jwk map[string]string
		if err := json.Unmarshal(b, &jwk); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		want := maps.Clone(v.Expect.Result)
		minBits, wantRSA := want["min_modulus_bits"].(float64)
		delete(want, "min_modulus_bits")
		got := map[string]any{"kty": jwk["kty"]}
		if crv, ok := jwk["crv"]; ok {
			got["crv"] = crv
		}
		if n, ok := jwk["n"]; ok != wantRSA {
			t.Errorf("%s: modulus present = %v, want %v", label, ok, wantRSA)
		} else if ok {
			raw, err := base64.RawURLEncoding.DecodeString(n)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if bits := new(big.Int).SetBytes(raw).BitLen(); float64(bits) < minBits {
				t.Errorf("%s: modulus is %d bits, want at least %v", label, bits, minBits)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: key = %v, want %v", label, got, want)
		}
	case OutcomeReject:
		if v.Expect.Error != "unsupported_algorithm" {
			t.Fatalf("%s: unknown expected error %q", label, v.Expect.Error)
		}
		var ue *dpop.UnsupportedAlgorithmError
		if !errors.As(err, &ue) {
			t.Fatalf("%s: expected UnsupportedAlgorithmError, got %v", label, err)
		}
	default:
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
}
