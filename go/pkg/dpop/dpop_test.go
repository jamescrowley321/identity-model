package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fixture reads a shared conformance fixture from spec/test-fixtures/dpop.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// test file lives at go/pkg/dpop; fixtures at <repo>/spec/test-fixtures.
	path := filepath.Join("..", "..", "..", "spec", "test-fixtures", "dpop", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// decodeProof splits a compact DPoP proof JWS into its decoded protected
// header and payload so tests can inspect individual members without a full
// verification pass.
func decodeProof(t *testing.T, compact string) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a compact JWS with 3 parts: got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode proof header: %v", err)
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("unmarshal proof header: %v", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode proof payload: %v", err)
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		t.Fatalf("unmarshal proof payload: %v", err)
	}
	return header, payload
}

// DPOP-001: a generated token-request proof has a protected header with
// typ=dpop+jwt, the key's asymmetric alg, and a public-only jwk, and a payload
// with a non-empty jti, htm=POST, htu matching the request, and a recent iat.
func TestProof_TokenRequest_Structure(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const uri = "https://server.example.com/token"
	compact, err := key.Proof(http.MethodPost, uri)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	header, payload := decodeProof(t, compact)

	if header["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want dpop+jwt", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256 (the key's asymmetric algorithm)", header["alg"])
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("header jwk missing or not an object: %v", header["jwk"])
	}
	// The embedded jwk MUST be public-only (RFC 9449 §4.2): no private members.
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, present := jwk[priv]; present {
			t.Errorf("embedded jwk leaks private member %q", priv)
		}
	}

	if jti, _ := payload["jti"].(string); jti == "" {
		t.Error("payload jti is empty")
	}
	if payload["htm"] != http.MethodPost {
		t.Errorf("htm = %v, want POST", payload["htm"])
	}
	if payload["htu"] != uri {
		t.Errorf("htu = %v, want %s", payload["htu"], uri)
	}
	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Fatalf("iat missing or not a number: %v", payload["iat"])
	}
	if delta := time.Since(time.Unix(int64(iat), 0)); delta > 5*time.Second || delta < -5*time.Second {
		t.Errorf("iat is not recent: %v away from now", delta)
	}

	// jti must be unique across proofs (replay prevention).
	compact2, err := key.Proof(http.MethodPost, uri)
	if err != nil {
		t.Fatalf("Proof (second): %v", err)
	}
	_, payload2 := decodeProof(t, compact2)
	if payload["jti"] == payload2["jti"] {
		t.Error("two proofs share the same jti; jti must be unique per proof")
	}
}

// DPOP-001: GenerateKey never yields a symmetric-algorithm key; a symmetric
// alg such as HS256 is rejected outright.
func TestGenerateKey_RejectsSymmetric(t *testing.T) {
	if _, err := GenerateKey("HS256"); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("GenerateKey(HS256) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// DPOP-001/DPOP-002: the token-request proof fixture documents the expected
// decoded shape — typ=dpop+jwt, a public jwk, and no ath claim. Assert a fresh
// generated proof matches that shape (the dynamic jti/iat aside).
func TestProof_TokenRequest_MatchesFixture(t *testing.T) {
	var fx struct {
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(fixture(t, "dpop-proof-token-request.json"), &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if fx.Header["typ"] != "dpop+jwt" {
		t.Fatalf("fixture header typ = %v, want dpop+jwt", fx.Header["typ"])
	}
	if _, hasATH := fx.Payload["ath"]; hasATH {
		t.Error("token-request fixture must not carry an ath claim")
	}

	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compact, err := key.Proof(fx.Payload["htm"].(string), fx.Payload["htu"].(string))
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	header, payload := decodeProof(t, compact)
	if header["typ"] != fx.Header["typ"] {
		t.Errorf("generated typ = %v, want %v", header["typ"], fx.Header["typ"])
	}
	if _, hasATH := payload["ath"]; hasATH {
		t.Error("generated token-request proof must not carry an ath claim")
	}
}

// DPOP-002: in token-request mode the Transport sets the DPoP header (carrying a
// proof with no ath) and leaves Authorization untouched.
func TestTransport_TokenMode_NoAuthorizationNoAth(t *testing.T) {
	var gotDPoP, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDPoP = r.Header.Get("DPoP")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := &http.Client{Transport: NewTransport(key)}
	resp, err := client.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()

	if gotDPoP == "" {
		t.Fatal("DPoP header not set on token request")
	}
	if gotAuth != "" {
		t.Errorf("Authorization header = %q, want empty in token mode", gotAuth)
	}
	_, payload := decodeProof(t, gotDPoP)
	if _, hasATH := payload["ath"]; hasATH {
		t.Error("token-mode proof must not carry an ath claim")
	}
}

// DPOP-003: Ath and WithAth produce BASE64URL(SHA-256(access_token)) with no
// padding, matching every deterministic pair in dpop-ath-pairs.json.
func TestAth_MatchesDeterministicPairs(t *testing.T) {
	var fx struct {
		Pairs []struct {
			AccessToken string `json:"access_token"`
			Ath         string `json:"ath"`
		} `json:"pairs"`
	}
	if err := json.Unmarshal(fixture(t, "dpop-ath-pairs.json"), &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fx.Pairs) == 0 {
		t.Fatal("no ath pairs in fixture")
	}

	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	for _, p := range fx.Pairs {
		if got := Ath(p.AccessToken); got != p.Ath {
			t.Errorf("Ath(%q) = %q, want %q", p.AccessToken, got, p.Ath)
		}
		// The same value must appear in a resource-request proof's ath claim.
		compact, err := key.Proof(http.MethodGet, "https://resource.example.com/r", WithAth(p.AccessToken))
		if err != nil {
			t.Fatalf("Proof: %v", err)
		}
		_, payload := decodeProof(t, compact)
		if payload["ath"] != p.Ath {
			t.Errorf("proof ath = %v, want %q", payload["ath"], p.Ath)
		}
	}

	// No base64 padding, ever.
	if strings.Contains(Ath("anything"), "=") {
		t.Error("Ath output contains base64 padding")
	}
}

// DPOP-004: on a 401 use_dpop_nonce challenge the Transport retries once with the
// server nonce in the proof, and caches the nonce for subsequent requests to the
// same host.
func TestTransport_NonceChallengeAndRetry(t *testing.T) {
	var proofs []string
	var challenged bool
	nonce := "server-nonce-abc123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proofs = append(proofs, r.Header.Get("DPoP"))
		if !challenged {
			challenged = true
			w.Header().Set("DPoP-Nonce", nonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := &http.Client{Transport: NewTransport(key)}

	resp, err := client.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200 after retry", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if len(proofs) != 2 {
		t.Fatalf("server saw %d proofs, want 2 (original + retry)", len(proofs))
	}
	// First proof carried no nonce; the retry carried the server nonce.
	if _, p0 := decodeProof(t, proofs[0]); p0["nonce"] != nil {
		t.Errorf("first proof nonce = %v, want none", p0["nonce"])
	}
	if _, p1 := decodeProof(t, proofs[1]); p1["nonce"] != nonce {
		t.Errorf("retry proof nonce = %v, want %q", p1["nonce"], nonce)
	}

	// The nonce is cached: a second request to the same host pre-includes it
	// without needing another challenge.
	resp2, err := client.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatalf("POST (second): %v", err)
	}
	_ = resp2.Body.Close()
	if len(proofs) != 3 {
		t.Fatalf("server saw %d proofs total, want 3", len(proofs))
	}
	if _, p2 := decodeProof(t, proofs[2]); p2["nonce"] != nonce {
		t.Errorf("cached-nonce proof nonce = %v, want %q", p2["nonce"], nonce)
	}
}

// DPOP-005: the RFC 7638 thumbprint of a DPoP public key equals the bound
// token's cnf.jkt, and every JWK in dpop-thumbprint-pairs.json (including the
// RFC 7638 §3.1 canonical RSA vector) reproduces its expected thumbprint.
func TestThumbprint_MatchesBoundTokenAndPairs(t *testing.T) {
	// The ES256 keypair fixture is the key the bound token is bound to.
	var kp struct {
		Private    json.RawMessage `json:"private"`
		Thumbprint string          `json:"thumbprint"`
	}
	if err := json.Unmarshal(fixture(t, "dpop-keypair-es256.json"), &kp); err != nil {
		t.Fatalf("unmarshal keypair fixture: %v", err)
	}
	key, err := KeyFromJWK(kp.Private)
	if err != nil {
		t.Fatalf("KeyFromJWK: %v", err)
	}
	tp, err := key.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if tp != kp.Thumbprint {
		t.Errorf("key thumbprint = %q, want %q", tp, kp.Thumbprint)
	}

	var bound struct {
		Payload struct {
			Cnf struct {
				Jkt string `json:"jkt"`
			} `json:"cnf"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(fixture(t, "dpop-bound-token.json"), &bound); err != nil {
		t.Fatalf("unmarshal bound-token fixture: %v", err)
	}
	if tp != bound.Payload.Cnf.Jkt {
		t.Errorf("cnf.jkt = %q, does not match key thumbprint %q", bound.Payload.Cnf.Jkt, tp)
	}

	// Every JWK/thumbprint pair must recompute correctly.
	var pairs struct {
		Pairs []struct {
			Description string          `json:"description"`
			JWK         json.RawMessage `json:"jwk"`
			Thumbprint  string          `json:"thumbprint"`
		} `json:"pairs"`
	}
	if err := json.Unmarshal(fixture(t, "dpop-thumbprint-pairs.json"), &pairs); err != nil {
		t.Fatalf("unmarshal thumbprint pairs: %v", err)
	}
	if len(pairs.Pairs) == 0 {
		t.Fatal("no thumbprint pairs in fixture")
	}
	for _, p := range pairs.Pairs {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(p.JWK); err != nil {
			t.Errorf("%s: unmarshal jwk: %v", p.Description, err)
			continue
		}
		raw, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Errorf("%s: Thumbprint: %v", p.Description, err)
			continue
		}
		if got := base64.RawURLEncoding.EncodeToString(raw); got != p.Thumbprint {
			t.Errorf("%s: thumbprint = %q, want %q", p.Description, got, p.Thumbprint)
		}
	}
}

// DPOP-006: VerifyProof accepts a well-formed proof and reports the offending
// field when htm or htu do not match the request.
func TestVerifyProof_HTMandHTUMismatch(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const uri = "https://resource.example.com/protected"
	compact, err := key.Proof(http.MethodGet, uri)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// Happy path.
	p, err := VerifyProof(compact, http.MethodGet, uri)
	if err != nil {
		t.Fatalf("VerifyProof (valid) err = %v", err)
	}
	wantTP, _ := key.Thumbprint()
	if p.Thumbprint != wantTP {
		t.Errorf("verified thumbprint = %q, want %q", p.Thumbprint, wantTP)
	}

	// Wrong method → htm field.
	_, err = VerifyProof(compact, http.MethodPost, uri)
	assertVerificationField(t, err, "htm")

	// Wrong URI → htu field.
	_, err = VerifyProof(compact, http.MethodGet, "https://resource.example.com/other")
	assertVerificationField(t, err, "htu")
}

// DPOP-006: VerifyProof rejects a proof signed with a symmetric algorithm, one
// with the embedded jwk stripped, and one whose signature was tampered with.
func TestVerifyProof_RejectsSymmetricMissingJWKAndTampered(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const method, uri = http.MethodGet, "https://resource.example.com/r"

	// Symmetric HS256 proof — must be rejected before any structural check.
	claims := proofClaims{Jti: "x", Htm: method, Htu: uri, Iat: time.Now().Unix()}
	payload, _ := json.Marshal(claims)
	hsSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("HS256 signer: %v", err)
	}
	jws, _ := hsSigner.Sign(payload)
	hsProof, _ := jws.CompactSerialize()
	if _, err := VerifyProof(hsProof, method, uri); !errors.Is(err, ErrVerification) {
		t.Errorf("VerifyProof(HS256) err = %v, want ErrVerification", err)
	}

	// ES256 proof WITHOUT the embedded jwk → missing-jwk rejection.
	noJWKSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.jwk.Key},
		(&jose.SignerOptions{}).WithType("dpop+jwt"), // EmbedJWK not set
	)
	if err != nil {
		t.Fatalf("no-jwk signer: %v", err)
	}
	jws2, _ := noJWKSigner.Sign(payload)
	noJWKProof, _ := jws2.CompactSerialize()
	_, err = VerifyProof(noJWKProof, method, uri)
	assertVerificationField(t, err, "jwk")

	// Tamper with the signature of a valid proof.
	valid, err := key.Proof(method, uri)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	parts := strings.Split(valid, ".")
	parts[2] = flipFirstChar(parts[2])
	tampered := strings.Join(parts, ".")
	if _, err := VerifyProof(tampered, method, uri); !errors.Is(err, ErrVerification) {
		t.Errorf("VerifyProof(tampered) err = %v, want ErrVerification", err)
	}
}

// flipFirstChar returns s with its first base64url character swapped for a
// different valid one, corrupting the signature without changing its length.
func flipFirstChar(s string) string {
	if s == "" {
		return s
	}
	repl := byte('A')
	if s[0] == 'A' {
		repl = 'B'
	}
	return string(repl) + s[1:]
}

// DPOP-007: ES256 yields an EC P-256 key, RS256 yields an RSA key of at least
// 2048 bits, and an unsupported algorithm is rejected.
func TestGenerateKey_AlgorithmProperties(t *testing.T) {
	es, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey(ES256): %v", err)
	}
	ecPub, ok := es.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("ES256 public key type = %T, want *ecdsa.PublicKey", es.Public())
	}
	if ecPub.Curve.Params().Name != "P-256" {
		t.Errorf("ES256 curve = %s, want P-256", ecPub.Curve.Params().Name)
	}

	rs, err := GenerateKey(RS256)
	if err != nil {
		t.Fatalf("GenerateKey(RS256): %v", err)
	}
	rsaPub, ok := rs.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("RS256 public key type = %T, want *rsa.PublicKey", rs.Public())
	}
	if rsaPub.N.BitLen() < 2048 {
		t.Errorf("RS256 modulus = %d bits, want >= 2048", rsaPub.N.BitLen())
	}

	if _, err := GenerateKey("ES999"); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("GenerateKey(ES999) err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// DPOP-008: in resource mode the Transport presents the token with the DPoP
// authorization scheme (not Bearer) and binds the proof with the ath claim.
func TestTransport_ResourceMode_DPoPSchemeAndAth(t *testing.T) {
	const accessToken = "example-dpop-bound-access-token-value"
	var gotAuth, gotDPoP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := &http.Client{Transport: NewTransport(key, WithAccessToken(accessToken))}
	resp, err := client.Get(srv.URL + "/protected")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if gotAuth != "DPoP "+accessToken {
		t.Errorf("Authorization = %q, want %q (DPoP scheme, not Bearer)", gotAuth, "DPoP "+accessToken)
	}
	if strings.HasPrefix(gotAuth, "Bearer") {
		t.Error("Authorization used the Bearer scheme; DPoP-bound tokens must use the DPoP scheme")
	}
	_, payload := decodeProof(t, gotDPoP)
	if payload["ath"] != Ath(accessToken) {
		t.Errorf("proof ath = %v, want %q", payload["ath"], Ath(accessToken))
	}
}

// Adversarial: a proof whose iat is outside the acceptable window is rejected on
// the iat field.
func TestVerifyProof_ExpiredIAT(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const method, uri = http.MethodGet, "https://resource.example.com/r"
	old := time.Now().Add(-10 * time.Minute)
	compact, err := key.Proof(method, uri, withNow(func() time.Time { return old }))
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	_, err = VerifyProof(compact, method, uri)
	assertVerificationField(t, err, "iat")

	// A generous window accepts it.
	if _, err := VerifyProof(compact, method, uri, WithMaxIATAge(time.Hour)); err != nil {
		t.Errorf("VerifyProof with 1h window err = %v, want nil", err)
	}
}

// Adversarial: WithExpectedAth and WithExpectedNonce reject a proof whose claim
// does not match the expected value.
func TestVerifyProof_AthAndNonceMismatch(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const method, uri = http.MethodGet, "https://resource.example.com/r"
	compact, err := key.Proof(method, uri, WithAth("token-A"), WithNonce("nonce-A"))
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	_, err = VerifyProof(compact, method, uri, WithExpectedAth("token-B"))
	assertVerificationField(t, err, "ath")

	_, err = VerifyProof(compact, method, uri, WithExpectedAth("token-A"), WithExpectedNonce("nonce-B"))
	assertVerificationField(t, err, "nonce")

	// Matching expectations verify.
	if _, err := VerifyProof(compact, method, uri, WithExpectedAth("token-A"), WithExpectedNonce("nonce-A")); err != nil {
		t.Errorf("VerifyProof (matching ath+nonce) err = %v, want nil", err)
	}
}

// Adversarial: normalizeHTU strips the query and fragment so htu is the bare
// scheme+authority+path (RFC 9449 §4.2), and a proof for a URI-with-query still
// verifies against the same URI.
func TestProof_HTUStripsQueryAndFragment(t *testing.T) {
	key, err := GenerateKey(ES256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	full := "https://server.example.com/token?foo=bar&baz=1#frag"
	compact, err := key.Proof(http.MethodPost, full)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	_, payload := decodeProof(t, compact)
	if payload["htu"] != "https://server.example.com/token" {
		t.Errorf("htu = %v, want query/fragment stripped", payload["htu"])
	}
	// Verification normalizes the expected URI the same way.
	if _, err := VerifyProof(compact, http.MethodPost, full); err != nil {
		t.Errorf("VerifyProof against query URI err = %v, want nil", err)
	}
}

// Adversarial: Ath of the empty string is still a well-formed (non-empty)
// SHA-256 digest, not an empty string.
func TestAth_EmptyToken(t *testing.T) {
	got := Ath("")
	if got == "" {
		t.Error("Ath(\"\") returned empty; want the SHA-256 digest of the empty string")
	}
	if _, err := base64.RawURLEncoding.DecodeString(got); err != nil {
		t.Errorf("Ath(\"\") is not valid base64url: %v", err)
	}
}

// Persistence: a key round-trips through both JWK and PKCS#8 PEM without
// changing its thumbprint, so a persisted key produces the same cnf.jkt binding.
func TestKey_RoundTripPreservesThumbprint(t *testing.T) {
	for _, alg := range []Algorithm{ES256, RS256} {
		key, err := GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		want, err := key.Thumbprint()
		if err != nil {
			t.Fatalf("Thumbprint: %v", err)
		}

		jwkBytes, err := key.MarshalPrivateJWK()
		if err != nil {
			t.Fatalf("MarshalPrivateJWK: %v", err)
		}
		fromJWK, err := KeyFromJWK(jwkBytes)
		if err != nil {
			t.Fatalf("KeyFromJWK: %v", err)
		}
		if got, _ := fromJWK.Thumbprint(); got != want {
			t.Errorf("%s: JWK round-trip thumbprint = %q, want %q", alg, got, want)
		}

		pemBytes, err := key.MarshalPKCS8PEM()
		if err != nil {
			t.Fatalf("MarshalPKCS8PEM: %v", err)
		}
		fromPEM, err := KeyFromPEM(pemBytes, alg)
		if err != nil {
			t.Fatalf("KeyFromPEM: %v", err)
		}
		if got, _ := fromPEM.Thumbprint(); got != want {
			t.Errorf("%s: PEM round-trip thumbprint = %q, want %q", alg, got, want)
		}
	}

	// A public-only JWK cannot be loaded as a signing key.
	pubOnly := []byte(`{"kty":"EC","crv":"P-256","x":"R1_cAR40t8_oOmoq64DJKyCn_wp_M-31Vxx1KavGTtg","y":"dkMh8R65lFQdtRvkgJ2Ebqp7IcAjS2xhCAUNAHyRaDI"}`)
	if _, err := KeyFromJWK(pubOnly); !errors.Is(err, ErrKey) {
		t.Errorf("KeyFromJWK(public-only) err = %v, want ErrKey", err)
	}
}

// assertVerificationField asserts err is a VerificationError naming field.
func assertVerificationField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a VerificationError for field %q, got nil", field)
	}
	var ve *VerificationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *VerificationError", err)
	}
	if ve.Field != field {
		t.Errorf("VerificationError.Field = %q, want %q", ve.Field, field)
	}
}
