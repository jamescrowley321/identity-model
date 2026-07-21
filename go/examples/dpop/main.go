// Command dpop demonstrates a complete OAuth 2.0 DPoP flow (RFC 9449):
// generate a key pair, request a DPoP-bound access token, and call a protected
// resource with that token — highlighting how DPoP differs from Bearer usage.
//
// It is fully self-contained: it starts an in-process authorization server and
// resource server that verify DPoP proofs, so it runs with no external provider:
//
//	go run ./examples/dpop
//
// Each step is annotated with the relevant RFC 9449 section.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"

	"github.com/jamescrowley321/identity-model/go/pkg/dpop"
)

func main() {
	// A DPoP client holds an asymmetric key pair; every proof embeds its public
	// half and is signed by the private half (RFC 9449 §4.1, §4.2).
	key, err := dpop.GenerateKey(dpop.ES256)
	if err != nil {
		fail("generate key", err)
	}
	thumbprint, err := key.Thumbprint()
	if err != nil {
		fail("thumbprint", err)
	}
	fmt.Printf("1. Generated an ES256 DPoP key pair.\n   RFC 7638 thumbprint (jkt): %s\n\n", thumbprint)

	srv := newServer()
	defer srv.Close()

	// --- Token request (RFC 9449 §5) -------------------------------------------
	// In token mode the transport sends only the DPoP proof header — no
	// Authorization, no ath claim.
	tokenClient := &http.Client{Transport: dpop.NewTransport(key)}
	resp, err := tokenClient.Post(srv.URL+"/token", "application/x-www-form-urlencoded",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		fail("token request", err)
	}
	var tok tokenResponse
	decode(resp, &tok)
	fmt.Printf("2. Token request carried a DPoP proof header (RFC 9449 §5).\n")
	fmt.Printf("   Response token_type=%q (RFC 9449 §6 marks the token DPoP-bound), cnf.jkt=%s\n\n",
		tok.TokenType, tok.Jkt)
	if tok.TokenType != "DPoP" {
		fail("token_type", fmt.Errorf("expected DPoP, got %q", tok.TokenType))
	}

	// --- Protected resource request (RFC 9449 §7) ------------------------------
	// In resource mode the transport presents the token with the DPoP scheme
	// (Authorization: DPoP <token>, NOT Bearer) and binds each proof to the token
	// with the ath claim. The resource server here first challenges with
	// use_dpop_nonce (RFC 9449 §8); the transport retries automatically.
	rsClient := &http.Client{Transport: dpop.NewTransport(key, dpop.WithAccessToken(tok.AccessToken))}
	rresp, err := rsClient.Get(srv.URL + "/resource")
	if err != nil {
		fail("resource request", err)
	}
	body := readBody(rresp)
	fmt.Printf("3. Resource request used Authorization: DPoP (not Bearer) + an ath-bound proof (RFC 9449 §7),\n")
	fmt.Printf("   and transparently retried after a use_dpop_nonce challenge (RFC 9449 §8).\n")
	fmt.Printf("   Resource server response (HTTP %d): %s\n\n", rresp.StatusCode, body)
	if rresp.StatusCode != http.StatusOK {
		fail("resource access", fmt.Errorf("HTTP %d", rresp.StatusCode))
	}

	fmt.Println("Bearer vs DPoP: a Bearer token is usable by anyone who holds it; a DPoP-bound")
	fmt.Println("token is useless without a signed proof of the bound private key on every request.")
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Jkt         string `json:"jkt"`
}

// server is an in-process AS (/token) + RS (/resource) that verify DPoP proofs.
type server struct {
	mu      sync.Mutex
	bound   map[string]string // access token -> bound key thumbprint (cnf.jkt)
	nonces  map[string]string // access token -> nonce issued to the client
	counter int
}

func newServer() *httptest.Server {
	s := &server{bound: map[string]string{}, nonces: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/resource", s.resource)
	return httptest.NewServer(mux)
}

// token verifies the token-request proof and issues a DPoP-bound token.
func (s *server) token(w http.ResponseWriter, r *http.Request) {
	proof, err := dpop.VerifyProof(r.Header.Get("DPoP"), r.Method, "http://"+r.Host+r.URL.Path)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_dpop_proof")
		return
	}
	s.mu.Lock()
	s.counter++
	at := fmt.Sprintf("dpop-at-%d", s.counter)
	s.bound[at] = proof.Thumbprint // cnf.jkt (RFC 9449 §6)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": at,
		"token_type":   "DPoP",
		"jkt":          proof.Thumbprint,
	})
}

// resource enforces the DPoP scheme, the nonce challenge, and ath binding.
func (s *server) resource(w http.ResponseWriter, r *http.Request) {
	scheme, at, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if scheme != "DPoP" { // RFC 9449 §7: must be DPoP, not Bearer.
		w.Header().Set("WWW-Authenticate", "DPoP")
		oauthError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	s.mu.Lock()
	nonce, issued := s.nonces[at]
	if !issued {
		// First contact: demand a nonce (RFC 9449 §8).
		nonce = fmt.Sprintf("nonce-%d", len(s.nonces)+1)
		s.nonces[at] = nonce
		s.mu.Unlock()
		w.Header().Set("DPoP-Nonce", nonce)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		oauthError(w, http.StatusUnauthorized, "use_dpop_nonce")
		return
	}
	jkt := s.bound[at]
	s.mu.Unlock()

	proof, err := dpop.VerifyProof(r.Header.Get("DPoP"), r.Method, "http://"+r.Host+r.URL.Path,
		dpop.WithExpectedAth(at), dpop.WithExpectedNonce(nonce))
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_dpop_proof")
		return
	}
	if proof.Thumbprint != jkt { // token must be presented with the key it was bound to.
		oauthError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resource": "secret-data", "sub": "demo"})
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(resp *http.Response, v any) {
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		fail("decode response", err)
	}
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	b, _ := json.Marshal(m)
	return string(b)
}

func fail(op string, err error) {
	fmt.Fprintf(os.Stderr, "dpop demo: %s: %v\n", op, err)
	os.Exit(1)
}
