//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jamescrowley321/identity-model/go/pkg/dpop"
	"github.com/jamescrowley321/identity-model/go/pkg/token"
	"github.com/jamescrowley321/identity-model/go/pkg/userinfo"
)

// runDPoPVector is the dpop.json adapter for the HTTP flows: the token-request
// proof, the use_dpop_nonce retry and the resource-request proof, sent through
// a dpop.Transport. Each send's proof is read back from the fixture's
// _requests and verified against the key-pair fixture. The pure-logic DPoP
// vectors run in TestLogicVectors.
func runDPoPVector(t *testing.T, label, base string, v HTTPVector) {
	t.Helper()
	if v.Expect.Outcome != OutcomeAccept {
		t.Fatalf("%s: unknown expected outcome %q", label, v.Expect.Outcome)
	}
	key := fixtureKey(t, inputString(v, "key"))
	ctx := context.Background()

	// One transport serves every request, so a server nonce can be reused.
	var path string
	var send func() error
	switch op := inputString(v, "operation"); op {
	case "resource_request":
		path = "/userinfo"
		at := inputString(v, "access_token")
		client := &http.Client{Transport: dpop.NewTransport(key, dpop.WithAccessToken(at))}
		send = func() error {
			_, err := userinfo.Fetch(ctx, base+path, at,
				userinfo.WithHTTPClient(client), userinfo.WithInsecureAllowHTTP())
			return err
		}
	case "token_request":
		path = "/token"
		client := &http.Client{Transport: dpop.NewTransport(key)}
		send = func() error {
			_, err := token.AuthorizationCode(ctx, base+path, "cid", inputString(v, "code"),
				inputString(v, "redirect_uri"), token.WithClientSecret("secret"),
				token.WithHTTPClient(client), token.WithInsecureAllowHTTP())
			return err
		}
	default:
		t.Fatalf("%s: unknown operation %q", label, op)
	}

	wantJSON, err := json.Marshal(v.Expect.Result)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(wantJSON), fixtureHost, base)), &want); err != nil {
		t.Fatalf("%s: %v", label, err)
	}

	requests := 1
	if n, ok := v.Input["requests"].(float64); ok {
		requests = int(n)
	}
	for range requests {
		if err := send(); err != nil {
			t.Fatalf("%s: expected accept, got %v", label, err)
		}
		seen := recordedProofs(t, label, base, path)
		assertProof(t, label, seen[len(seen)-1], key, want)
	}

	// Every proof sent, including a nonce retry's, must carry a fresh jti.
	jtis := map[string]bool{}
	for _, proof := range recordedProofs(t, label, base, path) {
		jti := proofJTI(t, label, proof)
		if jtis[jti] {
			t.Errorf("%s: jti %q reused across proofs", label, jti)
		}
		jtis[jti] = true
	}
}

// recordedProofs returns the DPoP header of each request the fixture has
// received for base+path, in order. It fails t when there are none.
func recordedProofs(t *testing.T, label, base, path string) []string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/_requests")
	if err != nil {
		t.Fatalf("%s: _requests: %v", label, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var got struct {
		Requests map[string][]struct {
			Headers map[string]any `json:"headers"`
		} `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("%s: decode _requests: %v", label, err)
	}
	var proofs []string
	for _, r := range got.Requests[path] {
		proof, ok := r.Headers["dpop"].(string)
		if !ok {
			t.Fatalf("%s: a request to %s carried no single DPoP header", label, path)
		}
		proofs = append(proofs, proof)
	}
	if len(proofs) == 0 {
		t.Fatalf("%s: no requests recorded to %s", label, path)
	}
	return proofs
}
