package dpop

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// maxChallengeBody caps how much of a 4xx nonce-challenge body is read into
// memory to detect a use_dpop_nonce error (RFC 9449 §8). Error bodies are tiny.
const maxChallengeBody = 64 << 10

// Transport is an [http.RoundTripper] that attaches a DPoP proof to every
// request (RFC 9449 §5, §7) and transparently handles the server nonce challenge
// (RFC 9449 §8).
//
// In token-request mode (no access token) it sets only the DPoP proof header. In
// resource mode (see [WithAccessToken]) it also sends the token with the DPoP
// authorization scheme (Authorization: DPoP <token>, NOT Bearer) and binds the
// proof to the token with the ath claim.
//
// Transport owns the DPoP and (in resource mode) Authorization request headers;
// any value a caller set on those headers is replaced.
type Transport struct {
	key         *Key
	base        http.RoundTripper
	accessToken string

	mu     sync.Mutex
	nonces map[string]string // host -> most recent server nonce
}

// TransportOption customises a [Transport].
type TransportOption func(*Transport)

// WithAccessToken puts the transport in resource-request mode: it presents token
// with the DPoP authorization scheme and adds the ath claim to each proof
// (RFC 9449 §7). Omit it for token-endpoint requests (RFC 9449 §5).
func WithAccessToken(token string) TransportOption {
	return func(t *Transport) { t.accessToken = token }
}

// WithBaseTransport sets the underlying RoundTripper. The default is
// [http.DefaultTransport].
func WithBaseTransport(rt http.RoundTripper) TransportOption {
	return func(t *Transport) { t.base = rt }
}

// NewTransport returns a [Transport] signing proofs with key. It panics if key
// is nil, since a nil key cannot sign proofs and would fail every request.
func NewTransport(key *Key, opts ...TransportOption) *Transport {
	if key == nil {
		panic("dpop: NewTransport called with a nil key")
	}
	t := &Transport{key: key, nonces: make(map[string]string)}
	for _, opt := range opts {
		opt(t)
	}
	if t.base == nil {
		t.base = http.DefaultTransport
	}
	return t
}

// RoundTrip attaches a DPoP proof to req and, on a use_dpop_nonce challenge,
// retries once with the server-supplied nonce (RFC 9449 §8).
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	getBody, err := bodyReplay(req)
	if err != nil {
		return nil, err
	}

	host := req.URL.Host
	resp, err := t.do(req, getBody, t.getNonce(host))
	if err != nil {
		return nil, err
	}
	t.cacheNonce(host, resp)

	// A server may reject the first request and supply a nonce to include in the
	// proof (RFC 9449 §8). Retry exactly once with that nonce.
	nonce, retry := t.nonceChallenge(resp)
	if !retry {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxChallengeBody))
	_ = resp.Body.Close()

	resp2, err := t.do(req, getBody, nonce)
	if err != nil {
		return nil, err
	}
	t.cacheNonce(host, resp2)
	return resp2, nil
}

// do clones req, builds a proof (carrying nonce when non-empty), sets the DPoP
// and — in resource mode — Authorization headers, and sends it. getBody yields a
// fresh body for the attempt (nil for a bodyless request). The original request
// is never mutated (RoundTripper contract).
func (t *Transport) do(req *http.Request, getBody func() (io.ReadCloser, error), nonce string) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if getBody != nil {
		rc, err := getBody()
		if err != nil {
			return nil, err
		}
		clone.Body = rc
		clone.GetBody = getBody
	}

	opts := make([]ProofOption, 0, 2)
	if t.accessToken != "" {
		opts = append(opts, WithAth(t.accessToken))
	}
	if nonce != "" {
		opts = append(opts, WithNonce(nonce))
	}
	proof, err := t.key.Proof(req.Method, req.URL.String(), opts...)
	if err != nil {
		return nil, err
	}

	clone.Header.Set("DPoP", proof)
	if t.accessToken != "" {
		// RFC 9449 §7: a DPoP-bound token uses the DPoP scheme, not Bearer.
		clone.Header.Set("Authorization", "DPoP "+t.accessToken)
	}
	return t.base.RoundTrip(clone)
}

// nonceChallenge reports whether resp is a use_dpop_nonce error carrying a new
// DPoP-Nonce (RFC 9449 §8), and returns that nonce. When resp is not a challenge
// its body is left intact so the caller still sees the original response.
func (t *Transport) nonceChallenge(resp *http.Response) (string, bool) {
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		return "", false
	}
	nonce := resp.Header.Get("DPoP-Nonce")
	if nonce == "" {
		return "", false
	}
	// A resource server signals the error via WWW-Authenticate (§7.1); the token
	// endpoint signals it in the JSON error body (§8). Check the header first,
	// then peek the body. The peeked prefix is prepended back onto resp.Body so a
	// non-match leaves the caller with the full, untruncated response body.
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
		return nonce, true
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody))
	resp.Body = &prefixedBody{Reader: io.MultiReader(bytes.NewReader(buf), resp.Body), body: resp.Body}
	var oauthErr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(buf, &oauthErr); err == nil && oauthErr.Error == "use_dpop_nonce" {
		return nonce, true
	}
	return "", false
}

// prefixedBody serves an already-read prefix of a response body followed by its
// remainder, while closing the original underlying body.
type prefixedBody struct {
	io.Reader
	body io.ReadCloser
}

func (p *prefixedBody) Close() error { return p.body.Close() }

func (t *Transport) getNonce(host string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonces[host]
}

func (t *Transport) cacheNonce(host string, resp *http.Response) {
	if n := resp.Header.Get("DPoP-Nonce"); n != "" {
		t.mu.Lock()
		t.nonces[host] = n
		t.mu.Unlock()
	}
}

// bodyReplay returns a factory that yields a fresh copy of req's body for each
// send, so the request can be replayed on a nonce retry (RFC 9449 §8). It prefers
// req.GetBody — which net/http populates for standard bodies — so the body is not
// buffered; it only reads the body into memory when the body is present but not
// rewindable. The original req.Body is always closed (RoundTripper contract).
func bodyReplay(req *http.Request) (func() (io.ReadCloser, error), error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	if req.GetBody != nil {
		_ = req.Body.Close()
		return req.GetBody, nil
	}
	b, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}, nil
}
