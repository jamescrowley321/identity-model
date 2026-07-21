package dpop

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// proofClaims is the payload of a DPoP proof JWT (RFC 9449 §4.2). ath and nonce
// are omitted when empty: ath appears only on resource-request proofs and nonce
// only after a server nonce challenge.
type proofClaims struct {
	Jti   string `json:"jti"`
	Htm   string `json:"htm"`
	Htu   string `json:"htu"`
	Iat   int64  `json:"iat"`
	Ath   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// proofConfig accumulates the optional proof claims.
type proofConfig struct {
	ath   string
	nonce string
	now   func() time.Time
}

// ProofOption customises an optional claim of a generated DPoP proof.
type ProofOption func(*proofConfig)

// WithAth binds the proof to accessToken by adding the ath claim
// (BASE64URL(SHA-256(access_token)), RFC 9449 §4.2). Use it for resource-request
// proofs; token-request proofs omit ath (RFC 9449 §5).
func WithAth(accessToken string) ProofOption {
	return func(c *proofConfig) { c.ath = Ath(accessToken) }
}

// WithNonce adds the server-provided nonce claim, sent when retrying after a
// use_dpop_nonce challenge (RFC 9449 §8).
func WithNonce(nonce string) ProofOption {
	return func(c *proofConfig) { c.nonce = nonce }
}

// withNow overrides the iat clock (test seam).
func withNow(now func() time.Time) ProofOption {
	return func(c *proofConfig) { c.now = now }
}

// Proof builds and signs a DPoP proof JWT for an HTTP request with the given
// method and target uri (RFC 9449 §4.2). The proof header carries
// typ=dpop+jwt, the key's asymmetric alg, and the public jwk; the payload
// carries a fresh random jti, htm=method, htu=uri (normalized to scheme +
// authority + path), and iat=now, plus any ath/nonce from opts. It returns the
// compact serialization to place in the DPoP HTTP header.
func (k *Key) Proof(method, uri string, opts ...ProofOption) (string, error) {
	cfg := &proofConfig{now: time.Now}
	for _, opt := range opts {
		opt(cfg)
	}

	htu, err := normalizeHTU(uri)
	if err != nil {
		return "", err
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	claims := proofClaims{
		Jti:   jti,
		Htm:   method,
		Htu:   htu,
		Iat:   cfg.now().Unix(),
		Ath:   cfg.ath,
		Nonce: cfg.nonce,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", &KeyError{Op: "marshal proof claims", Err: err}
	}

	// EmbedJWK embeds the PUBLIC key only (RFC 9449 §4.2 requires the public jwk
	// and forbids private material); typ marks the JWS as a DPoP proof.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.alg), Key: k.jwk.Key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		return "", &KeyError{Op: "build signer", Err: err}
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", &KeyError{Op: "sign proof", Err: err}
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", &KeyError{Op: "serialize proof", Err: err}
	}
	return compact, nil
}

// Ath computes the DPoP access-token hash claim value for accessToken:
// BASE64URL(SHA-256(access_token)) without padding (RFC 9449 §4.2, DPOP-003).
func Ath(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// normalizeHTU reduces a request URI to the htu form required by RFC 9449 §4.2:
// scheme + authority + path, with the query, fragment, and any userinfo removed.
func normalizeHTU(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", &KeyError{Op: "parse request URI", Err: err}
	}
	if u.Scheme == "" || u.Host == "" {
		return "", &KeyError{Op: "parse request URI", Err: fmt.Errorf("htu requires an absolute URI with scheme and host, got %q", uri)}
	}
	normalized := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return normalized.String(), nil
}

// newJTI returns a fresh 128-bit random identifier, base64url-encoded, for the
// proof's jti replay-prevention claim (RFC 9449 §4.2).
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", &KeyError{Op: "generate jti", Err: err}
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
