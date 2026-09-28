# DPoP test fixtures

Fixtures backing the `dpop` conformance suite (`spec/vectors/dpop.json`), per
RFC 9449 (Demonstrating Proof of Possession) and RFC 7638 (JWK Thumbprint).

- `dpop-proof-token-request.json` — a decoded DPoP proof JWT (header + payload)
  for a **token request** (RFC 9449 §5). It carries `typ=dpop+jwt`, an asymmetric
  `alg`, the public `jwk`, and the required `jti`/`htm`/`htu`/`iat` claims, and
  deliberately has **no `ath`** claim: token-request proofs do not bind to an
  access token (DPOP-001, DPOP-002). The resource-request proof shape, which
  adds an `ath` claim, is carried by DPOP-003 `resource-proof` in
  `spec/vectors/dpop.json`.
- `dpop-keypair-es256.json` — an EC P-256 (ES256) DPoP key pair in JWK form
  (`public`, `private`) plus its RFC 7638 `thumbprint` (DPOP-005, DPOP-007).
- `dpop-keypair-rs256.json` — an RSA 2048-bit (RS256) DPoP key pair in JWK form
  plus its RFC 7638 `thumbprint` (DPOP-005, DPOP-007).
- `dpop-bound-token.json` — a decoded DPoP-bound access token (RFC 9449 §6). Its
  `cnf.jkt` is the RFC 7638 thumbprint of the ES256 key pair above, binding the
  token to that key (DPOP-005). Its `token_type` is `DPoP`, which drives the
  `Authorization: DPoP` resource-request scheme (DPOP-008).
- `dpop-nonce-error-response.json` — the body of an HTTP 401 `use_dpop_nonce`
  response (RFC 9449 §8); the vector supplies the status and the `DPoP-Nonce` and
  `WWW-Authenticate` headers. The client must retry with the nonce echoed in the
  proof's `nonce` claim (DPOP-004).
- `dpop-token-response.json` — a token endpoint response issuing the DPoP-bound
  token `example-dpop-bound-access-token-value` with `token_type=DPoP`
  (DPOP-002, DPOP-004).
- `dpop-thumbprint-pairs.json` — an array of JWK / expected-thumbprint pairs for
  deterministic RFC 7638 verification (AC-S.13.5), read by the Go `dpop` package
  unit tests. No vector reads it: neither Go nor Python has a thumbprint API for
  a bare public JWK ([#785](https://github.com/jamescrowley321/identity-model/issues/785)),
  so DPOP-005 covers RFC 7638 through each library's key thumbprint. The first entry is
  the **RFC 7638 §3.1 canonical RSA vector** whose published thumbprint is
  `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`, providing a cross-check against
  the RFC's own test vector; the remaining entries are the EC and RSA DPoP keys.
- `dpop-ath-pairs.json` — an array of access_token / expected-ath pairs for
  deterministic `ath` computation verification (DPOP-003, AC-S.13.6). The first
  entry is the RFC 9449 §4.2 canonical example token whose published `ath` is
  `fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo`.

## Vectors

`spec/vectors/dpop.json` carries executable vectors, run by
`go/internal/conformance/dpop_test.go` and
`py/src/tests/unit/test_spec_dpop_conformance.py`. Proof vectors build a proof
with a key-pair fixture, verify its signature against that key and compare the
decoded header and payload (`jti` and `iat` are generated, so only their
presence and freshness are checked), and two proofs built in a row must carry
different `jti` values. The ath vector reads `dpop-ath-pairs.json`; the
thumbprint vectors read the key-pair fixtures. The proof verification vectors
(DPOP-006) carry their proofs inline, signed with the ES256 key pair, and may
supply an expected `access_token` (for `ath`) and `nonce`. The decoded
token-request proof fixture is read only by the Go `dpop` package unit tests.
