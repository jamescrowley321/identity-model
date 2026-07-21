# DPoP test fixtures

Fixtures backing the `dpop` conformance suite (`spec/conformance/dpop.json`), per
RFC 9449 (Demonstrating Proof of Possession) and RFC 7638 (JWK Thumbprint).

- `dpop-proof-token-request.json` — a decoded DPoP proof JWT (header + payload)
  for a **token request** (RFC 9449 §5). It carries `typ=dpop+jwt`, an asymmetric
  `alg`, the public `jwk`, and the required `jti`/`htm`/`htu`/`iat` claims, and
  deliberately has **no `ath`** claim: token-request proofs do not bind to an
  access token (DPOP-001, DPOP-002).
- `dpop-proof-resource-request.json` — a decoded DPoP proof JWT for a
  **protected-resource request** (RFC 9449 §7). Identical shape plus an `ath`
  claim equal to `BASE64URL(SHA-256(access_token))` (DPOP-003). The `ath` here is
  the hash of `example-dpop-bound-access-token-value` (see `dpop-ath-pairs.json`).
- `dpop-keypair-es256.json` — an EC P-256 (ES256) DPoP key pair in JWK form
  (`public`, `private`) plus its RFC 7638 `thumbprint` (DPOP-005, DPOP-007).
- `dpop-keypair-rs256.json` — an RSA 2048-bit (RS256) DPoP key pair in JWK form
  plus its RFC 7638 `thumbprint` (DPOP-005, DPOP-007).
- `dpop-bound-token.json` — a decoded DPoP-bound access token (RFC 9449 §6). Its
  `cnf.jkt` is the RFC 7638 thumbprint of the ES256 key pair above, binding the
  token to that key (DPOP-005). Its `token_type` is `DPoP`, which drives the
  `Authorization: DPoP` resource-request scheme (DPOP-008).
- `dpop-nonce-error-response.json` — an HTTP 401 `use_dpop_nonce` response with a
  `DPoP-Nonce` header (RFC 9449 §8); the client must retry with the nonce echoed
  in the proof's `nonce` claim (DPOP-004).
- `dpop-thumbprint-pairs.json` — an array of JWK / expected-thumbprint pairs for
  deterministic RFC 7638 verification (DPOP-005, AC-S.13.5). The first entry is
  the **RFC 7638 §3.1 canonical RSA vector** whose published thumbprint is
  `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`, providing a cross-check against
  the RFC's own test vector; the remaining entries are the EC and RSA DPoP keys.
- `dpop-ath-pairs.json` — an array of access_token / expected-ath pairs for
  deterministic `ath` computation verification (DPOP-003, AC-S.13.6). The first
  entry is the RFC 9449 §4.2 canonical example token whose published `ath` is
  `fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo`.

## Format note (DEC-003)

`spec/conformance/dpop.json` follows the same shape as the existing core
conformance files (`discovery.json`, `introspection.json`, …): top-level
`capability` / `spec` / `spec_url` / `required_fields` / `tests[]`, with each test
carrying `id` / `title` / `given` / `when` / `then` / `references[]` and an
optional `fixture`. The referenced `spec/conformance/schema.json` does not exist
in this repo; the established core-file shape is the normative format. The Epic 0F
S.13 field names (`rfc_references`, `fixture_files`) map onto `references` and
`fixture` respectively.
