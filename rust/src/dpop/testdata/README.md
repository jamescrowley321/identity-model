# DPoP key-loading test data

Two deliberately unacceptable private keys, used only by
`key_strength_is_enforced_by_the_backend` in `src/dpop/key.rs` to prove the
loader refuses them:

- `rsa-1024-too-small.pem` — a 1024-bit RSA key, below the RFC 7518 §3.3
  minimum of 2048 bits that DPOP-007 asserts.
- `ec-p384-wrong-curve.pem` — an EC P-384 key, where ES256 requires P-256.

Both were generated for this test, are committed deliberately, and are used for
nothing else. Neither is a credential: no service has ever held the public half.
