# DPoP key-loading test data

One deliberately unacceptable private key, used only by
`key_strength_is_enforced_by_the_backend` in `src/dpop/key.rs` to prove the
loader refuses it:

- `rsa-1024-too-small.pem` — a 1024-bit RSA key, below the RFC 7518 §3.3
  minimum of 2048 bits that DPOP-007 asserts.

It is committed rather than generated because it cannot be generated here:
`aws_lc_rs::rsa::KeySize` offers no size below 2048, and the `rsa` crate that
could mint one carries RUSTSEC-2023-0071 (see the dependency note in
`rust/Cargo.toml`). The test's wrong-curve counterpart has no such constraint,
so the P-384 key is minted per run by `p384_pem` in `src/dpop/key.rs` and is
not stored here.

This key was generated for this test and is used for nothing else. It is not a
credential: no service has ever held the public half.
