//! DPoP — Demonstrating Proof of Possession at the Application Layer
//! (RFC 9449): binds an access token to a client-held key pair, so a stolen
//! token cannot be replayed by an attacker who does not hold the private key.
//!
//! This is sender-constraining without mTLS. The client generates a key pair
//! ([`DpopKey`]), signs a short-lived proof JWT per request
//! ([`DpopKey::proof`]), and the authorization server binds the issued token to
//! that key by putting the key's RFC 7638 thumbprint
//! ([`DpopKey::thumbprint`]) in the token's `cnf.jkt` claim. A resource server
//! verifies the accompanying proof ([`verify_proof`]) and checks that the
//! verified [`DpopProof::thumbprint`] equals the token's `cnf.jkt`.
//!
//! The pieces:
//!
//! - [`DpopKey`] — a key pair for [`DpopAlgorithm::Es256`] (EC P-256) or
//!   [`DpopAlgorithm::Rs256`] (RSA 2048), which can be persisted as PKCS#8 and
//!   reloaded so it survives a restart and can be rotated without invalidating
//!   already-issued bound tokens (RFC 9449 §4.1).
//! - [`DpopKey::proof`] — builds and signs a proof JWT for one request:
//!   `typ=dpop+jwt`, the embedded public `jwk`, and the `jti`/`htm`/`htu`/`iat`
//!   claims (RFC 9449 §4.2). [`DpopProofOptions`] adds the `ath` claim for
//!   resource requests (§7) and `nonce` after a server challenge (§8).
//! - [`dpop_ath`] — the `BASE64URL(SHA-256(access_token))` binding value.
//! - [`jwk_thumbprint`] — the RFC 7638 thumbprint of a public JWK, for checking
//!   a `cnf.jkt` against a key held as a JWK rather than as a [`DpopKey`].
//! - [`verify_proof`] — validates a proof on the resource-server side
//!   (RFC 9449 §4.3).
//!
//! Behaviour is proven against the cross-language conformance IDs
//! `DPOP-001`..`DPOP-008` in `spec/vectors/dpop.json`, against the shared
//! fixtures in `spec/test-fixtures/dpop/` — the same contract
//! `go/pkg/dpop` satisfies.
//!
//! Sending the proof and handling the `use_dpop_nonce` retry over HTTP is not
//! part of this module yet; it is tracked by
//! [#573](https://github.com/jamescrowley321/identity-model/issues/573).
//! Until then, attach the proof yourself: put [`DpopKey::proof`]'s output in the
//! `DPoP` request header and, on a protected-resource request, present the token
//! as `Authorization: DPoP <access_token>` rather than `Bearer`
//! (RFC 9449 §7, DPOP-008).
//!
//! ```
//! use rs_identity_model::{DpopAlgorithm, DpopKey, DpopProofOptions};
//!
//! # fn main() -> rs_identity_model::Result<()> {
//! let key = DpopKey::generate(DpopAlgorithm::Es256)?;
//!
//! // Token request: the proof travels in the DPoP header and has no `ath`,
//! // because there is no access token to bind to yet (RFC 9449 §5).
//! let proof = key.proof("POST", "https://server.example.com/token", &DpopProofOptions::new())?;
//!
//! // The authorization server returns token_type=DPoP and binds the token to
//! // this thumbprint via cnf.jkt (RFC 9449 §6).
//! let jkt = key.thumbprint()?;
//! # let _ = (proof, jkt);
//! # Ok(())
//! # }
//! ```

mod key;
mod proof;
mod verify;

pub use key::{DpopAlgorithm, DpopKey, jwk_thumbprint};
pub use proof::{DPOP_PROOF_TYP, DpopProofOptions, ath, normalize_htu};
pub use verify::{DpopProof, DpopVerifyOptions, verify_proof};
