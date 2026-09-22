//! Tests driven by the shared, language-neutral fixtures under `../spec`.
//!
//! These are the Rust half of the cross-language contract: the same vector
//! files and fixture documents drive the Python and Go suites, so the three
//! libraries cannot drift against each other's private expectations. All of
//! them are offline and run in every bare `cargo test`.
//!
//! `validation` and `id_token` are wired into `tools/spec_coverage_gate.py`:
//! when `SPEC_COVERAGE_OUT` is set they write the executed case ids and the
//! gate fails by name if any language skipped a vector. The gate runs each by
//! its exact test path, for example
//! `cargo test --test it -- --exact conformance::validation::spec_validation_conformance`.

mod claims_validation;
mod dpop;
mod id_token;
mod validation;
