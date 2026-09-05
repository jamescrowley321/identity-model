# CHANGELOG

<!-- version list -->

## v0.3.0 (2026-09-05)

### Bug Fixes

- **rust**: Treat empty-string azp as absent for id-token multi-aud rule
  ([#631](https://github.com/jamescrowley321/identity-model/pull/631),
  [`37462c9`](https://github.com/jamescrowley321/identity-model/commit/37462c9fc97ee76a28bf6bc8baa86cc6b13d7575))

### Chores

- **rust**: Sync Cargo.lock with 0.2.0
  ([`c38328e`](https://github.com/jamescrowley321/identity-model/commit/c38328e6b3c0622efb970b3770bc10616bab2cac))

### Features

- **rust**: Validate_id_token (OIDC id-token profile) + conformance + integration
  ([#631](https://github.com/jamescrowley321/identity-model/pull/631),
  [`37462c9`](https://github.com/jamescrowley321/identity-model/commit/37462c9fc97ee76a28bf6bc8baa86cc6b13d7575))


## v0.2.0 (2026-09-05)

### Bug Fixes

- **rust**: Treat present-but-null/empty required claims as missing
  ([#625](https://github.com/jamescrowley321/identity-model/pull/625),
  [`a225eb5`](https://github.com/jamescrowley321/identity-model/commit/a225eb560e09f5a37b80cfe7ca40ba12ed8a7a7d))

### Chores

- **rust**: Sync Cargo.lock with 0.1.0
  ([`5e427b8`](https://github.com/jamescrowley321/identity-model/commit/5e427b844fd83c2ea5588a19e9f7438c1717e423))

### Features

- **rust**: Add injectable, composable claims validator
  ([#625](https://github.com/jamescrowley321/identity-model/pull/625),
  [`a225eb5`](https://github.com/jamescrowley321/identity-model/commit/a225eb560e09f5a37b80cfe7ca40ba12ed8a7a7d))

- **rust**: Injectable, composable claims validator
  ([#625](https://github.com/jamescrowley321/identity-model/pull/625),
  [`a225eb5`](https://github.com/jamescrowley321/identity-model/commit/a225eb560e09f5a37b80cfe7ca40ba12ed8a7a7d))

### Testing

- **rust**: Claims-validator conformance vectors + example + docs
  ([#625](https://github.com/jamescrowley321/identity-model/pull/625),
  [`a225eb5`](https://github.com/jamescrowley321/identity-model/commit/a225eb560e09f5a37b80cfe7ca40ba12ed8a7a7d))


## v0.1.0 (2026-09-04)

### Bug Fixes

- **rust**: Address introspection review findings (5.1-rust)
  ([#584](https://github.com/jamescrowley321/identity-model/pull/584),
  [`493ff0c`](https://github.com/jamescrowley321/identity-model/commit/493ff0cc793ad536cc694b48432a2e30fe1e8a9c))

### Features

- **rust**: Add RFC 7662 token introspection (5.1-rust)
  ([#584](https://github.com/jamescrowley321/identity-model/pull/584),
  [`493ff0c`](https://github.com/jamescrowley321/identity-model/commit/493ff0cc793ad536cc694b48432a2e30fe1e8a9c))

### Refactoring

- **rust**: Extract shared client-auth helpers into client_auth
  ([#584](https://github.com/jamescrowley321/identity-model/pull/584),
  [`493ff0c`](https://github.com/jamescrowley321/identity-model/commit/493ff0cc793ad536cc694b48432a2e30fe1e8a9c))


## v0.0.1 (2026-08-29)

- Initial Release
