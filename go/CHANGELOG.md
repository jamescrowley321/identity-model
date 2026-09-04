# Changelog — Go library

All notable changes to the Go library (`go/`) are documented here. This file is
independent of the repository-root `CHANGELOG.md`, which tracks the Python
library only.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

The Go library has not yet been tagged or published; everything below is the
initial, unreleased development state.

### Changed

- Module path is now `github.com/jamescrowley321/identity-model/go` (the
  repository was renamed from `py-identity-model` to `identity-model` during the
  polyglot consolidation). The library is unreleased, so no published version is
  affected; the first tag is cut on the new path.

### Added

- `pkg/jwt`: an injectable, composable claims validator. `WithClaimsValidator`
  installs a `ClaimsValidator` that runs after the signature and registered-claim
  checks, so application policy (tenant, scope, role) sees only otherwise-valid
  tokens. Ready-made validators `RequireClaims`, `RequireClaimValue`, and
  `RequireScopes` compose with `CombineClaimsValidators` (`all` / `any`). A
  rejection is a typed `ClaimsValidationError` (structured reason plus optional
  claim) that also satisfies `errors.Is(err, ErrClaimValidation)`, and is logged
  server-side when `WithLogger` is set.
- Core OIDC/OAuth 2.0 client packages: `discovery`, `jwks`, `jwt`, `token`
  (client-credentials, authorization-code, PKCE), `introspection`, `revocation`,
  `dpop`, and `userinfo`.
- Cross-language conformance: the `internal/conformance` runner executes the
  shared vectors in [`../spec`](../spec), and a headless authorization-code +
  PKCE end-to-end integration test runs against the shared providers in
  [`../infra`](../infra).

### Notes

- **Module path:** `github.com/jamescrowley321/identity-model/go`.
- Integration tests use the `//go:build integration` tag and require the local
  provider stack (`make infra-up`); they are excluded from a plain
  `go test ./...`.
