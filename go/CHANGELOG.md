# Changelog — Go library

All notable changes to the Go library (`go/`) are documented here. This file is
independent of [`../py/CHANGELOG.md`](../py/CHANGELOG.md) (Python) and
[`../rust/CHANGELOG.md`](../rust/CHANGELOG.md) (Rust) — each language releases
on its own cadence.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).
Releases are `go/vX.Y.Z` tags — the subdirectory-module format `go get`
requires — resolvable as
`go get github.com/jamescrowley321/identity-model/go@vX.Y.Z`.

## Unreleased

### Changed

- `pkg/token`: `TokenExchange` now rejects three request/response shapes it
  previously accepted. Each was a silent security downgrade, so the stricter
  behaviour is a break for callers that relied on it:
  - `WithActorToken("", ...)` — a supplied-but-empty actor token — is now an
    `ErrInvalidTokenExchange` before the request is sent, instead of being
    dropped from the form. Dropping it turned a delegation exchange into an
    impersonation exchange whose issued token carries the subject's full
    authority with no `act` claim. Omit `WithActorToken` entirely to request
    impersonation.
  - `WithExtraParams` carrying `resource`, `audience` or `requested_token_type`
    on an exchange is now an `ErrInvalidTokenExchange`, instead of being applied
    or silently dropped. Set them with `WithResource`, `WithAudience` and
    `WithRequestedTokenType`, which is where the exchange sources them from.
    Keys are matched case-insensitively and with surrounding whitespace trimmed.
    Other grants are unaffected and may still pass these keys as extras.
  - A 2xx exchange response with no `token_type` is now a `RequestError`
    (`missing token_type`) rather than a successful result. `token_type` is
    REQUIRED (RFC 6749 §5.1, RFC 8693 §2.2.1) and is also the bearer test, so a
    missing value left callers treating an unknown credential as a Bearer token.
- `pkg/token`: `client_assertion` and `client_assertion_type` are now reserved on
  every grant and can no longer be set via `WithExtraParams`; an injected
  assertion would authenticate the request as a different client (RFC 7523 §2.2).
- `examples/token-exchange`: delegation is now requested with the explicit
  `-delegate` flag rather than inferred from a non-empty `ACTOR_TOKEN`, so an
  empty `ACTOR_TOKEN` fails loudly instead of downgrading to impersonation.

## go/v0.3.0 (2026-09-05)

### Added

- `pkg/idtoken`: first-class OIDC ID Token validation (`ValidateIDToken`,
  `ValidateClaims`) implementing the id-token profile — `sub` presence, `azp`
  rules for multi-audience tokens, `nonce`, `auth_time`/`max_age`, `at_hash`,
  and `c_hash` binding — with functional options (`WithClientID`, `WithNonce`,
  `WithAccessToken`, `WithCode`, `WithMaxAge`, `WithClockSkew`,
  `WithAllowedAlgorithms`, `WithNow`) and typed `ProfileError` rejections
  satisfying `errors.Is(err, ErrIDTokenProfile)`. Driven by the shared
  conformance vectors and integration-tested against the shared providers.

## go/v0.2.0 (2026-09-05)

### Added

- `pkg/jwt`: an injectable, composable claims validator. `WithClaimsValidator`
  installs a `ClaimsValidator` that runs after the signature and registered-claim
  checks, so application policy (tenant, scope, role) sees only otherwise-valid
  tokens. Ready-made validators `RequireClaims`, `RequireClaimValue`, and
  `RequireScopes` compose with `CombineClaimsValidators` (`all` / `any`). A
  rejection is a typed `ClaimsValidationError` (structured reason plus optional
  claim) that also satisfies `errors.Is(err, ErrClaimValidation)`, and is logged
  server-side when `WithLogger` is set.

## go/v0.1.0 (2026-08-29)

### Added

- Core OIDC/OAuth 2.0 client packages: `discovery`, `jwks`, `jwt`, `token`
  (client-credentials, authorization-code, PKCE), `introspection`, `revocation`,
  `dpop`, and `userinfo`.
- Cross-language conformance: the `internal/conformance` runner executes the
  shared vectors in [`../spec`](../spec), and a headless authorization-code +
  PKCE end-to-end integration test runs against the shared providers in
  [`../infra`](../infra).

### Changed

- Module path is `github.com/jamescrowley321/identity-model/go` (the
  repository was renamed from `py-identity-model` to `identity-model` during
  the polyglot consolidation; the first tag was cut on the new path).

### Notes

- **Module path:** `github.com/jamescrowley321/identity-model/go`.
- Integration tests use the `//go:build integration` tag and require the local
  provider stack (`make infra-up`); they are excluded from a plain
  `go test ./...`.
