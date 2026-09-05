# identity-model (Go)

A native Go library for OpenID Connect and OAuth 2.0 clients: discovery, JWKS
retrieval and key resolution, JWT and ID token validation, and the token,
introspection, revocation, DPoP, and UserInfo endpoints.

- **Module:** `github.com/jamescrowley321/identity-model/go`
- **Minimum Go:** 1.26
- **Install:** `go get github.com/jamescrowley321/identity-model/go`

## Packages

| Package | Purpose | Spec |
|---------|---------|------|
| `pkg/discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `pkg/jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `pkg/jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `pkg/idtoken` | ID token validation (OIDC id-token profile) | OIDC Core 1.0 §3.1.3.7 |
| `pkg/token` | Client credentials, authorization code, PKCE | RFC 6749 / 7636 |
| `pkg/introspection` | Token introspection client | RFC 7662 |
| `pkg/revocation` | Token revocation client | RFC 7009 |
| `pkg/dpop` | DPoP proof creation + verification | RFC 9449 |
| `pkg/userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |

## Claims validation

Beyond the registered-claim checks, `pkg/jwt` exposes an injectable, composable
claims validator for application policy (tenant, scope, or role rules) that runs
only *after* the signature, algorithm-allowlist, and registered-claim checks
pass. The ready-made `RequireClaims`, `RequireClaimValue`, and `RequireScopes`
compose with `CombineClaimsValidators` (`CombineAll` / `CombineAny`) and install
via `jwt.WithClaimsValidator`. A rejection is a typed `*jwt.ClaimsValidationError`
that names the offending claim, and any non-rejection error from a validator
fails the token closed. See [`examples/claims-validation`](examples/claims-validation)
for a runnable demo, and the cross-language behavioural contract in
[`../spec/test-fixtures/claims-validation`](../spec/test-fixtures/claims-validation)
(the same vectors are executed by the Python and Rust libraries).

## Design

- HTTP via the `net/http` standard library; `sync.Pool` for client reuse.
- Functional options for configuration: `WithTimeout()`, `WithCacheTTL()`, `WithHTTPClient()`.
- `singleflight` deduplicates concurrent discovery / JWKS fetches.
- JOSE handling via `go-jose/v4`.

## Getting started

```bash
go build ./...
go test ./...
go run ./examples/hello
go run ./examples/claims-validation
```

Integration tests use the `integration` build tag and run against the shared
providers in [`../infra`](../infra); start them with `make infra-up` from the
repo root. The env-free default profile targets node-oidc-provider on `:9010`;
source `.env.identityserver` to run the same tests against IdentityServer.

Behavioral parity with the Python and Rust libraries is enforced by the
cross-language conformance vectors in [`../spec`](../spec), which the
`internal/conformance` runner executes.
