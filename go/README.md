# identity-model (Go)

Go implementation of the [identity-model](../README.md) OIDC/OAuth2 client library.

- **Module:** `github.com/jamescrowley321/identity-model/go`
- **Minimum Go:** 1.24
- **Install:** `go get github.com/jamescrowley321/identity-model/go`

## Package Layout

| Package | Purpose | Spec |
|---------|---------|------|
| `pkg/discovery` | OIDC Discovery client | OIDC Discovery 1.0 |
| `pkg/jwks` | JWKS fetch + key resolution | RFC 7517 / 7518 |
| `pkg/jwt` | JWT signature + claims validation | RFC 7519 / 7515 |
| `pkg/token` | Client credentials, auth code, PKCE | RFC 6749 / 7636 |
| `pkg/userinfo` | UserInfo endpoint client | OIDC Core 1.0 §5.3 |
| `internal/` | Shared non-exported utilities | — |

## Design Conventions

- HTTP via `net/http` stdlib; `sync.Pool` for client reuse.
- Functional options for configuration: `WithTimeout()`, `WithCacheTTL()`, `WithHTTPClient()`.
- `singleflight` to deduplicate concurrent discovery / JWKS fetches.
- JOSE handling via `go-jose/v4` or `golang-jwt/v5` (added as implementation lands).

## Getting Started

```bash
go build ./...
go vet ./...
go test ./...
go run ./examples/hello
```

Integration tests (build tag `integration`) run against the shared provider in [`../infra`](../infra).

> **Status:** Scaffolded. Capabilities are documented per package; implementation tracks the cross-language [`spec/`](../spec).
