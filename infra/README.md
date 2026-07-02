# Shared Test Infrastructure

A local, multi-provider OIDC stack, run via Docker Compose, that **all**
language bindings run their integration and conformance tests against — plus
cloud provider profiles (Ory, Descope) that reuse the same test suites.
Testing every change against heterogeneous providers catches
provider-specific behavior a single fixture cannot.

| Provider | Where | Issuer | Fixture |
|----------|-------|--------|---------|
| [`node-oidc-provider`](https://github.com/panva/node-oidc-provider) | local compose | `http://localhost:9000` | [`node-oidc-provider/`](node-oidc-provider/) |
| [Duende IdentityServer](https://duendesoftware.com/products/identityserver) | local compose | `http://localhost:9001` | [`identityserver/`](identityserver/) |
| Ory Network | cloud | per project | `.env.ory` (repo root, from `.env.ory.example`) |
| Descope | cloud | per project | `.env.descope` (repo root, from `.env.descope.example`) |

> Adapted from the `py-identity-model` provider fixtures. The local providers
> are the required per-PR CI gate; the cloud jobs run when their secrets are
> configured.

## Run

```bash
docker compose up -d --wait     # node-oidc-provider :9000 + IdentityServer :9001
curl http://localhost:9000/.well-known/openid-configuration
curl http://localhost:9001/.well-known/openid-configuration
docker compose down
```

Each provider is healthy once its `/.well-known/openid-configuration`
responds (Compose `healthcheck`s gate this for CI). From the repo root,
`make infra-up` / `make infra-down` wrap the same commands, and
`make test-integration-local` runs the full up → test both → down cycle.

## Test selection

Integration tests read the `TEST_*` environment convention shared with
py-identity-model (see `go/internal/integrationtest`). Per-provider profiles
live at the repo root: `.env.node-oidc`, `.env.identityserver`, and the
`.env.ory.example` / `.env.descope.example` templates. With no `TEST_*`
environment at all, tests default to the node-oidc-provider profile.

## Pre-configured Clients (both local providers)

The IdentityServer fixture seeds the subset of clients below that its flows
need (`test-client-credentials`, `test-auth-code`, `test-pkce-public`), with
the same IDs and secrets as node-oidc-provider, so the `.env.*` profiles
differ only by issuer.

| `client_id` | Secret | Grants | Auth method |
|-------------|--------|--------|-------------|
| `test-client-credentials` | `test-client-credentials-secret` | client_credentials (+ device_code, token-exchange on node-oidc) | client_secret_basic |
| `test-auth-code` | `test-auth-code-secret` | authorization_code, refresh_token | client_secret_basic |
| `test-pkce-public` | _(none)_ | authorization_code, refresh_token | none (PKCE) |
| `test-device` (node-oidc only) | `test-device-secret` | device_code, refresh_token | client_secret_basic |
| `test-token-exchange` (node-oidc only) | `test-token-exchange-secret` | token-exchange | client_secret_basic |
| `test-opaque` (node-oidc only) | see `provider.js` | — | — |

Redirect URI for code/PKCE clients: `http://localhost:8080/callback`.

## node-oidc-provider details

Endpoints: discovery `/.well-known/openid-configuration`, JWKS `/jwks`,
token `/token`, authorization `/auth`, UserInfo `/me` — all on `:9000`.
Signing keys: one RSA (`kid=rsa-sig-key`, RS256) and one EC
(`kid=ec-sig-key`, ES256). A static account `test-user` carries `email`,
`email_verified`, `name`, `given_name`, `family_name`, plus Descope-style
`dct`/`tenants` claims. Edit
[`node-oidc-provider/provider.js`](node-oidc-provider/provider.js) to change
clients, claims, or keys, then rebuild (`docker compose up -d --build`).

## IdentityServer details

Duende IdentityServer 7 on .NET 8, in-memory configuration, developer
signing credential, plain HTTP on `:9001` (test fixture only — Duende's
license permits development/testing use). Scope `api` is backed by an
`ApiResource` so client-credentials tokens carry `aud=api`. Edit
[`identityserver/Program.cs`](identityserver/Program.cs) to change clients
or scopes, then rebuild.
