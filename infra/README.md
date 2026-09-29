# Shared Test Infrastructure

A local, multi-provider OIDC stack, run via Docker Compose, that **all**
language suites (Python at the repo root, `/go`, `/rust`) run their
integration tests against — plus cloud provider profiles (Ory, Descope) that
reuse the same test suites. Testing every change against heterogeneous
providers catches provider-specific behavior a single fixture cannot.

| Provider | Where | Issuer | Fixture |
|----------|-------|--------|---------|
| [`node-oidc-provider`](https://github.com/panva/node-oidc-provider) | local compose | `http://localhost:9010` | [`node-oidc-provider/`](node-oidc-provider/) |
| [Duende IdentityServer](https://duendesoftware.com/products/identityserver) | local compose | `http://localhost:9001` | [`identityserver/`](identityserver/) |
| [Keycloak](https://www.keycloak.org/) | local compose | `http://localhost:8080/realms/py-identity-model` | [`keycloak/`](keycloak/) |
| Ory Network | cloud | per project | CI secrets / ambient `TEST_*` env |
| Descope | cloud | per project | `.env.descope` (repo root) |

> `descope/` in this directory is unrelated **Terraform** (Descope project +
> GitHub CI wiring), not a docker fixture. A separate Duende IdentityServer
> stack under `examples/` (ports 5000/5001) serves the packaged examples via
> `make test-examples`; the `identityserver/` fixture here (port 9001) is the
> Go/Rust cross-provider profile.

## Run

```bash
make infra-up      # node-oidc-provider :9010 + IdentityServer :9001 (Go/Rust default pair)
make infra-down    # stop them

# Or start exactly what you need:
docker compose -f infra/docker-compose.yml up -d --build --wait node-oidc-provider
docker compose -f infra/docker-compose.yml up -d --build --wait keycloak
docker compose -f infra/docker-compose.yml up -d --build --wait   # everything
docker compose -f infra/docker-compose.yml down
```

Each provider is healthy once its `/.well-known/openid-configuration`
responds (Compose `healthcheck`s gate `--wait`, so CI can't race a
half-booted provider; the Keycloak probe additionally waits for the realm
import to finish).

> All fixtures share one compose project, so every `make test-integration-*`
> target's teardown runs `docker compose down` for the whole project —
> including providers you started separately with `make infra-up`. Re-run
> `make infra-up` afterwards if you need them back.

## Test selection

All suites read the shared `TEST_*` environment convention:

- **Python** (repo root): `make test-integration-node-oidc` /
  `make test-integration-keycloak` source the per-provider profiles
  `.env.node-oidc` / `.env.keycloak` at the repo root.
- **Go** (`/go`): with no `TEST_*` env at all, `go test -tags=integration ./...`
  defaults to the node-oidc-provider profile (`:9010`). Source
  `.env.identityserver` (repo root) to run the same suite against
  IdentityServer, or export `TEST_*` for a cloud provider.
- **Rust** (`/rust`): live tests are `#[ignore]`-gated; run
  `cargo test -- --ignored` with `.env.node-oidc` sourced (they skip cleanly
  when `TEST_DISCO_ADDRESS` is unset).

Pre-registered clients: `test-client-credentials`, `test-auth-code`, and
`test-pkce-public` (public, PKCE) are **mirrored** across node-oidc-provider
and IdentityServer so the same `TEST_CLIENT_ID`/`TEST_CLIENT_SECRET` work
against both. `test-opaque` (opaque tokens for introspection/revocation),
`test-device`, `test-token-exchange`, and `test-private-key-jwt` are
**node-oidc-provider only**. Keycloak registers `py-identity-model-client`,
`test-auth-code`, and `test-pkce-public` in the imported `py-identity-model`
realm. Custom multi-tenant claims (`dct`, `tenants`) are injected by the
node-oidc fixture; see
[`node-oidc-provider/provider.js`](node-oidc-provider/provider.js).

## Spec vector routes

node-oidc-provider also serves the canned HTTP vectors in
[`../spec/vectors/`](../spec/vectors/) (copied into the image at build time, so run compose with `--build` after changing them), ahead of
the real OP — see
[`node-oidc-provider/vectors.js`](node-oidc-provider/vectors.js):

- `http://localhost:9010/v/{run}/{capability}/{case_id}/{vector}/{path}` answers
  with `vector.http[path]`, or the n-th entry of `vector.http_sequence[path]`
  for the n-th request; `https://server.example.com` in a fixture becomes the
  vector's base URL. `{vector}` is the vector's name (index when unnamed);
  `{run}` is any token of `[A-Za-z0-9_.-]`, so concurrent runs keep
  separate request records.
- `.../_check` returns `{"ok": bool, "diffs": [...]}`, comparing the requests
  received against the vector's `expect_request` and `expect_calls`, then
  clears them.
- `.../_requests` returns `{"requests": {path: [{method, headers, form}]}}`,
  the requests received so far, for a runner that must inspect a generated
  value such as a DPoP proof.

Everything outside `/v/` is the real provider.
