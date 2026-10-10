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
  for the n-th request (the last response repeats). Both
  `https://server.example.com` and `https://provider.example.com` in a fixture
  become the vector's base URL. `{vector}` is the vector's name (index when
  unnamed); `{run}` must be a **unique token per suite invocation**, using
  `[A-Za-z0-9_.-]`. Use a UUID or random token, including when multiple
  language suites share the container; a vector name alone is not unique.
- `.../_check` returns `{"ok": bool, "diffs": [...]}`, comparing the requests
  received against the vector's `expect_request` and `expect_calls`. It checks
  every recorded request to `expect_request.path` and preserves the records
  and sequence position, so repeated checks return the same result. An expected
  `""` header or form value requires the field to be absent; present-but-empty
  fails. Nonempty form expectations require exactly one matching value, so
  duplicate parameters fail. Request positions are reserved on arrival, so
  concurrent response sequences follow arrival order. Checks fail while any
  request body is pending.
- `.../_requests` returns `{"requests": {path: [{method, headers, form}]}}`
  for runners inspecting generated values such as DPoP proofs. It preserves
  records, counts and sequence positions, and follows the same run capacity
  and inactivity limits as `_check`. Unused, reset or expired runs have no
  recorded requests.
- **POST** `.../_reset` clears this vector's records, fixture errors and
  sequence position. Use it after a completed run to release capacity, or
  before intentionally restarting the vector. GET returns 405.

Request bodies are limited to 16 KiB (413 on overflow), records to 64 requests
per vector run (429), and retained vector runs to 256 (503 for new runs when
full). Existing active runs are preserved. Records expire after 10 minutes of
inactivity; use a fresh run token for a new execution after expiry. `_check`
fails when records are missing, except for explicit zero-call expectations.
Fixture read errors and per-run limit failures also make `_check` fail until
reset, so a negative vector cannot pass because its fixture is broken.
Missing fixtures return 404, other fixture read failures return 500; the error
names the capability, case, vector and fixture path.

The fixture-owned fields are validated against
[`../spec/http-vector.schema.json`](../spec/http-vector.schema.json) before
requests or checks run. Malformed fields return HTTP 500 with their schema
location; they cannot pass a zero-call check. Capability inputs and results
are validated by their language runners.

Run the fixture's Node tests with `make test-infra-vectors` (requires Node 22
or later). CI runs the same target before the node-oidc integration suite.
To build the image outside Compose, supply the spec build context:

```bash
docker build --build-context spec=./spec -t node-oidc-provider infra/node-oidc-provider
```

Everything outside `/v/` is the real provider.
