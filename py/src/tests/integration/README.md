# Integration Tests

Due to the nature of the library, the tests are written as integration tests against live OIDC providers. Currently supported providers:
- **ORY Hydra** (default for CI/CD)
- **Descope** (optional)
- **node-oidc-provider** (local Docker fixture, no credentials needed)
- **Keycloak** (local Docker fixture, no credentials needed)
- **Local identity server** (for development)

All integration tests are provider-agnostic and should pass against any compliant OIDC provider.

## Testing Against ORY (Default)

# Environment Configuration

Without `--env-file`, the suite loads `.env` from pytest's working directory —
`py/` when run via `make test-integration-ory` — so create it there (or export
the variables). `TEST_EXPIRED_TOKEN` and `TEST_AUDIENCE` are optional.
```shell
touch py/.env

TEST_DISCO_ADDRESS=
TEST_JWKS_ADDRESS=
TEST_CLIENT_ID=
TEST_CLIENT_SECRET=
TEST_EXPIRED_TOKEN=
TEST_AUDIENCE=
TEST_SCOPE=
```

```shell
export $(cat py/.env | xargs)
```

For a self-hosted Hydra, `ory_create_client.sh` creates a client-credentials client:
```shell
client=$(hydra create client \
    --endpoint http://127.0.0.1:4445/ \
    --format json \
    --grant-type client_credentials)

# We parse the JSON response using jq to get the client ID and client secret:
client_id=$(echo $client | jq -r '.client_id')
client_secret=$(echo $client | jq -r '.client_secret')

hydra perform client-credentials \
  --endpoint http://127.0.0.1:4444/ \
  --client-id "$client_id" \
  --client-secret "$client_secret"
```

## Testing Against Descope

### Prerequisites

1. Create a Descope account at https://www.descope.com/
2. Create a new project and note your **Project ID**
3. Configure an OAuth application with **Client Credentials** grant type
4. Note your **Client ID** and **Client Secret**

### Configuration

1. Copy the Descope environment template to the repo root:
```bash
cp py/src/tests/integration/.env.descope.example .env.descope
```

2. Edit `.env.descope` and replace the placeholders:
```bash
# Replace YOUR_PROJECT_ID with your actual Descope project ID
TEST_DISCO_ADDRESS=https://api.descope.com/YOUR_PROJECT_ID/.well-known/openid-configuration
TEST_JWKS_ADDRESS=https://api.descope.com/YOUR_PROJECT_ID/.well-known/jwks.json

# Add your OAuth client credentials from Descope console
TEST_CLIENT_ID=your-client-id
TEST_CLIENT_SECRET=your-client-secret

# Configure scopes (add descope.claims for roles/permissions)
TEST_SCOPE=openid

# Audience is typically your Project ID
TEST_AUDIENCE=YOUR_PROJECT_ID

# Optional: Generate an expired token for expiration tests
TEST_EXPIRED_TOKEN=

# Optional: Multi-tenant access-key exchange (harness TokenSource).
# When all four are set, `TokenSource.mint(Provider.DESCOPE, tenant=…)` reuses
# the access-key -> /v1/auth/accesskey/exchange flow to produce a session JWT
# carrying distinct dct/tenants claims; absent, the multi-tenant test skips.
DESCOPE_BASE_URL=https://api.descope.com
DESCOPE_PROJECT_ID=
DESCOPE_MANAGEMENT_KEY=
DESCOPE_TEST_TENANT_ID=
```

3. Load the environment variables:
```bash
export $(cat .env.descope | xargs)
```

### Running Tests

Run all integration tests against Descope:
```bash
make test-integration-descope
```

Or run pytest directly:
```bash
cd py && uv run pytest src/tests -m integration --env-file=../.env.descope -v -n auto
```

### Descope-Specific Notes

- **PKCE**: Descope enforces PKCE for authorization code flows (not used in integration tests, which use client credentials)
- **JWK Rotation**: Descope rotates JWKs daily with a 12-cycle window before invalidation
- **Custom Domains**: Supported on Pro/Enterprise plans - update discovery URL accordingly
- **Special Scopes**:
  - `descope.claims` - Include roles and permissions in token
  - `descope.custom_claims` - Include custom user attributes
- **Grant Types**: Authorization Code + PKCE, Client Credentials (used in tests)

### Troubleshooting

**Issue**: Tests fail with "Invalid client credentials"
- **Solution**: Verify CLIENT_ID and CLIENT_SECRET in `.env.descope`
- **Solution**: Ensure the OAuth application has Client Credentials grant enabled

**Issue**: Tests fail with "Invalid audience"
- **Solution**: Set TEST_AUDIENCE to your Descope Project ID
- **Solution**: Check that the token endpoint returns tokens with correct audience claim

**Issue**: Intermittent JWK validation failures
- **Solution**: This may occur during JWK rotation window - retry the tests
- **Solution**: Descope caches keys for 12 cycles, so failures should be rare

**Issue**: Discovery endpoint returns 404
- **Solution**: Verify PROJECT_ID is correct in the discovery URL
- **Solution**: Check if using custom domain - update URL accordingly

## Testing Against Keycloak

Keycloak ships as a **local Docker fixture** — no cloud account or credentials
required. The realm (`py-identity-model`) is capability-maximal: it advertises
`end_session_endpoint`, `registration_endpoint` (RFC 7591/7592), and
back-channel logout support, giving live-IdP coverage for the logout and
dynamic-registration profiles.

### Running Tests

```bash
make test-integration-keycloak
```

This target boots the fixture (`docker compose --build --wait`, which gates on
realm import via the healthcheck), runs the integration suite with
`--env-file=.env.keycloak`, and tears the fixture down afterwards.

### Environment Configuration

`.env.keycloak` is committed and points at the local fixture
(`http://localhost:8080/realms/py-identity-model`). No edits are needed for the
core suite. A few optional variables gate the live logout/registration tests:

- `TEST_ADMIN_USERNAME` / `TEST_ADMIN_PASSWORD` / `TEST_ADMIN_REALM` — bootstrap
  admin credentials (default `admin`/`admin`/`master`) used to mint a
  client-registration initial access token via the Keycloak admin REST API for
  the dynamic-registration CRUD test.
- `TEST_PROVIDER_REALM` — the realm dynamic clients are registered in
  (default `py-identity-model`).
- `TEST_REGISTRATION_INITIAL_ACCESS_TOKEN` — a pre-issued registration initial
  access token; when set it takes precedence over minting one via the admin API.
- `TEST_BACKCHANNEL_LOGOUT_RECEIVER_URL` — a provider-reachable URL that
  captures the pushed `logout_token` for the live back-channel logout test. The
  shipped fixture binds loopback-only (no container→host route), so leave this
  unset to skip that test cleanly.

### Capability-Gated Skips

All integration tests are provider-agnostic and capability-gated: features a
provider does not advertise (or credentials that are not supplied) cause the
relevant tests to **skip cleanly** rather than fail. Live back-channel logout
capture, for example, skips unless a reachable receiver URL is configured.

## Shared Fixtures & the Go/Rust Suites

All local Docker IdP fixtures live in one place — `infra/` — behind a single
`infra/docker-compose.yml` (consolidated in CONS-1.4): node-oidc-provider
(`:9010`), Duende IdentityServer (`:9001`), and Keycloak (`:8080`). Every
language suite in the repo tests against the same providers:

```bash
make infra-up               # node-oidc (:9010) + IdentityServer (:9001)
make test-integration-go    # Go suite: node-oidc default profile + IdentityServer profile
make test-integration-rust  # Rust #[ignore]-gated live suite vs node-oidc
make infra-down
```

The Go suite needs no env file for the node-oidc profile (in-code defaults);
`.env.identityserver` selects the IdentityServer profile. The Rust suite
sources `.env.node-oidc`. All three languages drive a **headless
authorization-code + PKCE** flow end-to-end against node-oidc-provider's
`devInteractions` in CI.

## Provider Capability Matrix

`make provider-matrix` probes every configured provider (any `.env.*` file) and
prints a live capability matrix — grant types, PKCE, DPoP, PAR, token exchange,
introspection/revocation, and the logout/registration columns
(`registration_endpoint`, `end_session_endpoint`, `backchannel_logout_supported`,
`backchannel_logout_session_supported`). Use it to confirm which profiles a
given provider (Keycloak, node-oidc, ORY, Descope) exercises live.

## Testing Against Local Identity Server

For development and testing with a local OIDC provider:

```bash
# Create .env.local at the repo root with the TEST_* variables shown above
make test-integration-local   # runs the suite with --env-file=../.env.local
```
