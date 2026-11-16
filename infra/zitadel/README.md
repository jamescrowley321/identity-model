# Zitadel integration test fixture

A local, reproducible [Zitadel](https://zitadel.com/) provider for
`py-identity-model` integration tests. Three services in
[`../docker-compose.yml`](../docker-compose.yml):

| Service | Role |
| --- | --- |
| `zitadel-db` | Postgres, on `tmpfs` — every start is a first-instance bootstrap |
| `zitadel` | Zitadel `v4.20.3`, plain HTTP on `localhost:9020` |
| `zitadel-setup` | Provisions the project, clients and users over the Zitadel API ([`setup.py`](setup.py)) |

Zitadel is pulled as an unmodified upstream image (AGPL-3.0); nothing from it
is linked into or distributed with the libraries.

## Start / stop

```bash
# from the repo root
docker compose -f infra/docker-compose.yml up -d --build --wait zitadel-setup
docker compose -f infra/docker-compose.yml cp zitadel-setup:/out/.env.zitadel .env.zitadel
docker compose -f infra/docker-compose.yml down
```

First-instance setup creates a bootstrap machine user (`fixture-admin`,
`IAM_OWNER`) and writes its personal access token to a volume shared with
`zitadel-setup`, which uses it to provision the instance. `zitadel-setup` then
stays up: its healthcheck passes once provisioning is done, so `--wait` returns
only when the clients below exist and the service user can mint a token.

Zitadel generates client IDs and client secrets, so the `TEST_*` profile is
written by `zitadel-setup` to `/out/.env.zitadel` and copied out, rather than
committed. `.env.zitadel` is git-ignored.

## Endpoints

Issuer `http://localhost:9020`. Zitadel listens on the external port inside the
container too, so the issuer is the same URL on the host and in the compose
network.

| Purpose | URL |
| --- | --- |
| Discovery | `http://localhost:9020/.well-known/openid-configuration` |
| JWKS | `http://localhost:9020/oauth/v2/keys` |
| Token | `http://localhost:9020/oauth/v2/token` |
| Authorize | `http://localhost:9020/oauth/v2/authorize` |
| UserInfo | `http://localhost:9020/oidc/v1/userinfo` |
| End session | `http://localhost:9020/oidc/v1/end_session` |
| Device authorization | `http://localhost:9020/oauth/v2/device_authorization` |
| Console | `http://localhost:9020/ui/console` (`zitadel-admin@zitadel.localhost` / `Password1!`) |

Signing keys are generated on first start, so tests fetch JWKS live.

## Clients

All in the `py-identity-model` project. Redirect and post-logout redirect URI
for the interactive clients: `http://localhost:9020/callback`.

| Name | Type | Client ID | Secret | Flows |
| --- | --- | --- | --- | --- |
| `py-identity-model-client` | service user | `py-identity-model-client` | generated | client_credentials; primary `TEST_CLIENT_ID` |
| `test-auth-code` | OIDC web app | generated | generated | authorization_code (PKCE), refresh_token |
| `test-pkce-public` | OIDC user-agent app | generated | — | authorization_code (PKCE), refresh_token |
| `test-device` | OIDC native app | generated | — | device_code; `TEST_DEVICE_CLIENT_ID` |

Zitadel grants client_credentials to service users only, so the
client-credentials client and the device-flow client are separate.

## Test user

`test-user` / `test` — email `test@example.com` (verified), name "Test User".
The password matches the shared `AuthCodeFlowConfig` default; the instance's
password complexity policy is relaxed to allow it. The user is marked as having
skipped 2-factor setup so the login UI does not prompt for it.

## Login UI

The fixture uses the login UI built into the Zitadel binary
(`ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=false`) instead of the
separate login container. It is identifier-first: a username page, then a
password page, each a server-rendered form the auth-code helper in
`py/src/tests/integration/conftest.py` fills in.

## Capabilities

- **JWT access tokens** — every client is configured for JWT access tokens.
  They carry `client_id` but no `scope` claim.
- **Refresh tokens** — issued for `offline_access`.
- **RP-initiated logout** — `end_session_endpoint` is advertised and completes
  the redirect on `id_token_hint` alone.
- **Device authorization grant** (RFC 8628) — on `test-device`.
- **Error codes** — an invalid authorization code or refresh token is rejected
  with `invalid_request`, not `invalid_grant`.
- **Back-channel logout** — advertised; the live test needs a
  provider-reachable receiver URL and skips without one.
- **Introspection / revocation** — advertised, but Zitadel authenticates these
  calls as an application, not as the service user that minted the token, so
  the single-client opaque-token tests skip (no `TEST_OPAQUE_CLIENT_ID`).
- **Not advertised** — token exchange, PAR, DPoP, JARM, mTLS, dynamic client
  registration, the `iss` authorization response parameter; those tests skip.

## Wiring

The `make test-integration-zitadel` target runs the Python integration suite
against the fixture; `py/src/tests/harness/provider_matrix.py` picks the
provider up from `.env.zitadel` once it has been copied out, and CI runs it in
the `integration-tests-zitadel` job (`.github/workflows/ci.yml`).
