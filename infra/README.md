# Shared Test Infrastructure

A single [`node-oidc-provider`](https://github.com/panva/node-oidc-provider) instance, run via Docker Compose, that **all** language bindings run their integration and conformance tests against. This guarantees every language is tested against the same RFC-compliant provider.

> Adapted from the `py-identity-model` provider fixture and standardized on port **9000**.

## Run

```bash
docker compose up -d            # starts provider on http://localhost:9000
curl http://localhost:9000/.well-known/openid-configuration
docker compose down
```

The provider is healthy once `/.well-known/openid-configuration` responds (a Compose `healthcheck` gates this for CI).

## Endpoints

| Endpoint | URL |
|----------|-----|
| Discovery | `http://localhost:9000/.well-known/openid-configuration` |
| JWKS | `http://localhost:9000/jwks` |
| Token | `http://localhost:9000/token` |
| Authorization | `http://localhost:9000/auth` |
| UserInfo | `http://localhost:9000/me` |

Signing keys: one RSA (`kid=rsa-sig-key`, RS256) and one EC (`kid=ec-sig-key`, ES256).

## Pre-configured Clients

| `client_id` | Secret | Grants | Auth method |
|-------------|--------|--------|-------------|
| `test-client-credentials` | `test-client-credentials-secret` | client_credentials, device_code, token-exchange | client_secret_basic |
| `test-auth-code` | `test-auth-code-secret` | authorization_code, refresh_token | client_secret_basic |
| `test-pkce-public` | _(none)_ | authorization_code, refresh_token | none (PKCE) |
| `test-device` | `test-device-secret` | device_code, refresh_token | client_secret_basic |
| `test-token-exchange` | `test-token-exchange-secret` | token-exchange | client_secret_basic |
| `test-opaque` | see `provider.js` | — | — |

Redirect URI for code/PKCE clients: `http://localhost:8080/callback`.

## Test User & Claims

A static account `test-user` is configured with `email`, `email_verified`, `name`, `given_name`, `family_name`. Edit `provider.js` (`ACCOUNTS`) to add accounts or custom claims.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `PORT` | `9000` | Listen port |
| `ISSUER` | `http://localhost:9000` | Issuer / base URL |

See [`.env.example`](.env.example). To change clients, claims, or keys, edit [`provider.js`](provider.js) and rebuild (`docker compose up -d --build`).
