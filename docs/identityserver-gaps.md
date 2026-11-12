# Integration Test Fixture Gap Analysis

This document compares the OIDC test fixtures used by py-identity-model to identify coverage gaps and guide expansion of real-provider testing.

## Background

py-identity-model historically used a Duende IdentityServer (.NET) fixture for integration testing (`py/examples/identity-server/`, still used by `make test-examples`; a separate `infra/identityserver/` fixture on port 9001 is the Go/Rust cross-provider profile). As the library expanded to cover advanced OAuth 2.0/OIDC specifications (DPoP, PAR, JAR, Device Authorization, Token Exchange, FAPI 2.0), a node-oidc-provider fixture was added (`infra/node-oidc-provider/`) to provide coverage that IdentityServer cannot.

## Feature Comparison

| Feature / RFC | IdentityServer | node-oidc-provider | Notes |
|---|:---:|:---:|---|
| **Core Protocol** | | | |
| OpenID Connect Discovery 1.0 | Yes | Yes | Both expose `/.well-known/openid-configuration` |
| JWKS (RFC 7517) | Yes | Yes | node: RSA + EC keys with explicit KIDs; IS: implicit single key |
| Client Credentials (RFC 6749) | Yes | Yes | |
| Authorization Code + PKCE (RFC 7636) | Partial | Yes | IS: auth code client configured but no PKCE enforcement; node: dedicated public PKCE client |
| Refresh Tokens | Yes | Yes | IS: via `offline_access`; node: same |
| **Token Management** | | | |
| Token Introspection (RFC 7662) | No | Yes | Not enabled in IS fixture |
| Token Revocation (RFC 7009) | No | Yes | Not enabled in IS fixture |
| **Advanced Request Mechanisms** | | | |
| DPoP (RFC 9449) | No | Yes | Not supported by Duende in test config |
| Pushed Authorization Requests (RFC 9126) | No | Yes | |
| JWT-Secured Authorization Requests (RFC 9101) | No | Yes | |
| **Alternative Grant Types** | | | |
| Device Authorization (RFC 8628) | No | Yes | Custom UI handler in node fixture |
| Token Exchange (RFC 8693) | No | Yes | Custom grant handler in node fixture |
| **Security Profiles** | | | |
| FAPI 2.0 Security Profile | No | Partial | node: `private_key_jwt` client (`test-private-key-jwt`), PAR, signed request objects; no FAPI profile enforcement |
| Resource Indicators (RFC 8707) | No | Yes | node uses this for JWT vs opaque token selection |
| **Test Infrastructure** | | | |
| Custom JWT claims (`dct`, `tenants`) | No | Yes | Descope-style multi-tenant claims via `extraTokenClaims` |
| Multiple signing algorithms | No | Yes | node: RS256 + ES256; IS: default algorithm only |
| Opaque token support | No | Yes | node: dedicated `test-opaque` client for introspection/revocation tests |
| Public client (no secret) | No | Yes | node: `test-pkce-public` client |

**Summary:** IdentityServer covers 4 of 14 features. node-oidc-provider covers 13 of 14 (FAPI 2.0 partial).

## Client Configuration Comparison

### IdentityServer (2 clients)

| Client ID | Grant Types | Scopes |
|---|---|---|
| `py-identity-model-client` | `client_credentials` | `py-identity-model` |
| `py-identity-model-test` | `authorization_code` | `openid`, `profile`, `py-identity-model` |

### node-oidc-provider (7 clients)

| Client ID | Grant Types | Scopes | Purpose |
|---|---|---|---|
| `test-client-credentials` | `client_credentials`, `device_code`, `token-exchange` | `openid`, `api` | Primary M2M testing |
| `test-auth-code` | `authorization_code`, `refresh_token` | `openid`, `profile`, `email`, `offline_access`, `api` | Auth code flow |
| `test-pkce-public` | `authorization_code`, `refresh_token` | `openid`, `profile`, `email`, `offline_access`, `api` | Public PKCE (no secret) |
| `test-device` | `device_code`, `refresh_token` | `openid`, `api` | Device flow |
| `test-token-exchange` | `token-exchange` | `openid`, `api` | RFC 8693 |
| `test-opaque` | `client_credentials` | `openid`, `api` | Opaque tokens for introspection/revocation |
| `test-private-key-jwt` | `client_credentials`, `authorization_code`, `refresh_token` | `openid`, `profile`, `email`, `offline_access`, `api` | `private_key_jwt` client auth (RFC 7523) |

## Infrastructure Comparison

| Aspect | IdentityServer | node-oidc-provider |
|---|---|---|
| **Base image** | `mcr.microsoft.com/dotnet/aspnet:8.0` | `node:22-alpine` |
| **Image size** | ~400 MB+ (SDK layer + runtime) | ~150 MB |
| **Startup time** | ~30-60 seconds (cert wait + .NET cold start) | ~2-3 seconds |
| **TLS requirement** | Yes — requires cert-generator service, shared volumes, PFX files | No — HTTP-only (`proxy = true`) |
| **Compose services** | 4 (cert-generator + identityserver + fastapi-app + test-runner) | 1 (node-oidc-provider) |
| **Health check** | `curl -k -f http://localhost:80/.well-known/openid-configuration` | `wget -q --spider http://localhost:9010/.well-known/openid-configuration` |
| **Dependencies** | .NET 8 SDK (build), ASP.NET runtime, Duende packages | Node.js 22, `oidc-provider`, `jose` |
| **CI overhead** | High — multi-stage Docker build, cert generation, service orchestration | Low — single container, no TLS setup |

## Licensing

| | IdentityServer (Duende) | node-oidc-provider |
|---|---|---|
| **License** | Duende Software License (commercial) | MIT |
| **Cost** | Free for dev/test; commercial license required for production use | Free |
| **Implications** | License compliance risk if fixture code is referenced as a production pattern | No restrictions |

Duende IdentityServer transitioned from the open-source IdentityServer4 to a commercial model. While the test fixture itself is not a production deployment, the licensing model adds friction and audit overhead that node-oidc-provider avoids entirely.

## Integration Test Coverage by Provider

| Test File | IdentityServer | node-oidc-provider | Ory Hydra | Descope |
|---|:---:|:---:|:---:|:---:|
| `test_discovery.py` | Yes | Yes | Yes | Yes |
| `test_aio_discovery.py` | Yes | Yes | Yes | Yes |
| `test_aio_jwks.py` | Yes | Yes | Yes | Yes |
| `test_token_client.py` | Yes | Yes | Yes | Yes |
| `test_token_validation.py` | Yes | Yes | Yes | Yes |
| `test_aio_token_validation.py` | Yes | Yes | Yes | Yes |
| `test_auth_code_pkce.py` | No | Yes | No | No |
| `test_refresh_token.py` | Partial | Yes | Yes | No |
| `test_introspection.py` | No | Yes | Yes | No |
| `test_revocation.py` | No | Yes | Yes | No |
| `test_dpop_par_jar.py` | No | Yes | No | No |
| `test_device_token_exchange.py` | No | Yes | No | No |
| `test_fapi_compliance.py` | Yes | Yes | Yes | Yes |
| `test_userinfo.py` | Partial | Yes | Yes | No |

**IdentityServer can run:** 7 of 14 test files (core discovery, JWKS, token client, token validation, and the discovery-based FAPI checks).
**node-oidc-provider can run:** all 14 test files.

`test_fapi_compliance.py` validates the live provider's discovery metadata with the FAPI 2.0 helpers, so it runs against every provider. The table lists a subset of `src/tests/integration/`, which now holds more test files (JARM, mTLS, `private_key_jwt`, logout, dynamic registration, and others).

## Coverage Gaps to Address

### IdentityServer fixture gaps

The current IdentityServer fixture only exercises core discovery, JWKS, client credentials, and token validation. These features could be enabled in the fixture to close the gap:

| Feature | Effort | Notes |
|---|---|---|
| Token Introspection | Low | Enable `AllowIntrospection` on existing clients, add API scope |
| Token Revocation | Low | Enable revocation endpoint in server config |
| PKCE enforcement | Low | Add a public client with `RequirePkce = true` |
| Refresh tokens | Low | Already partially working, needs `offline_access` scope |
| UserInfo | Low | Already partially working, needs claims mapping |

These features require more significant work or may not be supported in the current Duende version:

| Feature | Effort | Notes |
|---|---|---|
| DPoP (RFC 9449) | High | Requires Duende Business Edition or custom middleware |
| PAR (RFC 9126) | Medium | Supported in Duende 6.3+, needs config |
| JAR (RFC 9101) | Medium | Needs request object signing config |
| Device Authorization | Medium | Needs custom UI/consent handler |
| Token Exchange | Medium | Requires custom grant validator |

### Cross-provider coverage targets

The goal is to validate py-identity-model against multiple real providers to catch provider-specific quirks (non-standard claims, discovery URL formats, key rotation behavior).

| Provider | Type | Current Coverage | Target |
|---|---|---|---|
| node-oidc-provider | Local (Docker) | 13/14 features | Complete FAPI 2.0 (T125) |
| IdentityServer | Local (Docker) | 6/14 features | Enable introspection, revocation, PKCE |
| Ory Hydra | External | 8/14 features | Maintain current coverage |
| Descope | External | 6/14 features | Add refresh, introspection if supported |
| AWS Cognito | External | Not started | Core flows + provider-specific claims (`cognito:groups`) |
| Microsoft Entra ID | External | Not started | Core flows + multi-tenant discovery, `tid`/`oid` claims |
| Auth0 | External | Not started | Core flows + `permissions`/`org_id` claims, custom domains |

### Next steps

1. **Quick wins** — Enable introspection, revocation, and PKCE in the IdentityServer fixture (low effort, closes 3 gaps)
2. **Cloud provider cassettes** — Build cassette-based integration tests (pytest-recording/vcrpy) for Cognito, Entra ID, and Auth0 with live/replay mode switching
3. **Nightly CI** — Add a scheduled workflow that runs live tests against cloud providers and creates issues on drift detection
4. **FAPI 2.0** — Complete T125 (FAPI profile enforcement in the node-oidc-provider fixture)
