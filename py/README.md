# py-identity-model
![Build](https://github.com/jamescrowley321/identity-model/workflows/Build/badge.svg)
![License](https://img.shields.io/pypi/l/py-identity-model)

Production-grade OIDC/OAuth2.0 client library for Python. Dual sync/async API with comprehensive RFC coverage. Inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model).

## OpenID Certified

<a href="https://openid.net/certification/certified-openid-relying-parties-profiles/">
  <img src="https://raw.githubusercontent.com/jamescrowley321/identity-model/main/docs/assets/openid-certified.png" alt="OpenID Certified" width="220">
</a>

py-identity-model is [OpenID Certified<sup>®</sup>](https://openid.net/certification/certified-openid-relying-parties-profiles/) by the OpenID Foundation as a Relying Party (RP) for the **Basic RP**, **Config RP**, and **Form Post Basic RP** conformance profiles (certified 2 July 2026, `py-identity-model 3.1.0`). See [the certification docs](https://jamescrowley321.github.io/identity-model/certification/) for the conformance harness and submission process.

> OpenID Certified is a certification mark of the OpenID Foundation.

## Installation

```bash
pip install py-identity-model
```

Or with uv:

```bash
uv add py-identity-model
```

**Requirements:** Python 3.12+

## Features

### Protocol Support

| Feature | RFC/Spec | Status |
|---------|----------|--------|
| OpenID Connect Discovery 1.0 | OIDC Discovery | Done |
| JSON Web Key Sets | RFC 7517 | Done |
| JWT Validation | RFC 7519 | Done |
| Client Credentials Grant | RFC 6749 | Done |
| Authorization Code + PKCE | RFC 7636 | Done |
| Refresh Token Grant | RFC 6749 | Done |
| Token Introspection | RFC 7662 | Done |
| Token Revocation | RFC 7009 | Done |
| Device Authorization | RFC 8628 | Done |
| Token Exchange | RFC 8693 | Done |
| DPoP | RFC 9449 | Done |
| Pushed Authorization Requests | RFC 9126 | Done |
| JWT Secured Authorization Request | RFC 9101 | Done |
| JWT Secured Authorization Response Mode (JARM) | JARM | Done |
| private_key_jwt Client Authentication | RFC 7523 | Done |
| Mutual-TLS Client Auth + Certificate-Bound Tokens | RFC 8705 | Done |
| FAPI 2.0 Security Profile | FAPI 2.0 | Done |
| UserInfo Endpoint | OIDC Core | Done |
| OAuth Callback State Validation | RFC 6749 | Done |
| AS Issuer Identification (Mix-Up Defense) | RFC 9207 | Done |
| Policy-Based Configuration | — | Done |

### Architecture

- **Dual API**: Synchronous (`py_identity_model`) and asynchronous (`py_identity_model.aio`)
- **Thread-safe**: Sync uses thread-local HTTP clients; async uses singleton with lock protection
- **Modular**: Shared business logic in `core/`, thin sync/async HTTP wrappers
- **Connection pooling**: httpx-based with configurable timeouts and retry logic

## Quick Start

### Discovery

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

response = get_discovery_document(DiscoveryDocumentRequest(address="https://issuer.example.com"))
if response.is_successful:
    print(f"Token Endpoint: {response.token_endpoint}")
```

### Token Validation

```python
from py_identity_model import TokenValidationConfig, validate_token

config = TokenValidationConfig(perform_disco=True, audience="my-api")
claims = validate_token(jwt=token, token_validation_config=config, disco_doc_address="https://issuer.example.com")
```

### Async API

```python
from py_identity_model.aio import get_discovery_document, validate_token
from py_identity_model import DiscoveryDocumentRequest

response = await get_discovery_document(DiscoveryDocumentRequest(address=url))
```

### Client Credentials

```python
from py_identity_model import ClientCredentialsTokenRequest, request_client_credentials_token

token = request_client_credentials_token(ClientCredentialsTokenRequest(
    client_id="my-client", client_secret="secret",
    address=token_endpoint, scope="api"
))
```

## Examples

Each protocol feature has a standalone example in [`examples/`](examples/):

| Example | Feature |
|---------|---------|
| [sync_examples.py](examples/sync_examples.py) | Discovery, JWKS, token validation, client credentials |
| [async_examples.py](examples/async_examples.py) | Async versions of all core operations |
| [auth_code_pkce_example.py](examples/auth_code_pkce_example.py) | Authorization Code + PKCE flow |
| [introspection_example.py](examples/introspection_example.py) | Token introspection (RFC 7662) |
| [revocation_example.py](examples/revocation_example.py) | Token revocation (RFC 7009) |
| [dpop_example.py](examples/dpop_example.py) | DPoP proof creation (RFC 9449) |
| [par_example.py](examples/par_example.py) | Pushed Authorization Requests (RFC 9126) |
| [jar_example.py](examples/jar_example.py) | JWT Secured Authorization Request (RFC 9101) |
| [jarm_example.py](examples/jarm_example.py) | JWT Secured Authorization Response Mode (JARM) |
| [private_key_jwt_example.py](examples/private_key_jwt_example.py) | private_key_jwt client authentication (RFC 7523) |
| [mtls_example.py](examples/mtls_example.py) | mTLS client auth + certificate-bound tokens (RFC 8705) |
| [fapi_example.py](examples/fapi_example.py) | FAPI 2.0 Security Profile |
| [device_auth_example.py](examples/device_auth_example.py) | Device Authorization Grant (RFC 8628) |
| [token_exchange_example.py](examples/token_exchange_example.py) | Token Exchange (RFC 8693) |

## Framework Integration

`py-identity-model` is framework-agnostic — call `validate_token` (or `py_identity_model.aio.validate_token`) from any Python framework's auth layer. For FastAPI, [`examples/fastapi/`](examples/fastapi/) ships a complete, production-shaped integration you can copy into your own project:

- **`TokenValidationMiddleware`** — Bearer token extraction, JWKS-cached validation, configurable excluded paths, pluggable custom-claim validators
- **Dependency injection** — `CurrentUser`, `Claims`, `Token` annotated types for typed access to the authenticated principal from route handlers
- **Authorization guards** — `require_claim(type, value)` and `require_scope(scope)` factories that plug into `Depends(...)` to enforce RBAC/ABAC at the route level
- **Token refresh helper** — Proactive refresh of expiring access tokens for service-to-service flows

```python
from fastapi import Depends, FastAPI

from .middleware import TokenValidationMiddleware
from .dependencies import CurrentUser, require_scope

app = FastAPI()

app.add_middleware(
    TokenValidationMiddleware,
    discovery_url="https://issuer.example.com/.well-known/openid-configuration",
    audience="my-api",
    excluded_paths=["/health", "/docs", "/openapi.json"],
)


@app.get("/me")
async def me(user: CurrentUser) -> dict:
    return {"sub": user.identity.name}


@app.get("/admin", dependencies=[Depends(require_scope("api.admin"))])
async def admin() -> dict:
    return {"status": "ok"}
```

| Integration | Path | Highlights |
|-------------|------|------------|
| FastAPI | [`examples/fastapi/`](examples/fastapi/) | Middleware, DI, authorization guards, token refresh |
| Descope (FastAPI) | [`examples/descope/`](examples/descope/) | Extends the FastAPI base with Descope-specific issuer/tenant handling |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_TIMEOUT` | 30.0 | Request timeout (seconds) |
| `HTTP_RETRY_COUNT` | 3 | Retries for rate-limited requests |
| `HTTP_RETRY_BASE_DELAY` | 1.0 | Base delay for exponential backoff |
| `SSL_CERT_FILE` | — | CA bundle path (recommended) |
| `REQUESTS_CA_BUNDLE` | — | CA bundle path (legacy compat) |

## Documentation

Full docs: **[jamescrowley321.github.io/identity-model](https://jamescrowley321.github.io/identity-model/)**

- [Getting Started](https://jamescrowley321.github.io/identity-model/getting-started/)
- [Migration Guide](https://jamescrowley321.github.io/identity-model/migration-guide/)
- [Performance Guide](https://jamescrowley321.github.io/identity-model/performance/)
- [Integration Tests](https://jamescrowley321.github.io/identity-model/integration-tests/)
- [API Reference](https://jamescrowley321.github.io/identity-model/api/)

## License

Apache License 2.0
