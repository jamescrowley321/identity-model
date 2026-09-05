# Migration Guide: Sync to Async

This guide helps you migrate from the synchronous API to the asynchronous API in py-identity-model.

## Overview

py-identity-model v1.2.0 introduced full async/await support while maintaining 100% backward compatibility with the synchronous API. You can:

- Use the async API exclusively (new applications)
- Use the sync API exclusively (existing applications, no changes required)
- Use both APIs in the same application (incremental migration)

## Key Differences

| Aspect | Synchronous | Asynchronous |
|--------|-------------|--------------|
| Import from | `py_identity_model` | `py_identity_model.aio` |
| Function calls | Regular function calls | `await` function calls |
| HTTP Client | Thread-local `httpx.Client` | Singleton `httpx.AsyncClient` |
| HTTP library | `httpx` (sync) | `httpx.AsyncClient` |
| Best for | Scripts, CLI, Flask, Django | FastAPI, Starlette, high-concurrency apps |

## Migration Steps

### Step 1: Update Imports

**Before (Sync):**
```python
from py_identity_model import (
    get_discovery_document,
    get_jwks,
    validate_token,
    request_client_credentials_token,
)
```

**After (Async):**
```python
# Models are still imported from the root package
from py_identity_model import (
    DiscoveryDocumentRequest,
    TokenValidationConfig,
    ClientCredentialsTokenRequest,
)

# Functions are imported from the aio module
from py_identity_model.aio import (
    get_discovery_document,
    get_jwks,
    validate_token,
    request_client_credentials_token,
)
```

**Note:** All models, exceptions, and dataclasses remain in the root package - only the functions change.

### Step 2: Add `async`/`await` Keywords

**Before (Sync):**
```python
def get_token():
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = get_discovery_document(disco_request)

    if disco_response.is_successful:
        # ... use discovery document
        return disco_response
```

**After (Async):**
```python
async def get_token():
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = await get_discovery_document(disco_request)

    if disco_response.is_successful:
        # ... use discovery document
        return disco_response
```

Changes:
- Add `async` before `def`
- Add `await` before async function calls

### Step 3: Update Function Calls

All top-level functions that make HTTP requests are now async:

| Sync Function | Async Function |
|---------------|----------------|
| `get_discovery_document()` | `await get_discovery_document()` |
| `get_jwks()` | `await get_jwks()` |
| `validate_token()` | `await validate_token()` |
| `request_client_credentials_token()` | `await request_client_credentials_token()` |

### Step 4: Handle Custom Claims Validators

If you use custom claims validators, they can be either sync or async:

**Sync validator (works with both sync and async):**
```python
def my_claims_validator(claims: dict) -> None:
    if "custom_claim" not in claims:
        raise ValueError("Missing custom_claim")

# Works with both sync and async validate_token
config = TokenValidationConfig(
    perform_disco=True,
    claims_validator=my_claims_validator,
)
```

**Async validator (only works with async validate_token):**
```python
async def my_async_claims_validator(claims: dict) -> None:
    # Can make async calls here
    user_id = claims.get("sub")
    is_valid = await check_user_in_database(user_id)
    if not is_valid:
        raise ValueError("User not found in database")

# Only works with async validate_token
config = TokenValidationConfig(
    perform_disco=True,
    claims_validator=my_async_claims_validator,
)
```

**Composable validators (recommended for common cases):**

Instead of hand-writing a callable, use the ready-made `require_claims` /
`require_claim_value` / `require_scopes` and compose them with
`combine_claims_validators`. They raise a typed `ClaimsValidationError` whose
reason is preserved to the caller. See [Claims Validation](api/claims-validation.md).

```python
from py_identity_model import (
    combine_claims_validators,
    require_claim_value,
    require_scopes,
)

config = TokenValidationConfig(
    perform_disco=True,
    claims_validator=combine_claims_validators(
        [require_claim_value("token_use", "access"), require_scopes("orders:read")]
    ),
)
```

## Common Migration Patterns

### Pattern 1: Discovery Document

**Before (Sync):**
```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

def get_endpoints():
    request = DiscoveryDocumentRequest(address="https://auth.example.com")
    response = get_discovery_document(request)

    if response.is_successful:
        return {
            "issuer": response.issuer,
            "token_endpoint": response.token_endpoint,
            "jwks_uri": response.jwks_uri,
        }
    else:
        raise Exception(response.error)
```

**After (Async):**
```python
from py_identity_model import DiscoveryDocumentRequest
from py_identity_model.aio import get_discovery_document

async def get_endpoints():
    request = DiscoveryDocumentRequest(address="https://auth.example.com")
    response = await get_discovery_document(request)

    if response.is_successful:
        return {
            "issuer": response.issuer,
            "token_endpoint": response.token_endpoint,
            "jwks_uri": response.jwks_uri,
        }
    else:
        raise Exception(response.error)
```

### Pattern 2: Token Validation

**Before (Sync):**
```python
from py_identity_model import TokenValidationConfig, validate_token

def validate_request_token(token: str):
    config = TokenValidationConfig(
        perform_disco=True,
        audience="api",
    )

    try:
        claims = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://auth.example.com",
        )
        return claims
    except PyIdentityModelException as e:
        print(f"Validation failed: {e}")
        return None
```

**After (Async):**
```python
from py_identity_model import TokenValidationConfig
from py_identity_model.aio import validate_token

async def validate_request_token(token: str):
    config = TokenValidationConfig(
        perform_disco=True,
        audience="api",
    )

    try:
        claims = await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://auth.example.com",
        )
        return claims
    except PyIdentityModelException as e:
        print(f"Validation failed: {e}")
        return None
```

### Pattern 3: Client Credentials Flow

**Before (Sync):**
```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    ClientCredentialsTokenRequest,
    get_discovery_document,
    request_client_credentials_token,
)

def get_access_token():
    # Get token endpoint from discovery
    disco_response = get_discovery_document(
        DiscoveryDocumentRequest(address="https://auth.example.com")
    )

    if not disco_response.is_successful:
        return None

    # Request token
    token_response = request_client_credentials_token(
        ClientCredentialsTokenRequest(
            address=disco_response.token_endpoint,
            client_id="my-client",
            client_secret="my-secret",
            scope="api",
        )
    )

    if token_response.is_successful:
        return token_response.token["access_token"]
    return None
```

**After (Async):**
```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    ClientCredentialsTokenRequest,
)
from py_identity_model.aio import (
    get_discovery_document,
    request_client_credentials_token,
)

async def get_access_token():
    # Get token endpoint from discovery
    disco_response = await get_discovery_document(
        DiscoveryDocumentRequest(address="https://auth.example.com")
    )

    if not disco_response.is_successful:
        return None

    # Request token
    token_response = await request_client_credentials_token(
        ClientCredentialsTokenRequest(
            address=disco_response.token_endpoint,
            client_id="my-client",
            client_secret="my-secret",
            scope="api",
        )
    )

    if token_response.is_successful:
        return token_response.token["access_token"]
    return None
```

## Framework-Specific Migration

### FastAPI Migration

FastAPI is async by default, so migration is straightforward:

**Before (Sync - works but not optimal):**
```python
from fastapi import FastAPI, Depends, HTTPException
from py_identity_model import validate_token, TokenValidationConfig

app = FastAPI()

def verify_token(token: str = Depends(oauth2_scheme)):
    config = TokenValidationConfig(perform_disco=True, audience="api")

    try:
        claims = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://auth.example.com",
        )
        return claims
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected")
def protected_route(claims: dict = Depends(verify_token)):
    return {"user": claims["sub"]}
```

**After (Async - optimal):**
```python
from fastapi import FastAPI, Depends, HTTPException
from py_identity_model import TokenValidationConfig
from py_identity_model.aio import validate_token

app = FastAPI()

async def verify_token(token: str = Depends(oauth2_scheme)):
    config = TokenValidationConfig(perform_disco=True, audience="api")

    try:
        claims = await validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://auth.example.com",
        )
        return claims
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected")
async def protected_route(claims: dict = Depends(verify_token)):
    return {"user": claims["sub"]}
```

Benefits:
- Better performance under high concurrency
- Non-blocking I/O operations
- Can use other async operations in the same handler

### Flask/Django (Stay Sync)

For Flask and Django, continue using the synchronous API:

```python
# Flask example - keep using sync API
from flask import Flask, request, jsonify
from py_identity_model import validate_token, TokenValidationConfig

app = Flask(__name__)

@app.route("/protected")
def protected_route():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    config = TokenValidationConfig(perform_disco=True, audience="api")

    try:
        claims = validate_token(
            jwt=token,
            token_validation_config=config,
            disco_doc_address="https://auth.example.com",
        )
        return jsonify({"user": claims["sub"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 401
```

**Note:** Flask and Django are synchronous frameworks, so the sync API is the correct choice.

## Incremental Migration Strategy

You don't have to migrate everything at once. You can use both APIs in the same application:

```python
# Import both sync and async versions with aliases
from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document as sync_get_discovery,
    validate_token as sync_validate_token,
)
from py_identity_model.aio import (
    get_discovery_document as async_get_discovery,
    validate_token as async_validate_token,
)

# Use sync in background jobs
def background_job():
    disco = sync_get_discovery(DiscoveryDocumentRequest(address="..."))
    # ... sync processing

# Use async in API endpoints
async def api_endpoint(token: str):
    claims = await async_validate_token(...)
    # ... async processing
```

## HTTP Client Management Differences

Both sync and async implementations manage HTTP clients differently for optimal performance:

| Aspect | Sync | Async |
|--------|------|-------|
| Client Storage | Thread-local (`threading.local()`) | Singleton per process |
| Connection Pooling | Per thread | Shared across all async operations |
| Thread Safety | Isolated per thread | Lock-protected initialization |
| Resource Management | Auto-created, manually closeable | Auto-created, manually closeable |

### Synchronous API
Each thread gets its own HTTP client with its own connection pool. This provides thread isolation without locks:

```python
from py_identity_model.http_client import get_http_client, close_http_client

# Each thread automatically gets its own client
client = get_http_client()  # Thread-local client

# Optional cleanup (usually not needed)
close_http_client()  # Closes client for current thread only
```

### Asynchronous API
All async operations share a single HTTP client per process:

```python
from py_identity_model.http_client import get_async_http_client, close_async_http_client

# All async operations share this client
client = await get_async_http_client()  # Singleton

# Optional cleanup
await close_async_http_client()  # Closes the shared client
```

**Important:** Sync and async HTTP clients are **completely separate**. Each manages its own connections independently.

## Performance Considerations

### When Async Provides Benefits

- **High concurrency**: Many simultaneous requests
- **I/O-bound operations**: Waiting for network responses
- **Already using asyncio**: Existing async event loop

**Example - Concurrent operations:**
```python
import asyncio
from py_identity_model.aio import validate_token

async def validate_many_tokens(tokens: list[str]):
    config = TokenValidationConfig(perform_disco=True, audience="api")

    # Validate all tokens concurrently
    results = await asyncio.gather(
        *[validate_token(token, config, disco_address) for token in tokens],
        return_exceptions=True
    )

    return results

# Much faster than sequential sync validation for many tokens
```

### When Sync Is Sufficient

- **Single operations**: One-off token validations
- **Low concurrency**: Few requests
- **Simple scripts**: CLI tools, batch jobs
- **Sync frameworks**: Flask, Django

## Troubleshooting

### Error: "RuntimeWarning: coroutine was never awaited"

**Problem:** You forgot to `await` an async function.

**Solution:**
```python
# Wrong
claims = validate_token(token, config, disco_address)

# Correct
claims = await validate_token(token, config, disco_address)
```

### Error: "RuntimeError: no running event loop"

**Problem:** Trying to call async code from sync context without `asyncio.run()`.

**Solution:**
```python
import asyncio

# Wrong - calling async function from sync context
def my_function():
    claims = await validate_token(...)  # Error!

# Correct - wrap in asyncio.run
def my_function():
    async def _async_operation():
        claims = await validate_token(...)
        return claims

    return asyncio.run(_async_operation())
```

### Error: "Cannot call async function from __init__"

**Problem:** `__init__` methods cannot be async.

**Solution:** Use a factory method:
```python
class MyClass:
    def __init__(self):
        self.claims = None

    @classmethod
    async def create(cls):
        instance = cls()
        instance.claims = await validate_token(...)
        return instance

# Usage
my_obj = await MyClass.create()
```

### SSL Certificate Configuration

**Note:** py-identity-model v1.2.0+ uses `httpx` instead of `requests` for HTTP operations. This change affects SSL certificate configuration.

#### Environment Variables

The library supports the following SSL certificate environment variables (in priority order):

1. **`SSL_CERT_FILE`** - httpx native variable (highest priority)
2. **`CURL_CA_BUNDLE`** - also respected by httpx
3. **`REQUESTS_CA_BUNDLE`** - legacy requests library variable (for backward compatibility)

**Backward Compatibility:** If you're migrating from an older version that used `requests`, your existing `REQUESTS_CA_BUNDLE` environment variable will continue to work. The library automatically sets `SSL_CERT_FILE` to the value of `REQUESTS_CA_BUNDLE` if `SSL_CERT_FILE` is not already set.

#### Example

```bash
# Option 1: Use SSL_CERT_FILE (recommended for new deployments)
export SSL_CERT_FILE=/path/to/ca-bundle.crt

# Option 2: Use REQUESTS_CA_BUNDLE (backward compatibility)
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt

# Option 3: Use CURL_CA_BUNDLE
export CURL_CA_BUNDLE=/path/to/ca-bundle.crt
```

```python
# The library will automatically use the appropriate certificate
from py_identity_model.aio import get_discovery_document
from py_identity_model import DiscoveryDocumentRequest

async def main():
    request = DiscoveryDocumentRequest(address="https://your-identity-server.com/.well-known/openid-configuration")
    response = await get_discovery_document(request)
    # SSL certificates will be used automatically
```

#### Docker Configuration

When running in Docker, ensure SSL environment variables are passed to the container:

```yaml
# docker-compose.yml
services:
  app:
    environment:
      - SSL_CERT_FILE=/path/to/ca-cert.crt
      # OR for backward compatibility:
      - REQUESTS_CA_BUNDLE=/path/to/ca-cert.crt
    volumes:
      - ./certs:/path/to:ro
```

## Testing

### Testing Async Code

Use `pytest-asyncio` for testing async functions:

```python
import pytest
from py_identity_model.aio import get_discovery_document
from py_identity_model import DiscoveryDocumentRequest

@pytest.mark.asyncio
async def test_async_discovery():
    request = DiscoveryDocumentRequest(address="https://demo.duendesoftware.com")
    response = await get_discovery_document(request)

    assert response.is_successful
    assert response.issuer is not None
```

## Summary Checklist

- [ ] Update imports to use `py_identity_model.aio` for async functions
- [ ] Add `async` keyword to function definitions
- [ ] Add `await` keyword before all async function calls
- [ ] Update claims validators to async if they need async operations
- [ ] Update tests to use `pytest-asyncio` for async test functions
- [ ] Verify caching behavior if using both sync and async
- [ ] Test error handling with async context
- [ ] Consider using concurrent operations with `asyncio.gather()` where beneficial

## Additional Resources

- [Async Examples](https://github.com/jamescrowley321/identity-model/blob/main/examples/async_examples.py) - Complete async usage examples
- [Mixed Usage Example](https://github.com/jamescrowley321/identity-model/blob/main/examples/mixed_usage.py) - Using both sync and async
- [FastAPI Middleware Example](https://github.com/jamescrowley321/identity-model/blob/main/examples/fastapi/middleware.py) - Production-ready FastAPI integration
- [Python Asyncio Documentation](https://docs.python.org/3/library/asyncio.html)
