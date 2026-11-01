# Descope FastAPI Example

Production-ready FastAPI application demonstrating OAuth2/OIDC authentication with **Descope** using `py-identity-model`.

## Overview

This example shows how to integrate [Descope](https://www.descope.com/), a no-/low-code CIAM (Customer Identity and Access Management) platform, with FastAPI using `py-identity-model` for token validation.

### What This Example Demonstrates

- ✅ Descope-specific OIDC configuration
- ✅ JWT token validation with Descope's JWK endpoint
- ✅ Role-based access control (RBAC) using Descope roles
- ✅ Permission-based authorization with Descope permissions
- ✅ Scope-based authorization
- ✅ Custom claims extraction
- ✅ Middleware-based token validation
- ✅ FastAPI dependency injection patterns
- ✅ Production-ready error handling
- ✅ Docker containerization
- ✅ Integration testing

### Code Architecture

This example **reuses shared code** from the `fastapi-identity-model` package (`py/packages/fastapi-identity-model/`) to minimize duplication:

**Shared Components** (imported from `fastapi_identity_model`):
- `TokenValidationMiddleware` - JWT validation middleware
- `CurrentUser` and base dependency functions - `get_claims()`, `get_current_user()`, `get_token()`, `require_scope()`

**Descope-Specific Components** (unique to this example):
- `app.py` - Main application with Descope-specific endpoints
- `dependencies.py` - Descope roles/permissions extraction functions
- `test_integration.py` - Integration tests for Descope features

This modular approach demonstrates:
- 🔄 **Code reuse** across provider examples
- 🎯 **Provider-specific extensions** without duplication
- 📦 **Package reuse** of the published `fastapi-identity-model` package

## Prerequisites

### 1. Descope Account Setup

1. **Create a Descope account** at https://www.descope.com/
2. **Create a new project** and note your **Project ID**
3. **Configure an OAuth application**:
   - Navigate to **Applications** in Descope console
   - Create a new application or use existing one
   - Enable **Client Credentials** grant type
   - Configure allowed scopes: `openid`, `profile`, `email`, `descope.claims`
   - Note your **Client ID** and **Client Secret**

### 2. Local Development Requirements

- Python 3.12 or higher
- Docker and Docker Compose (optional, for containerized deployment)
- `uv` (recommended) or `pip` for dependency management

## Quick Start

### 1. Configure Environment

Copy the example environment file and fill in your Descope credentials:

```bash
cd py/examples/descope
cp .env.example .env
```

The app does not load `.env` itself; export the variables into your shell (e.g. `set -a && . ./.env && set +a`).

Edit `.env` with your Descope configuration:

```bash
# Your Descope Project ID
DESCOPE_PROJECT_ID=P2xXXXXXXXXXXXXXXXXXXXXX

# Discovery URL (auto-configured, or use custom domain)
DISCOVERY_URL=https://api.descope.com/P2xXXXXXXXXXXXXXXXXXXXXX/.well-known/openid-configuration

# Audience (typically your Project ID)
AUDIENCE=P2xXXXXXXXXXXXXXXXXXXXXX

# OAuth Client Credentials from Descope console
CLIENT_ID=your-client-id-here
CLIENT_SECRET=your-client-secret-here

# Scopes to request
SCOPE=openid profile email descope.claims
```

### 2. Install Dependencies

Using `uv` (recommended), from `py/` (this example is a member of the `uv` workspace there):

```bash
cd py && uv sync --all-packages
```

Or using `pip`:

```bash
pip install -e .
```

### 3. Run the Application

`app.py` imports `examples.descope.dependencies`, so run it as a module from `py/`:

```bash
cd py && uv run python -m examples.descope.app
```

The API will be available at:
- **API Base**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **OpenAPI Spec**: http://localhost:8000/openapi.json

### 4. Get an Access Token

Use client credentials flow to get a token:

```bash
# Install py-identity-model if not already installed
pip install py-identity-model

# Use the token request utility
python -c "
from py_identity_model import *
import os

disco = get_discovery_document(
    DiscoveryDocumentRequest(
        address='https://api.descope.com/{YOUR_PROJECT_ID}/.well-known/openid-configuration'
    )
)

token = request_client_credentials_token(
    ClientCredentialsTokenRequest(
        address=disco.token_endpoint,
        client_id='{YOUR_CLIENT_ID}',
        client_secret='{YOUR_CLIENT_SECRET}',
        scope='openid profile email descope.claims'
    )
)

print(token.token['access_token'])
"
```

Or use `curl` directly with Descope's token endpoint:

```bash
curl -X POST "https://api.descope.com/{PROJECT_ID}/v1/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id={CLIENT_ID}" \
  -d "client_secret={CLIENT_SECRET}" \
  -d "scope=openid profile email descope.claims"
```

### 5. Test the API

```bash
# Set your token
export TOKEN="your-access-token-here"

# Test public endpoint (no auth required)
curl http://localhost:8000/

# Test protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/me

# Test Descope-specific endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/descope/roles
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/descope/permissions
```

## API Endpoints

### Public Endpoints (No Authentication)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint with API information |
| `/health` | GET | Health check endpoint |
| `/docs` | GET | Interactive API documentation (Swagger UI) |
| `/openapi.json` | GET | OpenAPI specification |

### Protected Endpoints (Requires Valid Token)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/me` | GET | Current user information |
| `/api/claims` | GET | All token claims |
| `/api/token-info` | GET | Token metadata |
| `/api/profile` | GET | User profile from claims |

### Descope-Specific Endpoints

| Endpoint | Method | Description | Required Scope |
|----------|--------|-------------|----------------|
| `/api/descope/roles` | GET | User's Descope roles | `descope.claims` |
| `/api/descope/permissions` | GET | User's Descope permissions | `descope.claims` |

### Role-Based Endpoints (Requires Specific Descope Role)

| Endpoint | Method | Description | Required Role |
|----------|--------|-------------|---------------|
| `/api/admin/users` | GET | List users (admin only) | `admin` |
| `/api/admin/stats` | GET | Admin statistics | `admin` |

### Permission-Based Endpoints (Requires Specific Descope Permission)

| Endpoint | Method | Description | Required Permission |
|----------|--------|-------------|---------------------|
| `/api/users` | POST | Create user | `users.create` |
| `/api/users/{user_id}` | DELETE | Delete user | `users.delete` |

### Scope-Based Endpoints

| Endpoint | Method | Description | Required Scope |
|----------|--------|-------------|----------------|
| `/api/data` | GET | Get data | `openid` |

## Descope-Specific Features

### 1. Configuration

Descope uses your **Project ID** as the central identifier:

```python
DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID")
DISCOVERY_URL = f"https://api.descope.com/{DESCOPE_PROJECT_ID}/.well-known/openid-configuration"
AUDIENCE = DESCOPE_PROJECT_ID
```

For **custom domains** (Pro/Enterprise plans):

```python
DISCOVERY_URL = f"https://your-custom-domain.com/{DESCOPE_PROJECT_ID}/.well-known/openid-configuration"
```

### 2. Descope Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OIDC - includes standard claims (sub, iat, exp, etc.) |
| `profile` | User profile information (name, picture, etc.) |
| `email` | User email address |
| `descope.claims` | **Descope-specific**: Includes roles and permissions |
| `descope.custom_claims` | **Descope-specific**: Custom user attributes |

### 3. Roles and Permissions

Descope provides two levels of authorization:

**Roles** (coarse-grained):
- Defined in Descope console
- Included in token when `descope.claims` scope is requested
- Example: `admin`, `user`, `viewer`

**Permissions** (fine-grained):
- More granular than roles
- Also included with `descope.claims` scope
- Example: `users.create`, `users.delete`, `data.read`

```python
# Extract roles from token
@app.get("/my-roles")
async def get_my_roles(roles: list = Depends(get_descope_roles)):
    return {"roles": roles}

# Extract permissions from token
@app.get("/my-permissions")
async def get_my_permissions(perms: list = Depends(get_descope_permissions)):
    return {"permissions": perms}

# Require specific role
@app.get("/admin", dependencies=[Depends(require_descope_role("admin"))])
async def admin_endpoint():
    return {"message": "Admin access granted"}

# Require specific permission
@app.post("/users", dependencies=[Depends(require_descope_permission("users.create"))])
async def create_user():
    return {"message": "User created"}
```

### 4. PKCE (Proof Key for Code Exchange)

**Important**: Descope **enforces PKCE** for authorization code flows. This example uses **client credentials flow** which doesn't require PKCE, but if you implement authorization code flow, you must include PKCE parameters.

### 5. JWK Rotation

Descope rotates JWKs (JSON Web Keys) daily with a **12-cycle window** before invalidation. The `py-identity-model` library handles this automatically by:
- Fetching the current JWKS from Descope's endpoint
- Caching keys for performance
- Automatically refetching when keys change

## Running Tests

### Integration Tests

The example includes integration tests that verify:
- Public endpoints work without authentication
- Protected endpoints reject missing/invalid tokens
- Valid tokens are accepted
- Descope-specific features work correctly
- Role/permission/scope-based authorization

Run tests:

```bash
# Make sure the app is running (from py/)
uv run python -m examples.descope.app &

# Run integration tests
uv run python examples/descope/test_integration.py

# Stop the app
kill %1
```

## Docker Deployment

### Build and Run

```bash
# Build the image (the build context is py/, the uv workspace root)
cd py
docker build -f examples/descope/Dockerfile -t descope-fastapi-example .

# Run the container
docker run -p 8000:8000 \
  -e DESCOPE_PROJECT_ID="your-project-id" \
  -e CLIENT_ID="your-client-id" \
  -e CLIENT_SECRET="your-client-secret" \
  descope-fastapi-example
```

## Troubleshooting

### Issue: "Discovery document not found" or 404 errors

**Solution**:
- Verify your `DESCOPE_PROJECT_ID` is correct
- Check that the discovery URL is formatted correctly:
  `https://api.descope.com/{PROJECT_ID}/.well-known/openid-configuration`
- If using custom domain, ensure it's properly configured in Descope

### Issue: "Invalid client credentials" when requesting token

**Solution**:
- Verify `CLIENT_ID` and `CLIENT_SECRET` in `.env`
- Ensure the OAuth application in Descope has **Client Credentials** grant enabled
- Check that the client hasn't been disabled or deleted in Descope console

### Issue: "Invalid audience" in token validation

**Solution**:
- Set `AUDIENCE` to your Descope Project ID
- Verify tokens issued by Descope include the correct `aud` claim
- Check Descope application settings for audience configuration

### Issue: "Missing required role/permission" errors

**Solution**:
- Ensure you're requesting `descope.claims` scope when getting tokens
- Verify roles/permissions are assigned to your user/application in Descope console
- Check claim format in token - roles/permissions might be in different claim names

### Issue: Token validation fails intermittently

**Solution**:
- This may occur during Descope's JWK rotation window (rare)
- The library will automatically retry with updated keys
- If issue persists, check Descope status page or contact support

### Issue: CORS errors in browser

**Solution**:
- This example is for backend API authentication
- For frontend applications, configure CORS in FastAPI:
  ```python
  from fastapi.middleware.cors import CORSMiddleware
  app.add_middleware(CORSMiddleware, allow_origins=["*"])
  ```
- Consider using Descope's frontend SDKs for browser-based apps

## Production Considerations

### Security Best Practices

1. **Never commit secrets**: Use environment variables or secret management systems
2. **Use HTTPS**: Always use HTTPS in production (not HTTP)
3. **Rotate credentials**: Regularly rotate OAuth client secrets
4. **Least privilege**: Assign minimal required roles/permissions
5. **Monitor tokens**: Implement token expiration and refresh logic
6. **Rate limiting**: Add rate limiting middleware for API endpoints
7. **Audit logging**: Log authentication and authorization events

### Performance Optimization

1. **Connection pooling**: `py-identity-model` uses `httpx` with connection pooling by default
2. **Caching**: Discovery documents and JWKS are cached automatically
3. **Async support**: Consider using `py_identity_model.aio` for async FastAPI
4. **Horizontal scaling**: App is stateless and can be scaled horizontally

### Monitoring and Observability

1. **Health checks**: Use `/health` endpoint for container orchestration
2. **Metrics**: Add Prometheus metrics for token validation success/failure
3. **Distributed tracing**: Integrate OpenTelemetry for request tracing
4. **Logging**: Enhance logging for production debugging

## Additional Resources

- **Descope Documentation**: https://docs.descope.com/
- **Descope OIDC/OAuth Guide**: https://docs.descope.com/getting-started/oidc-endpoints
- **Descope Python SDK**: https://github.com/descope/python-sdk
- **py-identity-model Docs**: https://github.com/jamescrowley321/identity-model
- **FastAPI Documentation**: https://fastapi.tiangolo.com/

## Support

For issues related to:
- **This example**: Open an issue at https://github.com/jamescrowley321/identity-model/issues
- **Descope platform**: Contact Descope support or visit https://docs.descope.com/
- **py-identity-model library**: See main project README

## License

This example is part of the py-identity-model project and shares the same license.
