# IdentityServer Example for E2E Testing

The [`py/examples/identity-server/`](https://github.com/jamescrowley321/identity-model/tree/main/py/examples/identity-server) directory contains the configuration for running Duende IdentityServer for end-to-end testing with the py-identity-model library.

## Files

- `Dockerfile` - Docker build configuration for custom IdentityServer image
- `startup.sh` - Startup script that waits for certificates before launching
- `IdentityServer.csproj` - .NET project file with Duende IdentityServer dependencies
- `Program.cs` - IdentityServer application bootstrap code
- `Config.cs` - Loads clients and scopes from `identityserver-config.json` (reads client secrets from environment)
- `identityserver-config.json` - API scope and client definitions
- `appsettings.json` - IdentityServer application settings (issuer URI)
- `generate-certs.sh` - Helper for generating a local self-signed certificate outside Docker

## Usage

**Recommended:** Use the complete test setup from the `py/examples/` directory which includes automatic certificate generation:

```bash
# From project root
cd py/examples
docker compose -f docker-compose.test.yml up --build
```

This automatically:
- Generates SSL certificates
- Starts the Identity Server
- Configures the FastAPI example
- Runs integration tests

### Running Identity Server Standalone

If you only need the Identity Server:

```bash
cd py/examples
docker compose -f docker-compose.test.yml up identityserver -d
```

**Note:** Certificates are automatically generated and managed via the `cert-generator` service.

## Configuration

The IdentityServer is configured with:

- **HTTPS Port**: 5001 (HTTPS)
- **HTTP Port**: 5000 (HTTP, for fallback)
- **Discovery Endpoint**: https://localhost:5001/.well-known/openid-configuration
- **JWKS Endpoint**: https://localhost:5001/.well-known/openid-configuration/jwks
- **Token Endpoint**: https://localhost:5001/connect/token

### Clients

Two test clients are configured:

1. **py-identity-model-client** (Client Credentials)
   - Client ID: `py-identity-model-client`
   - Client Secret: Configured via `CLIENT_SECRET` environment variable (default: `py-identity-model-secret`)
   - Scopes: `py-identity-model`

2. **py-identity-model-test** (Authorization Code)
   - Client ID: `py-identity-model-test`
   - Client Secret: Configured via `TEST_CLIENT_SECRET` environment variable (default: `test-secret`)
   - Scopes: `openid`, `profile`, `py-identity-model`
   - Redirect URI: `https://localhost:5002/signin-oidc`

**Security:** Client secrets are read from environment variables (`CLIENT_SECRET`, `TEST_CLIENT_SECRET`), which `docker-compose.test.yml` passes through with the defaults above.

## Health Check

The `identityserver` service in `docker-compose.test.yml` defines a health check that verifies the discovery endpoint is accessible. Wait for the container to be healthy before running tests.

## Testing

Use this setup for integration and E2E testing of the py-identity-model library against a real IdentityServer instance.