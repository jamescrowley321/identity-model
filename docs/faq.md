# Frequently Asked Questions (FAQ)

## General Questions

### What is py-identity-model?

py-identity-model is a Python library for OAuth 2.0 and OpenID Connect operations. It helps you:
- Discover identity provider endpoints
- Request and validate JWT tokens
- Implement secure authentication in Python applications

The library is inspired by [Duende.IdentityModel](https://github.com/DuendeSoftware/foss/tree/main/identity-model) for .NET.

### What Python versions are supported?

py-identity-model requires Python 3.12 or higher.

### Is py-identity-model production-ready?

Yes! The library has been used in production Flask and FastAPI applications for years. The core features (discovery, JWKS, token validation, client credentials) are stable and well-tested.

### What's the difference between OAuth 2.0 and OpenID Connect?

- **OAuth 2.0**: Authorization framework for granting access to resources
- **OpenID Connect (OIDC)**: Authentication layer built on top of OAuth 2.0

OIDC adds standardized ways to authenticate users and retrieve user information, while OAuth 2.0 focuses on authorization (what you can access).

## Features and Capabilities

### What OAuth flows are supported?

- ✅ Client Credentials Grant
- ✅ Authorization Code Flow with PKCE
- ✅ Refresh Token Grant
- ✅ Device Authorization Grant (RFC 8628)
- ✅ Token Exchange (RFC 8693)

### Does it support opaque tokens?

Local (offline) validation applies to JWT tokens only. Opaque tokens are
supported through [token introspection](api/introspection.md) (RFC 7662) —
`introspect_token` asks the authorization server whether the token is active
and returns its claims.

### Can I use this with async/await?

Yes. The `py_identity_model.aio` module mirrors the sync API — see the
[API Reference](api/index.md) for the import conventions.

### What identity providers are supported?

py-identity-model works with any OAuth 2.0 / OpenID Connect compliant provider, including:
- Auth0
- Okta
- Azure AD (Microsoft Entra ID)
- Google
- AWS Cognito
- Keycloak
- Duende IdentityServer
- Any other OIDC-compliant provider

### Does it support token refresh?

Yes — see [Refresh Token](api/refresh-token.md) for `refresh_token` and its
request/response models.

## Usage Questions

### How do I validate tokens from my API?

```python
from py_identity_model import validate_token, TokenValidationConfig

config = TokenValidationConfig(
    perform_disco=True,
    audience="your-api-audience",
)

try:
    claims = validate_token(
        jwt=token,
        token_validation_config=config,
        disco_doc_address="https://your-idp.com/.well-known/openid-configuration"
    )
    # Token is valid
except PyIdentityModelException:
    # Token is invalid
    pass
```

See the [Getting Started Guide](getting-started.md) for more details.

### How do I get an access token for service-to-service calls?

Use the client credentials flow:

```python
from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)

token_response = request_client_credentials_token(
    ClientCredentialsTokenRequest(
        address="https://your-idp.com/oauth/token",
        client_id="your-client-id",
        client_secret="your-client-secret",
        scope="api:access",
    )
)

if token_response.is_successful:
    access_token = token_response.token["access_token"]
```

### Should I cache discovery documents and JWKS?

py-identity-model handles caching internally, but for high-performance applications, you can cache these at the application level:

```python
# Fetch once at startup
disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))
jwks = get_jwks(JwksRequest(address=disco.jwks_uri))

# Reuse these throughout your application
# They typically don't change for hours or days
```

### How do I handle token expiration?

Tokens expire for security reasons. Request a new token when needed:

```python
import time

def get_valid_token():
    global cached_token, token_expiry

    if time.time() >= token_expiry:
        # Token expired, get new one
        response = request_client_credentials_token(token_request)
        cached_token = response.token["access_token"]
        token_expiry = time.time() + response.token["expires_in"] - 60  # 60s buffer

    return cached_token
```

### Can I use this with Flask or FastAPI?

Yes! py-identity-model works great with both. See the [Examples](https://github.com/jamescrowley321/identity-model/tree/main/examples) directory for middleware implementations.

### How do I validate tokens in a decorator?

```python
from functools import wraps
from flask import request, jsonify

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            claims = validate_token(token, config, disco_address)
            request.user_claims = claims
            return f(*args, **kwargs)
        except PyIdentityModelException:
            return jsonify({'error': 'Unauthorized'}), 401
    return decorated
```

## Security Questions

### Is it safe to store client secrets in environment variables?

For development: Yes, using `.env` files is acceptable.

For production: Use a secrets management solution like:
- AWS Secrets Manager
- Azure Key Vault
- HashiCorp Vault
- Kubernetes Secrets

Never commit secrets to version control!

### What validation options should I use?

For production, enable these validations:

```python
options = {
    "verify_signature": True,   # Always verify signature
    "verify_aud": True,          # Verify audience
    "verify_exp": True,          # Check expiration
    "verify_iss": True,          # Verify issuer
    "verify_nbf": True,          # Check not-before time
}
```

### Should I disable SSL verification?

**Never in production!** Only disable SSL verification in local development if absolutely necessary.

### How often do signing keys change?

It varies by provider, but typically:
- Keys are rotated every few months
- Multiple keys are active simultaneously
- Old keys remain valid during rotation period

py-identity-model automatically handles key rotation by fetching the current JWKS.

## Integration Questions

### Can I use this with Django?

Yes, though examples currently focus on Flask and FastAPI. The validation functions work the same way in Django views or middleware.

### Does it work with API Gateway?

Yes, you can use py-identity-model in Lambda functions behind API Gateway to validate tokens.

### Can I validate tokens from multiple issuers?

Yes. `TokenValidationConfig` accepts a list of issuers via `issuer` /
`allowed_issuers` — see [Token Validation](api/token-validation.md).

## Development Questions

### How do I contribute?

See the [Contributing Guide](contributing.md) for detailed instructions.

### How do I run tests?

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests against a specific provider (Docker fixtures)
make test-integration-node-oidc
make test-integration-keycloak
```

### Where can I find examples?

Check the [examples directory](https://github.com/jamescrowley321/identity-model/tree/main/py/examples) in the repository.

### Is there API documentation?

Yes! See the [API Documentation](index.md) for detailed information on all classes and functions.

## Troubleshooting Questions

### Why am I getting "Signature verification failed"?

Common causes:
1. Token is from a different issuer than expected
2. Token has been tampered with
3. JWKS endpoint is not accessible
4. Token's `kid` doesn't match any keys in JWKS

See the [Troubleshooting Guide](troubleshooting.md#signature-verification-failed) for solutions.

### Why is token validation slow?

Discovery documents and JWKS are cached automatically. If it's still slow:
- Fetch discovery/JWKS once at startup and reuse
- Check network latency to identity provider
- Consider using a local cache for claims

### My discovery document returns 404

Verify your discovery URL:
- Most providers: `https://domain/.well-known/openid-configuration`
- Check provider documentation for exact URL
- Test the URL in a browser first

See more in the [Troubleshooting Guide](troubleshooting.md).

## Future Plans

### What features are coming next?

See the [project roadmap](py_identity_model_roadmap.md) and the
[capability matrix](https://github.com/jamescrowley321/identity-model/blob/main/spec/capabilities.md)
for detailed plans. Highlights:

- Node/TypeScript library (the fourth language in the family)
- Go and Rust parity with the full Python capability surface
- Rich Authorization Requests (RFC 9396) and CIBA

### Can I request a feature?

Yes! Open an issue on [GitHub](https://github.com/jamescrowley321/identity-model/issues) describing:
- What you want to do
- Why it's useful
- Any relevant specifications (RFCs)

### How can I help?

Contributions are welcome! See the [Contributing Guide](contributing.md) for:
- Setting up your development environment
- Coding standards and conventions
- How to submit pull requests

## Still Have Questions?

- Check the [Troubleshooting Guide](troubleshooting.md)
- Review [Getting Started](getting-started.md)
- Open an issue on [GitHub](https://github.com/jamescrowley321/identity-model/issues)
- Read the [project documentation](index.md)
