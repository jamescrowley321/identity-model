# Getting Started

This guide will help you get up and running with py-identity-model quickly.

## Installation

Install py-identity-model using pip:

```bash
pip install py-identity-model
```

Or using uv:

```bash
uv add py-identity-model
```

## Requirements

- Python 3.12 or higher
- An OAuth 2.0 or OpenID Connect provider (Auth0, Okta, Azure AD, etc.)

## Quick Start

### 1. Discover Your Identity Provider

First, retrieve the OpenID Connect discovery document from your identity provider:

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

# Your identity provider's discovery endpoint
DISCO_ADDRESS = "https://your-idp.com/.well-known/openid-configuration"

disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
disco_response = get_discovery_document(disco_request)

if disco_response.is_successful:
    print(f"Issuer: {disco_response.issuer}")
    print(f"Token Endpoint: {disco_response.token_endpoint}")
    print(f"JWKS URI: {disco_response.jwks_uri}")
else:
    print(f"Error: {disco_response.error}")
```

### 2. Request an Access Token

Use the client credentials flow to obtain an access token:

```python
from py_identity_model import (
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)

# Your client credentials
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
SCOPE = "api:read api:write"

# Request a token
token_request = ClientCredentialsTokenRequest(
    address=disco_response.token_endpoint,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    scope=SCOPE,
)

token_response = request_client_credentials_token(token_request)

if token_response.is_successful:
    access_token = token_response.token["access_token"]
    expires_in = token_response.token["expires_in"]
    print(f"Access token obtained, expires in {expires_in} seconds")
else:
    print(f"Error: {token_response.error}")
```

### 3. Validate a JWT Token

Validate incoming JWT tokens from your identity provider:

```python
from py_identity_model import (
    TokenValidationConfig,
    validate_token,
    PyIdentityModelException,
)

# The JWT token you want to validate
jwt_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Configure validation
validation_config = TokenValidationConfig(
    perform_disco=True,
    audience="your-api-audience",
    options={
        "verify_signature": True,
        "verify_aud": True,
        "verify_exp": True,
        "verify_iss": True,
    }
)

try:
    claims = validate_token(
        jwt=jwt_token,
        token_validation_config=validation_config,
        disco_doc_address=DISCO_ADDRESS
    )
    print(f"Token valid! Subject: {claims.get('sub')}")
    print(f"Scopes: {claims.get('scope')}")
except PyIdentityModelException as e:
    print(f"Token validation failed: {e}")
```

## Common Use Cases

### Use Case 1: Service-to-Service Authentication

When your backend service needs to call another API:

```python
from py_identity_model import (
    DiscoveryDocumentRequest,
    get_discovery_document,
    ClientCredentialsTokenRequest,
    request_client_credentials_token,
)
import requests

# Discover the token endpoint
disco = get_discovery_document(
    DiscoveryDocumentRequest(address="https://auth.example.com/.well-known/openid-configuration")
)

# Get access token
token_response = request_client_credentials_token(
    ClientCredentialsTokenRequest(
        address=disco.token_endpoint,
        client_id="my-service",
        client_secret="my-secret",
        scope="api:access"
    )
)

# Use the token to call an API
if token_response.is_successful:
    headers = {
        "Authorization": f"Bearer {token_response.token['access_token']}"
    }
    response = requests.get("https://api.example.com/data", headers=headers)
```

### Use Case 2: API Token Validation Middleware

Validate incoming tokens in your API:

```python
from functools import wraps
from flask import request, jsonify
from py_identity_model import validate_token, TokenValidationConfig, PyIdentityModelException

def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401

        token = auth_header.split(' ')[1]

        config = TokenValidationConfig(
            perform_disco=True,
            audience="my-api",
        )

        try:
            claims = validate_token(
                jwt=token,
                token_validation_config=config,
                disco_doc_address="https://auth.example.com/.well-known/openid-configuration"
            )
            request.user_claims = claims
            return f(*args, **kwargs)
        except PyIdentityModelException:
            return jsonify({'error': 'Invalid token'}), 401

    return decorated_function

@app.route('/protected')
@require_token
def protected_route():
    return jsonify({'message': f"Hello {request.user_claims.get('sub')}"})
```

## Next Steps

- Read the [API Documentation](index.md) for detailed information on all classes and functions
- Check out [Examples](https://github.com/jamescrowley321/identity-model/tree/main/py/examples) for complete working examples
- Read the [Migration Guide](migration-guide.md) for sync to async migration
- Learn about [OAuth 2.0 and OpenID Connect specifications](https://oauth.net/2/)

## Environment Variables

It's recommended to use environment variables for sensitive configuration:

```python
import os

DISCO_ADDRESS = os.environ.get("DISCO_ADDRESS")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
SCOPE = os.environ.get("SCOPE", "api:read")
```

Create a `.env` file (don't commit this!):

```bash
DISCO_ADDRESS=https://your-idp.com/.well-known/openid-configuration
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
SCOPE=api:read api:write
```

Load environment variables using `python-dotenv`:

```python
from dotenv import load_dotenv
load_dotenv()
```

## Need Help?

- Check the [Troubleshooting Guide](troubleshooting.md)
- Review the [FAQ](faq.md)
- Open an issue on [GitHub](https://github.com/jamescrowley321/identity-model/issues)
