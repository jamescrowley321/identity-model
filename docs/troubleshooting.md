# Troubleshooting Guide

This guide covers common issues and their solutions when using py-identity-model.

## Installation Issues

### Package Not Found

**Problem**: `pip install py-identity-model` fails with "Could not find a version that satisfies the requirement"

**Solution**:
```bash
# Ensure you're using Python 3.12 or higher
python --version

# Upgrade pip
pip install --upgrade pip

# Try installing again
pip install py-identity-model
```

### Import Errors

**Problem**: `ImportError: No module named 'py_identity_model'`

**Solution**:
```bash
# Verify installation
pip list | grep py-identity-model

# If not installed, install it
pip install py-identity-model

# Make sure you're in the correct virtual environment
which python
```

## Discovery Document Issues

### SSL Certificate Verification Failed

**Problem**: `SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]` when fetching discovery document

**Solution**:
```python
# NOT RECOMMENDED for production - only for testing/development
import os
os.environ['CURL_CA_BUNDLE'] = ''  # Disable SSL verification (unsafe!)

# RECOMMENDED: Install proper certificates
# On macOS:
# /Applications/Python\ 3.x/Install\ Certificates.command

# Or specify a custom CA bundle
import requests
from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

# Use custom CA bundle
os.environ['REQUESTS_CA_BUNDLE'] = '/path/to/ca-bundle.crt'
```

### Discovery Document Returns 404

**Problem**: Discovery endpoint returns 404 Not Found

**Solution**:
```python
# Verify the discovery URL is correct
# Most providers use:
# https://your-domain/.well-known/openid-configuration

# Common provider patterns:
# Auth0: https://your-tenant.auth0.com/.well-known/openid-configuration
# Okta: https://your-domain.okta.com/.well-known/openid-configuration
# Azure AD: https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration
# Google: https://accounts.google.com/.well-known/openid-configuration

# Test the URL in your browser first
```

### Invalid Discovery Response

**Problem**: Discovery document doesn't contain expected fields

**Solution**:
```python
from py_identity_model import get_discovery_document, DiscoveryDocumentRequest

disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))

# Check for errors
if not disco.is_successful:
    print(f"Error: {disco.error}")
    print(f"Status Code: {disco.http_status_code}")
    exit(1)

# Verify required fields
if not disco.issuer:
    print("Warning: No issuer in discovery document")
if not disco.token_endpoint:
    print("Warning: No token_endpoint in discovery document")
```

## Token Request Issues

### Unauthorized (401) When Requesting Token

**Problem**: Token request returns 401 Unauthorized

**Solution**:
```python
# Verify your client credentials
# - Client ID is correct
# - Client Secret is correct
# - Client is configured for client_credentials grant

# Check the token endpoint URL
print(f"Token Endpoint: {disco.token_endpoint}")

# Verify scopes are valid for your client
# Some providers require specific scope formats
```

### Invalid Scope Error

**Problem**: Token request fails with "invalid_scope" error

**Solution**:
```python
# Check scope format for your provider
# Some providers use space-separated scopes:
scope = "api:read api:write"

# Others use comma-separated:
scope = "api:read,api:write"

# Some require specific prefixes:
scope = "https://api.example.com/api:read"

# Check your provider's documentation for the correct format
```

### Connection Timeout

**Problem**: Token request times out

**Solution**:
```python
# Check network connectivity
# Verify firewall rules allow outbound HTTPS
# Check if proxy settings are needed

# If behind a proxy:
import os
os.environ['HTTP_PROXY'] = 'http://proxy.example.com:8080'
os.environ['HTTPS_PROXY'] = 'http://proxy.example.com:8080'
```

## Token Validation Issues

### Signature Verification Failed

**Problem**: `PyIdentityModelException: Signature verification failed`

**Solution**:
```python
# 1. Verify the token hasn't been tampered with
# 2. Ensure the discovery document is from the correct issuer
# 3. Check that JWKS is being fetched correctly

from py_identity_model import get_jwks, JwksRequest

# Manually verify JWKS is accessible
jwks = get_jwks(JwksRequest(address=disco.jwks_uri))
if jwks.is_successful:
    print(f"Found {len(jwks.keys)} signing keys")
else:
    print(f"JWKS Error: {jwks.error}")

# 4. Verify the token's 'kid' matches a key in JWKS
import jwt
header = jwt.get_unverified_header(token)
print(f"Token kid: {header.get('kid')}")
print(f"Available kids: {[key.kid for key in jwks.keys]}")
```

### Token Expired

**Problem**: `PyIdentityModelException: Token has expired`

**Solution**:
```python
# This is expected behavior - request a new token
# Tokens have limited lifetimes for security

# Option 1: Request a new token when needed
if is_token_expired(token):
    token_response = request_client_credentials_token(token_request)
    token = token_response.token['access_token']

# Option 2: Implement automatic token refresh
# (Future feature - see roadmap for refresh token support)

# Option 3: Add clock skew tolerance if times are slightly off
from py_identity_model import TokenValidationConfig

config = TokenValidationConfig(
    perform_disco=True,
    audience="my-api",
    options={
        "verify_exp": True,
        "leeway": 60,  # Allow 60 seconds clock skew
    }
)
```

### Audience Mismatch

**Problem**: `PyIdentityModelException: Invalid audience`

**Solution**:
```python
# The 'aud' claim in the token must match the audience you're validating against

# Check the token's audience claim
import jwt
claims = jwt.decode(token, options={"verify_signature": False})
print(f"Token audience: {claims.get('aud')}")

# Match your validation config to the token's audience
config = TokenValidationConfig(
    perform_disco=True,
    audience=claims.get('aud'),  # Use the actual audience from token
)

# Or disable audience validation if not needed
config = TokenValidationConfig(
    perform_disco=True,
    options={
        "verify_aud": False,  # Disable audience verification
    }
)
```

### Issuer Mismatch

**Problem**: `PyIdentityModelException: Invalid issuer`

**Solution**:
```python
# The 'iss' claim must match the discovery document issuer

# Check both values
print(f"Discovery issuer: {disco.issuer}")
print(f"Token issuer: {claims.get('iss')}")

# Common issues:
# 1. Trailing slash mismatch: "https://auth.example.com" vs "https://auth.example.com/"
# 2. HTTP vs HTTPS
# 3. Wrong tenant/domain

# Ensure you're using the correct discovery document for your tokens
```

## Common Errors

### `PyIdentityModelException: Content did not change`

This is actually a Dependabot informational message, not an error in your code. It means dependencies are already up to date.

### Import Errors After Update

**Problem**: After updating py-identity-model, imports fail

**Solution**:
```bash
# Reinstall the package
pip uninstall py-identity-model
pip install py-identity-model

# Clear Python cache
find . -type d -name __pycache__ -exec rm -r {} +
find . -type f -name '*.pyc' -delete

# Restart your Python interpreter/application
```

### Type Hints Issues

**Problem**: Type checker complains about py-identity-model types

**Solution**:
```python
# py-identity-model includes full type hints
# Make sure you're using a recent version of mypy/pyright

# If using mypy:
pip install --upgrade mypy

# If still having issues, you can ignore type checking for the module:
# type: ignore
```

## Performance Issues

### Slow Token Validation

**Problem**: Token validation is slow

**Solution**:
```python
# Discovery documents and JWKS should be cached
# py-identity-model caches these automatically, but you can also cache at application level

# For high-performance applications, fetch discovery/JWKS once at startup:
from py_identity_model import get_discovery_document, get_jwks

# At application startup
disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCO_ADDRESS))
jwks = get_jwks(JwksRequest(address=disco.jwks_uri))

# Store these and reuse them
# They typically don't change often (hours/days)
```

### High Memory Usage

**Problem**: Application uses excessive memory

**Solution**:
```python
# Ensure you're not storing tokens unnecessarily
# Tokens can be large, especially with many claims

# Only store what you need:
claims = validate_token(jwt, config, disco_address)
user_id = claims.get('sub')  # Extract what you need
# Don't keep the full claims dict in memory if not needed
```

## Getting More Help

If you're still experiencing issues:

1. **Check the Examples**: Review the [examples directory](https://github.com/jamescrowley321/identity-model/tree/main/examples) for working code
2. **Enable Debugging**: Set up logging to see detailed information
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```
3. **Check GitHub Issues**: See if your issue is already reported at [GitHub Issues](https://github.com/jamescrowley321/identity-model/issues)
4. **Open an Issue**: If you found a bug, please [open an issue](https://github.com/jamescrowley321/identity-model/issues/new) with:
   - Python version
   - py-identity-model version
   - Minimal code to reproduce the issue
   - Full error message and stack trace

## Known Limitations

- **Opaque tokens**: Cannot be validated locally (no signature to verify) —
  use [token introspection](api/introspection.md) (RFC 7662) instead
- **Encrypted JARM responses**: Only signed JARM (JWS) is supported; encrypted
  (JWE) authorization responses are rejected

For upcoming features, check the [project roadmap](py_identity_model_roadmap.md).
