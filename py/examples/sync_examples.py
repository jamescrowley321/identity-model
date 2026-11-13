"""
Synchronous Examples for py-identity-model

This module demonstrates how to use the synchronous API for traditional blocking I/O.
Perfect for scripts, CLIs, traditional web frameworks (Flask, Django), and simple applications.
"""

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    JwksRequest,
    TokenValidationConfig,
    UserInfoRequest,
    get_discovery_document,
    get_jwks,
    get_userinfo,
    request_client_credentials_token,
    validate_token,
)


# Constants
DEMO_DISCOVERY_URL = "https://demo.duendesoftware.com/.well-known/openid-configuration"


# =============================================================================
# Example 1: Discovery Document Fetching
# =============================================================================


def fetch_discovery_document_example():
    """Fetch discovery document synchronously."""
    print("\\n" + "=" * 60)
    print("Example 1: Discovery Document")
    print("=" * 60)

    discovery_request = DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)

    # Synchronous fetch - blocks until response received
    response = get_discovery_document(discovery_request)

    if response.is_successful:
        print("✓ Discovery successful!")
        print(f"  Issuer: {response.issuer}")
        print(f"  JWKS URI: {response.jwks_uri}")
        print(f"  Token Endpoint: {response.token_endpoint}")
        print(
            f"  Supported algorithms: {response.id_token_signing_alg_values_supported}"
        )
    else:
        print(f"✗ Discovery failed: {response.error}")

    return response


# =============================================================================
# Example 2: JWKS Fetching
# =============================================================================


def fetch_jwks_example():
    """Fetch JWKS synchronously."""
    print("\\n" + "=" * 60)
    print("Example 2: JWKS Fetching")
    print("=" * 60)

    jwks_request = JwksRequest(
        address="https://demo.duendesoftware.com/.well-known/openid-configuration/jwks"
    )

    # Synchronous fetch - blocks until response received
    response = get_jwks(jwks_request)

    if response.is_successful:
        assert response.keys is not None
        print("✓ JWKS fetched successfully!")
        print(f"  Number of keys: {len(response.keys)}")
        for key in response.keys:
            print(f"  - Key ID: {key.kid}, Algorithm: {key.alg}, Type: {key.kty}")
    else:
        print(f"✗ JWKS fetch failed: {response.error}")

    return response


# =============================================================================
# Example 3: Client Credentials Token Request
# =============================================================================


def request_token_example():
    """Request access token using client credentials flow."""
    print("\\n" + "=" * 60)
    print("Example 3: Client Credentials Token")
    print("=" * 60)

    token_request = ClientCredentialsTokenRequest(
        address="https://demo.duendesoftware.com/connect/token",
        client_id="m2m",
        client_secret="secret",
        scope="api",
    )

    # Synchronous request - blocks until response received
    response = request_client_credentials_token(token_request)

    if response.is_successful:
        assert response.token is not None
        print("✓ Token obtained successfully!")
        print(f"  Token Type: {response.token.get('token_type')}")
        print(f"  Expires In: {response.token.get('expires_in')} seconds")
        print(
            f"  Access Token (first 50 chars): {str(response.token.get('access_token'))[:50]}..."
        )
        return response.token.get("access_token")
    print(f"✗ Token request failed: {response.error}")
    return None


# =============================================================================
# Example 4: Token Validation
# =============================================================================


def validate_token_example(access_token: str):
    """Validate an access token."""
    print("\\n" + "=" * 60)
    print("Example 4: Token Validation")
    print("=" * 60)

    try:
        # Configure token validation
        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,  # Set to your API audience
            options={
                "verify_aud": False,  # Disabled for demo
                "require_aud": False,
            },
        )

        # Synchronous validation - blocks until complete
        decoded = validate_token(
            access_token,
            config,
            disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
        )

        print("✓ Token validated successfully!")
        print(f"  Subject: {decoded.get('sub')}")
        print(f"  Issuer: {decoded.get('iss')}")
        print(f"  Client ID: {decoded.get('client_id')}")
        print(f"  Scope: {decoded.get('scope')}")
        return decoded

    except Exception as e:
        print(f"✗ Token validation failed: {e}")
        return None


# =============================================================================
# Example 5: Custom Claims Validation
# =============================================================================


def custom_claims_validation_example(access_token: str):
    """Validate a token with custom claims validation."""
    print("\\n" + "=" * 60)
    print("Example 5: Custom Claims Validation")
    print("=" * 60)

    def custom_validator(claims: dict) -> None:
        """Custom claims validator function."""
        # Ensure the token has specific scopes
        scope = claims.get("scope", "")
        if "api" not in scope:
            raise ValueError("Token must have 'api' scope")

        # Add any other custom validation logic here
        print(f"  ✓ Custom validation passed for scope: {scope}")

    try:
        config = TokenValidationConfig(
            perform_disco=True,
            audience=None,
            claims_validator=custom_validator,  # Custom validator
            options={"verify_aud": False, "require_aud": False},
        )

        decoded = validate_token(
            access_token,
            config,
            disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
        )

        print("✓ Token with custom claims validated successfully!")
        return decoded

    except Exception as e:
        print(f"✗ Custom claims validation failed: {e}")
        return None


# =============================================================================
# Example 6: UserInfo Endpoint
# =============================================================================


def userinfo_example(access_token: str):
    """Fetch user claims from the UserInfo endpoint."""
    print("\\n" + "=" * 60)
    print("Example 6: UserInfo Endpoint")
    print("=" * 60)

    # First get the discovery document to find the userinfo endpoint
    discovery_request = DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)
    disco_response = get_discovery_document(discovery_request)

    if not disco_response.is_successful:
        print(f"✗ Discovery failed: {disco_response.error}")
        return None

    userinfo_endpoint = disco_response.userinfo_endpoint
    if not userinfo_endpoint:
        print("✗ No userinfo endpoint found in discovery document")
        return None

    print(f"  UserInfo Endpoint: {userinfo_endpoint}")

    # Request user info using the access token
    userinfo_request = UserInfoRequest(
        address=userinfo_endpoint,
        token=access_token,
    )

    response = get_userinfo(userinfo_request)

    if response.is_successful:
        print("✓ UserInfo fetched successfully!")
        if response.claims:
            for claim_name, claim_value in response.claims.items():
                print(f"  {claim_name}: {claim_value}")
        return response
    print(f"✗ UserInfo request failed: {response.error}")
    print(
        "  Note: Client credentials tokens may not have a userinfo endpoint available"
    )
    return response


# =============================================================================
# Example 7: Error Handling
# =============================================================================


def error_handling_example():
    """Demonstrate comprehensive error handling."""
    print("\\n" + "=" * 60)
    print("Example 7: Error Handling")
    print("=" * 60)

    # Test with invalid URL
    print("\\nTesting with invalid discovery URL...")
    discovery_request = DiscoveryDocumentRequest(
        address="https://invalid-url-that-does-not-exist.example.com/.well-known/openid-configuration"
    )

    response = get_discovery_document(discovery_request)

    if not response.is_successful:
        print("✓ Error handled gracefully")
        print(f"  Error message: {response.error}")
        print("  Application continues normally...")
    else:
        print("✗ Unexpected success")

    # Test with invalid token
    print("\\nTesting with invalid token...")
    try:
        config = TokenValidationConfig(
            perform_disco=False,
            key={"kty": "RSA", "n": "test", "e": "AQAB"},
            algorithms=["RS256"],
        )

        validate_token("invalid.jwt.token", config)
        print("✗ Unexpected success")
    except Exception as e:
        print("✓ Exception caught and handled")
        print(f"  Exception type: {type(e).__name__}")
        print(f"  Error message: {str(e)[:100]}...")


# =============================================================================
# Example 8: Flask Integration Pattern
# =============================================================================


def flask_pattern_example():
    """
    Example pattern for using py-identity-model in Flask.

    This is a demonstration - in real Flask, you'd use decorators or before_request.
    """
    print("\\n" + "=" * 60)
    print("Example 8: Flask Integration Pattern")
    print("=" * 60)

    def protected_endpoint(authorization: str):
        """Simulated Flask protected endpoint."""
        # Extract token from Authorization header
        if not authorization or not authorization.startswith("Bearer "):
            return {"error": "Invalid authorization header"}, 401

        token = authorization.replace("Bearer ", "")

        try:
            # Validate token synchronously (Flask is sync by default)
            config = TokenValidationConfig(
                perform_disco=True,
                audience="api",
            )

            claims = validate_token(
                token,
                config,
                disco_doc_address="https://demo.duendesoftware.com/.well-known/openid-configuration",
            )

            return {
                "message": "Access granted",
                "user_id": claims.get("sub"),
                "scopes": claims.get("scope"),
            }, 200
        except Exception as e:
            return {"error": f"Unauthorized: {e}"}, 401

    # Get a token first
    token_request = ClientCredentialsTokenRequest(
        address="https://demo.duendesoftware.com/connect/token",
        client_id="m2m",
        client_secret="secret",
        scope="api",
    )

    token_response = request_client_credentials_token(token_request)

    if token_response.is_successful:
        assert token_response.token is not None
        access_token = token_response.token.get("access_token")

        # Simulate the endpoint call
        result, status = protected_endpoint(f"Bearer {access_token}")
        print(f"✓ Endpoint response ({status}): {result}")
        return result
    print("✗ Could not get token for demo")
    return None


# =============================================================================
# Main: Run All Examples
# =============================================================================


def main():
    """Run all synchronous examples."""
    print("\\n" + "=" * 60)
    print("PY-IDENTITY-MODEL SYNCHRONOUS EXAMPLES")
    print("=" * 60)
    print(
        "\\nThese examples demonstrate traditional synchronous operations (blocking I/O)."
    )
    print("Perfect for scripts, CLIs, Flask, Django, and simple applications.\\n")

    # Example 1: Discovery
    fetch_discovery_document_example()

    # Example 2: JWKS
    fetch_jwks_example()

    # Example 3: Token Request
    access_token = request_token_example()

    # Example 4: Token Validation
    if access_token:
        validate_token_example(access_token)

        # Example 5: Custom Claims Validation
        custom_claims_validation_example(access_token)

        # Example 6: UserInfo
        userinfo_example(access_token)

    # Example 7: Error Handling
    error_handling_example()

    # Example 8: Flask Pattern
    flask_pattern_example()

    print("\\n" + "=" * 60)
    print("All synchronous examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
