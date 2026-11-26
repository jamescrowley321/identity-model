#!/usr/bin/env python3
"""
Script to generate an access token from the locally running identity server.

This script connects to the local identity server at https://localhost:5001
and generates an access token using the client credentials flow.

Usage:
    python examples/generate_token.py

Requirements:
    - Local identity server must be running (cd examples && docker compose -f docker-compose.test.yml up identityserver -d)
    - Certificates are automatically generated and trusted in Docker
"""

import sys

from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    get_discovery_document,
    request_client_credentials_token,
)


def main():
    """Generate a token from the local identity server."""

    # Local identity server configuration
    issuer = "https://localhost:5001"
    client_id = "py-identity-model-client"
    client_secret = "py-identity-model-secret"
    scope = "py-identity-model"

    print("🔍 Discovering endpoints from local identity server...")
    print(f"   Issuer: {issuer}")

    # Get discovery document to find token endpoint
    disco_request = DiscoveryDocumentRequest(issuer=issuer)
    disco_response = get_discovery_document(disco_request)

    if not disco_response.is_successful:
        print(f"❌ Failed to get discovery document: {disco_response.error}")
        print("\n💡 Make sure the local identity server is running:")
        print(
            "      cd examples && docker compose -f docker-compose.test.yml up identityserver -d",
        )
        print("\n   Or use the full test setup:")
        print(
            "      cd examples && docker compose -f docker-compose.test.yml up --build",
        )
        return 1

    print("✅ Discovery successful!")
    print(f"   Issuer: {disco_response.issuer}")
    print(f"   Token endpoint: {disco_response.token_endpoint}")

    # Request token using client credentials flow
    print("\n🎫 Requesting access token...")
    print(f"   Client ID: {client_id}")
    print(f"   Scope: {scope}")

    # Check if token endpoint is available
    token_endpoint = disco_response.token_endpoint
    if token_endpoint is None or token_endpoint == "":
        print("❌ No token endpoint found in discovery document")
        return 1

    token_request = ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
    )

    token_response = request_client_credentials_token(token_request)

    if not token_response.is_successful:
        print(f"❌ Failed to get token: {token_response.error}")
        return 1

    print("✅ Token generated successfully!")

    # Extract and display token information
    token_data = token_response.token or {}
    access_token = token_data.get("access_token", "")
    token_type = token_data.get("token_type", "Bearer")
    expires_in = token_data.get("expires_in", 0)

    print("\n📋 Token Information:")
    print(f"   Token Type: {token_type}")
    print(f"   Expires In: {expires_in} seconds")
    print(f"   Scope: {token_data.get('scope', 'N/A')}")

    print("\n🔑 Access Token:")
    print(f"   {access_token}")

    print("\n💡 Usage Examples:")
    print("   # Use in Authorization header:")
    print(f"   Authorization: {token_type} {access_token}")
    print("   ")
    print("   # Use with curl:")
    print(
        f'   curl -H "Authorization: {token_type} {access_token}" https://your-api.com/endpoint',
    )

    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
