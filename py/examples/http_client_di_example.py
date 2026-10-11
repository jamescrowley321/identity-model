"""
HTTP Client Dependency Injection Examples for py-identity-model

Demonstrates three patterns for managing HTTP client lifecycle:
1. Context manager (recommended for scripts/applications)
2. Shared client across multiple calls
3. Custom client configuration (timeout, SSL)
"""

from py_identity_model import (
    Config,
    DiscoveryDocumentRequest,
    HTTPClient,
    JwksRequest,
    get_discovery_document,
    get_jwks,
)


DEMO_DISCOVERY_URL = "https://demo.duendesoftware.com/.well-known/openid-configuration"


# =============================================================================
# Example 1: Context Manager (Recommended)
# =============================================================================


def context_manager_example():
    """Use HTTPClient as a context manager for automatic cleanup."""
    print("\n" + "=" * 60)
    print("Example 1: Context Manager")
    print("=" * 60)

    with HTTPClient() as client:
        response = get_discovery_document(
            DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL),
            http_client=client,
        )

    if response.is_successful:
        print(f"  Issuer: {response.issuer}")
        print("  Client automatically closed after context exit")

    return response


# =============================================================================
# Example 2: Shared Client Across Multiple Calls
# =============================================================================


def shared_client_example():
    """Share a single HTTP client across multiple operations."""
    print("\n" + "=" * 60)
    print("Example 2: Shared Client")
    print("=" * 60)

    with HTTPClient() as client:
        # All calls share the same connection pool
        disco = get_discovery_document(
            DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL),
            http_client=client,
        )

        if disco.is_successful and disco.jwks_uri:
            jwks = get_jwks(
                JwksRequest(address=disco.jwks_uri),
                http_client=client,
            )
            if jwks.is_successful and jwks.keys:
                print(f"  Found {len(jwks.keys)} keys via shared client")

    return disco


# =============================================================================
# Example 3: Custom Timeout
# =============================================================================


def custom_timeout_example():
    """Create a client with custom timeout for slow endpoints."""
    print("\n" + "=" * 60)
    print("Example 3: Custom Timeout")
    print("=" * 60)

    # Settings come from a Config; a CA bundle is set the same way, e.g.
    # Config(http_timeout=60.0, ca_bundle="/path/to/ca-bundle.crt").
    with HTTPClient(config=Config(http_timeout=60.0)) as client:
        response = get_discovery_document(
            DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL),
            http_client=client,
        )

    if response.is_successful:
        print(f"  Issuer: {response.issuer} (with 60s timeout)")

    return response


# =============================================================================
# Example 4: Backward Compatibility
# =============================================================================


def backward_compat_example():
    """Existing code without http_client still works."""
    print("\n" + "=" * 60)
    print("Example 4: Backward Compatibility")
    print("=" * 60)

    # No http_client parameter — uses the library default client
    response = get_discovery_document(
        DiscoveryDocumentRequest(address=DEMO_DISCOVERY_URL)
    )

    if response.is_successful:
        print(f"  Issuer: {response.issuer} (library default client)")

    return response


# =============================================================================
# Example 5: FastAPI / Starlette Integration Pattern
# =============================================================================


def framework_integration_pattern():
    """Demonstrate how to integrate with web frameworks."""
    print("\n" + "=" * 60)
    print("Example 5: Web Framework Integration Pattern")
    print("=" * 60)

    print("""
    # In FastAPI:
    from contextlib import asynccontextmanager
    from py_identity_model.aio import AsyncHTTPClient, get_discovery_document

    @asynccontextmanager
    async def lifespan(app):
        app.state.http_client = AsyncHTTPClient()
        yield
        await app.state.http_client.close()

    @app.get("/discovery")
    async def discovery(request: Request):
        disco = await get_discovery_document(
            DiscoveryDocumentRequest(address="..."),
            http_client=request.app.state.http_client,
        )
        return {"issuer": disco.issuer}
    """)


# =============================================================================
# Main
# =============================================================================


def main():
    """Run all HTTP client DI examples."""
    print("\n" + "=" * 60)
    print("PY-IDENTITY-MODEL HTTP CLIENT DI EXAMPLES")
    print("=" * 60)

    context_manager_example()
    shared_client_example()
    custom_timeout_example()
    backward_compat_example()
    framework_integration_pattern()

    print("\n" + "=" * 60)
    print("All HTTP client DI examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
