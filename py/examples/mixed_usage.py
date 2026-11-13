"""
Mixed Sync/Async Usage Example

This example demonstrates how to use both synchronous and asynchronous APIs
from py-identity-model in the same application.

This is useful for:
- Migrating from sync to async incrementally
- Using async in async contexts (FastAPI) and sync elsewhere (CLI tools, scripts)
- Mixing frameworks (e.g., FastAPI for API + sync batch jobs)
"""

import asyncio
import os
import time

# Import both sync and async versions
from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    TokenValidationConfig,
)
from py_identity_model import (
    get_discovery_document as sync_get_discovery_document,
)
from py_identity_model import (
    request_client_credentials_token as sync_request_token,
)
from py_identity_model import (
    validate_token as sync_validate_token,
)
from py_identity_model.aio import (
    get_discovery_document as async_get_discovery_document,
)
from py_identity_model.aio import (
    request_client_credentials_token as async_request_token,
)
from py_identity_model.aio import (
    validate_token as async_validate_token,
)


# Configuration
DISCO_ADDRESS = os.environ.get(
    "DISCO_ADDRESS",
    "https://demo.duendesoftware.com/.well-known/openid-configuration",
)
CLIENT_ID = os.environ.get("CLIENT_ID", "m2m")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "secret")
AUDIENCE = os.environ.get("AUDIENCE", "api")


# =============================================================================
# Example 1: Synchronous Usage (Scripts, CLI tools, simple applications)
# =============================================================================


def sync_example():
    """
    Synchronous example - good for:
    - Command-line scripts
    - Batch processing jobs
    - Simple applications
    - Environments where async is not available
    """
    print("\n" + "=" * 60)
    print("SYNCHRONOUS EXAMPLE")
    print("=" * 60)

    # 1. Get discovery document (synchronous)
    print("\n1. Fetching discovery document (sync)...")
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = sync_get_discovery_document(disco_request)

    if disco_response.is_successful:
        print(f"✓ Issuer: {disco_response.issuer}")
        print(f"✓ Token Endpoint: {disco_response.token_endpoint}")
    else:
        print(f"✗ Error: {disco_response.error}")
        return

    # 2. Request access token (synchronous)
    print("\n2. Requesting access token (sync)...")
    assert disco_response.token_endpoint is not None
    token_request = ClientCredentialsTokenRequest(
        address=disco_response.token_endpoint,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scope="api",
    )
    token_response = sync_request_token(token_request)

    if token_response.is_successful:
        assert token_response.token is not None
        print("✓ Token received successfully")
        print(f"  Token type: {token_response.token.get('token_type')}")
        print(f"  Expires in: {token_response.token.get('expires_in')} seconds")
    else:
        print(f"✗ Error: {token_response.error}")
        return

    # 3. Validate token (synchronous)
    print("\n3. Validating token (sync)...")
    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=AUDIENCE,
    )

    try:
        assert token_response.token is not None
        claims = sync_validate_token(
            jwt=token_response.token["access_token"],
            token_validation_config=validation_config,
            disco_doc_address=DISCO_ADDRESS,
        )
        print("✓ Token validated successfully")
        print(f"  Subject: {claims.get('sub')}")
        print(f"  Client ID: {claims.get('client_id')}")
    except Exception as e:
        print(f"✗ Validation failed: {e}")


# =============================================================================
# Example 2: Asynchronous Usage (FastAPI, async frameworks)
# =============================================================================


async def async_example():
    """
    Asynchronous example - good for:
    - FastAPI applications
    - High-concurrency web services
    - Applications already using asyncio
    - Concurrent operations
    """
    print("\n" + "=" * 60)
    print("ASYNCHRONOUS EXAMPLE")
    print("=" * 60)

    # 1. Get discovery document (asynchronous)
    print("\n1. Fetching discovery document (async)...")
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = await async_get_discovery_document(disco_request)

    if disco_response.is_successful:
        print(f"✓ Issuer: {disco_response.issuer}")
        print(f"✓ Token Endpoint: {disco_response.token_endpoint}")
    else:
        print(f"✗ Error: {disco_response.error}")
        return

    # 2. Request access token (asynchronous)
    print("\n2. Requesting access token (async)...")
    assert disco_response.token_endpoint is not None
    token_request = ClientCredentialsTokenRequest(
        address=disco_response.token_endpoint,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scope="api",
    )
    token_response = await async_request_token(token_request)

    if token_response.is_successful:
        assert token_response.token is not None
        print("✓ Token received successfully")
        print(f"  Token type: {token_response.token.get('token_type')}")
        print(f"  Expires in: {token_response.token.get('expires_in')} seconds")
    else:
        print(f"✗ Error: {token_response.error}")
        return

    # 3. Validate token (asynchronous)
    print("\n3. Validating token (async)...")
    validation_config = TokenValidationConfig(
        perform_disco=True,
        audience=AUDIENCE,
    )

    try:
        assert token_response.token is not None
        claims = await async_validate_token(
            jwt=token_response.token["access_token"],
            token_validation_config=validation_config,
            disco_doc_address=DISCO_ADDRESS,
        )
        print("✓ Token validated successfully")
        print(f"  Subject: {claims.get('sub')}")
        print(f"  Client ID: {claims.get('client_id')}")
    except Exception as e:
        print(f"✗ Validation failed: {e}")


# =============================================================================
# Example 3: Concurrent Async Operations (Performance Benefit)
# =============================================================================


async def concurrent_async_example():
    """
    Demonstrate the performance benefit of async operations.

    This example shows how to run multiple operations concurrently,
    which is much faster than running them sequentially.
    """
    print("\n" + "=" * 60)
    print("CONCURRENT ASYNC EXAMPLE")
    print("=" * 60)

    print("\nFetching multiple tokens concurrently...")

    # Create multiple token requests
    disco_request = DiscoveryDocumentRequest(address=DISCO_ADDRESS)
    disco_response = await async_get_discovery_document(disco_request)

    if not disco_response.is_successful:
        print(f"✗ Discovery failed: {disco_response.error}")
        return

    # Request multiple tokens concurrently
    assert disco_response.token_endpoint is not None
    token_requests = [
        ClientCredentialsTokenRequest(
            address=disco_response.token_endpoint,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope="api",
        )
        for _ in range(3)
    ]

    # Execute all requests concurrently
    start = time.time()
    responses = await asyncio.gather(
        *[async_request_token(req) for req in token_requests]
    )
    elapsed = time.time() - start

    successful = sum(1 for r in responses if r.is_successful)
    print(f"✓ Completed {successful}/{len(responses)} token requests")
    print(f"  Time: {elapsed:.2f}s (concurrent)")
    print(f"  Note: Sequential would take ~{elapsed * len(responses):.2f}s")


# =============================================================================
# Example 4: Mixed Usage in the Same Application
# =============================================================================


class MixedApp:
    """
    Example application that uses both sync and async APIs.

    This represents a real-world scenario where you might have:
    - Async web endpoints (FastAPI)
    - Sync background jobs (cron jobs, workers)
    """

    def __init__(self, disco_address: str):
        self.disco_address = disco_address

    def background_job(self):
        """
        Synchronous background job (e.g., cron job, celery task).

        Uses sync API because background jobs often run in separate
        processes without async event loops.
        """
        print("\n[Background Job] Running sync token validation...")

        disco_request = DiscoveryDocumentRequest(address=self.disco_address)
        disco_response = sync_get_discovery_document(disco_request)

        if disco_response.is_successful:
            print("[Background Job] ✓ Discovery complete")
            return disco_response
        print(f"[Background Job] ✗ Error: {disco_response.error}")
        return None

    async def api_endpoint(self, token: str):
        """
        Async API endpoint (e.g., FastAPI route handler).

        Uses async API for better performance in async web frameworks.
        """
        print("\n[API Endpoint] Validating token (async)...")

        validation_config = TokenValidationConfig(
            perform_disco=True,
            audience=AUDIENCE,
        )

        try:
            claims = await async_validate_token(
                jwt=token,
                token_validation_config=validation_config,
                disco_doc_address=self.disco_address,
            )
            print(f"[API Endpoint] ✓ Token valid for: {claims.get('sub')}")
            return {"status": "authorized", "claims": claims}
        except Exception as e:
            print(f"[API Endpoint] ✗ Validation failed: {e}")
            return {"status": "unauthorized", "error": str(e)}


def mixed_app_example():
    """Demonstrate mixed sync/async usage in the same application."""
    print("\n" + "=" * 60)
    print("MIXED SYNC/ASYNC APP EXAMPLE")
    print("=" * 60)

    app = MixedApp(DISCO_ADDRESS)

    # Sync background job
    disco_response = app.background_job()

    if disco_response and disco_response.is_successful:
        # Get a token for testing the async endpoint
        assert disco_response.token_endpoint is not None
        token_request = ClientCredentialsTokenRequest(
            address=disco_response.token_endpoint,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope="api",
        )
        token_response = sync_request_token(token_request)

        if token_response.is_successful:
            assert token_response.token is not None

            # Async API endpoint (needs to run in async context)
            access_token = token_response.token["access_token"]

            async def test_endpoint():
                return await app.api_endpoint(access_token)

            result = asyncio.run(test_endpoint())
            print(f"\n[Result] {result['status']}")


# =============================================================================
# Main
# =============================================================================


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("PY-IDENTITY-MODEL: MIXED SYNC/ASYNC USAGE EXAMPLES")
    print("=" * 60)
    print(f"\nDiscovery Address: {DISCO_ADDRESS}")
    print(f"Client ID: {CLIENT_ID}")

    # Example 1: Synchronous usage
    sync_example()

    # Example 2: Asynchronous usage
    print("\nRunning async example...")
    asyncio.run(async_example())

    # Example 3: Concurrent async operations
    print("\nRunning concurrent async example...")
    asyncio.run(concurrent_async_example())

    # Example 4: Mixed usage
    mixed_app_example()

    print("\n" + "=" * 60)
    print("SUMMARY: When to use sync vs async")
    print("=" * 60)
    print(
        """
    Use SYNC when:
    ✓ Writing CLI tools or scripts
    ✓ Running batch jobs or cron tasks
    ✓ Working with synchronous frameworks (Flask, Django)
    ✓ Simplicity is more important than concurrency

    Use ASYNC when:
    ✓ Building with async frameworks (FastAPI, Starlette)
    ✓ Handling many concurrent operations
    ✓ Application already uses asyncio
    ✓ Performance under high load is critical

    You can use BOTH in the same application!
    """
    )


if __name__ == "__main__":
    main()
