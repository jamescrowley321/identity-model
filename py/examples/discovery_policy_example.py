"""
Discovery Policy Example

Demonstrates configuring discovery validation for different
environments using DiscoveryPolicy.
"""

from py_identity_model import (
    DiscoveryDocumentRequest,
    DiscoveryPolicy,
    TokenValidationConfig,
    discovery_document_url,
)


def production_example():
    """Production: strict HTTPS validation (default)."""
    print("\n" + "=" * 60)
    print("Discovery Policy - Production (strict defaults)")
    print("=" * 60)

    req = DiscoveryDocumentRequest(
        address=discovery_document_url("https://auth.example.com"),
    )
    print(f"\n  Address: {req.address}")
    print(f"  Policy: {req.policy} (None = strict defaults)")
    print("  HTTPS required, issuer validated, endpoints validated")


def development_example():
    """Development: relaxed policy for local testing."""
    print("\n" + "=" * 60)
    print("Discovery Policy - Development (relaxed)")
    print("=" * 60)

    policy = DiscoveryPolicy(
        require_https=False,
        validate_issuer=False,
    )
    req = DiscoveryDocumentRequest(
        address=discovery_document_url("http://localhost:8080"),
        policy=policy,
    )
    print(f"\n  Address: {req.address}")
    print(f"  require_https: {policy.require_https}")
    print(f"  validate_issuer: {policy.validate_issuer}")
    print("  HTTP allowed, issuer validation disabled")


def loopback_example():
    """Loopback exception: HTTPS required but localhost allowed."""
    print("\n" + "=" * 60)
    print("Discovery Policy - Loopback Exception")
    print("=" * 60)

    policy = DiscoveryPolicy(
        require_https=True,
        allow_http_on_loopback=True,
    )
    req = DiscoveryDocumentRequest(
        address=discovery_document_url("http://localhost:5000"),
        policy=policy,
    )
    print(f"\n  Address: {req.address}")
    print(f"  require_https: {policy.require_https}")
    print(f"  allow_http_on_loopback: {policy.allow_http_on_loopback}")
    print("  HTTPS required, but localhost gets an exception")


def cached_validation_example():
    """Inject a policy into the cached token-validation path.

    ``TokenValidationConfig.discovery_policy`` applies a full policy while
    still using the built-in discovery/JWKS TTL cache — no need to fetch
    discovery yourself and re-implement caching. Here the issuer publishes its
    JWKS on a separate CDN host, which the default strict policy would reject.
    """
    print("\n" + "=" * 60)
    print("Discovery Policy - Cached Token Validation")
    print("=" * 60)

    policy = DiscoveryPolicy(
        additional_endpoint_base_addresses=["https://keys.cdn.example"],
    )
    config = TokenValidationConfig(
        perform_disco=True,
        audience="my-api",
        discovery_policy=policy,
    )
    print(f"\n  discovery_policy: {config.discovery_policy}")
    print("  Injected policy governs discovery validation on the cached path")
    print("  (takes precedence over require_https); the built-in TTL cache is")
    print("  reused, and cache entries are partitioned by the full policy.")


def discovery_url_example():
    """Derive the discovery document URL from an issuer (OIDC Discovery §4.1)."""
    print("\n" + "=" * 60)
    print("Discovery Document URL")
    print("=" * 60)

    for issuer in ("https://auth.example.com", "https://auth.example.com/tenant1"):
        print(f"\n  Issuer: {issuer}")
        print(f"  Discovery URL: {discovery_document_url(issuer)}")


def main():
    production_example()
    development_example()
    loopback_example()
    cached_validation_example()
    discovery_url_example()
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
