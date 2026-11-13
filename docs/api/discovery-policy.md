# Discovery Policy

Configurable security policy for OpenID Connect discovery validation.

A policy can be supplied directly to `get_discovery_document` (via
`DiscoveryDocumentRequest.policy`) and to the cached token-validation path (via
`TokenValidationConfig.discovery_policy`).

## Cached token validation

`TokenValidationConfig.discovery_policy` applies a full policy while still using
the built-in discovery and JWKS TTL caches — no need to fetch discovery yourself
and re-implement caching. When it is `None` (the default) a policy is derived
from `require_https` alone, so existing behavior is unchanged; when set, it takes
precedence over `require_https`.

```python
from py_identity_model import (
    DiscoveryPolicy,
    TokenValidationConfig,
    validate_token,
)

# The issuer publishes its JWKS on a separate CDN host — allow that authority
# while keeping every other endpoint pinned to the issuer.
config = TokenValidationConfig(
    perform_disco=True,
    audience="my-api",
    discovery_policy=DiscoveryPolicy(
        additional_endpoint_base_addresses=["https://keys.cdn.example"],
    ),
)

claims = validate_token(
    jwt=token,
    token_validation_config=config,
    disco_doc_address="https://issuer.example/.well-known/openid-configuration",
)
```

The discovery cache is partitioned by the full policy, so a document admitted
under a lax policy is never served to a caller using a stricter one.

## Policy Configuration

::: py_identity_model.core.discovery_policy.DiscoveryPolicy

## Discovery Document URL

`DiscoveryDocumentRequest.address` and `disco_doc_address` take the discovery
document URL. `discovery_document_url` derives it from an issuer identifier
(OpenID Connect Discovery 1.0 §4.1).

```python
from py_identity_model import discovery_document_url

discovery_document_url("https://auth.example.com/tenant1")
# "https://auth.example.com/tenant1/.well-known/openid-configuration"
```

::: py_identity_model.core.discovery_policy.discovery_document_url

## Utilities

::: py_identity_model.core.discovery_policy.validate_url_scheme

::: py_identity_model.core.discovery_policy.is_loopback
