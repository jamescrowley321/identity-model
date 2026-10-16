# Discovery

OpenID Connect Discovery 1.0 document fetching and parsing.

## Request / Response Models

::: py_identity_model.core.models.DiscoveryDocumentRequest

::: py_identity_model.core.models.DiscoveryDocumentResponse

## Sync API

::: py_identity_model.sync.discovery.get_discovery_document

## Async API

::: py_identity_model.aio.discovery.get_discovery_document

## Failure diagnostics

Sync and async discovery return the same structured diagnostics on a failed
`DiscoveryDocumentResponse`. `error` remains human-readable text; use
`error_kind` for classification instead of parsing that text.

```python
from py_identity_model import DiscoveryErrorKind

if response.error_kind is DiscoveryErrorKind.UNEXPECTED_STATUS:
    retry_later(response.status_code)
```

| `DiscoveryErrorKind` | Meaning | Additional details |
| --- | --- | --- |
| `UNEXPECTED_STATUS` | The endpoint returned a non-success HTTP status | `status_code` is the actual HTTP status |
| `INVALID_JSON` | The response body could not be decoded as JSON | |
| `MISSING_FIELDS` | A required-field check failed | `missing_fields` lists the fields rejected by that check |
| `HTTPS_REQUIRED` | A URL violated the policy's HTTPS requirement | |
| `INVALID_CONFIGURATION` | Another URL or configuration check failed | |
| `INVALID_DOCUMENT` | Another discovery document check failed | |
| `NETWORK_ERROR` | The HTTP transport failed | |
| `UNEXPECTED_ERROR` | An unclassified exception occurred | |

On success, `error_kind` and `status_code` are `None`, and `missing_fields` is
empty. These fields are optional keyword-only additions; existing positional
response constructors and exception base classes remain compatible.

The metadata describes the checks the library actually performs. It does not
add issuer matching (#574).

## Required metadata

A discovery document must carry all seven REQUIRED fields of
[OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata):
`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`response_types_supported`, `subject_types_supported` and
`id_token_signing_alg_values_supported`. A field that is absent, `null`,
`false`, `0`, an empty string, an empty array or an empty object is missing.
The request fails with `MISSING_FIELDS`, and `missing_fields` lists every
missing field in that order. A body that is valid JSON but not an object (for
example `[]` or `null`) fails with `INVALID_JSON`.

§3 exempts `token_endpoint` when a provider supports only the Implicit Flow.
The library requires it anyway, by policy. No `DiscoveryPolicy` setting relaxes
any of these fields.

!!! warning "`require_key_set` removed"
    `DiscoveryPolicy.require_key_set` has been removed. `jwks_uri` is always
    required, so `DiscoveryPolicy(require_key_set=False)` raises `TypeError`.
    Delete the argument. A provider that publishes no `jwks_uri` cannot be
    used for discovery.

    The fields after `validate_endpoints` (`additional_endpoint_base_addresses`,
    `authority`, `allow_loopback_endpoints`) are now keyword-only. A call that
    passed `require_key_set` as the fifth positional argument, such as
    `DiscoveryPolicy(True, True, True, True, False)`, raises `TypeError`
    instead of binding the value to another field. Pass those fields by name.
