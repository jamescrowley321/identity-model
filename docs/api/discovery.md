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
add issuer matching (#574) or make the authorization/token endpoints required
(#771). A field failure reports the fields in the failing check, rather than
claiming an exhaustive audit of the whole document.
