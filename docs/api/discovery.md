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
`error_code` for classification instead of parsing that text.

| `error_code` | Meaning | Additional details |
| --- | --- | --- |
| `http_status` | The endpoint returned a non-success HTTP status | `status_code` is the actual HTTP status |
| `parse` | JSON decoding failed | |
| `missing_fields` | A required-field check failed | `missing_fields` lists the fields rejected by that check |
| `https_required` | The URL violated the policy's HTTPS requirement | |
| `configuration` | Another URL/configuration check failed | |
| `validation` | Another discovery validation check failed | |
| `network` | HTTP transport failed | |
| `unexpected` | An unclassified exception occurred | |

On success, `error_code` and `status_code` are `None`, and `missing_fields` is
empty. These fields are optional keyword-only additions; existing positional
response constructors and exception base classes remain compatible.

The metadata describes the checks the library actually performs. It does not
add issuer matching (#574) or make the authorization/token endpoints required
(#771). A field failure reports the fields in the failing check, rather than
claiming an exhaustive audit of the whole document.
