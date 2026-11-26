# Discovery

OpenID Connect Discovery 1.0 document fetching and parsing.

Discovery takes the provider's issuer identifier, not a URL. The library builds
the document URL from it: by default the issuer with any terminating `/`
removed and `/.well-known/openid-configuration` appended (OpenID Connect
Discovery 1.0 §4.1). `DiscoveryPolicy.location` selects the RFC 8414 location
instead; see [Discovery Policy](discovery-policy.md#discovery-document-location).

```python
from py_identity_model import DiscoveryDocumentRequest, get_discovery_document

response = get_discovery_document(
    DiscoveryDocumentRequest(issuer="https://auth.example.com")
)
# fetches https://auth.example.com/.well-known/openid-configuration
```

An issuer that ends with `/.well-known/openid-configuration` or
`/.well-known/oauth-authorization-server`, or that has a query, a fragment, no
host or a scheme other than `http`/`https`, is a configuration error: no request
is sent and the response fails with `INVALID_CONFIGURATION`.

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
| `ISSUER_MISMATCH` | The document's `issuer` is not the configured issuer | `requested_issuer` and `returned_issuer` |
| `INVALID_CONFIGURATION` | Another URL or configuration check failed | |
| `INVALID_DOCUMENT` | Another discovery document check failed | |
| `NETWORK_ERROR` | The HTTP transport failed | |
| `UNEXPECTED_ERROR` | An unclassified exception occurred | |

On success, `error_kind`, `status_code`, `requested_issuer` and
`returned_issuer` are `None`, and `missing_fields` is empty.

`validate_token` raises a typed exception for a failed discovery response:
`DiscoveryException` (a `NetworkException`) for `UNEXPECTED_STATUS`,
`NETWORK_ERROR` and `UNEXPECTED_ERROR`; `DiscoveryParseError`,
`DiscoveryMissingFieldsError`, `DiscoveryIssuerMismatchError` or
`DiscoveryValidationError` (all `ValidationException`s) for an invalid
document; `DiscoveryHTTPSRequiredError` or `ConfigurationException` for a URL
check or an invalid issuer. See [Exceptions](exceptions.md).

The metadata describes the checks the library actually performs.

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

    Every `DiscoveryPolicy` field is keyword-only, so a positional call
    raises `TypeError` instead of binding a value to the wrong field.

## Issuer match

The document's `issuer` must be identical to the configured issuer (OIDC
Discovery 1.0 §4.3, RFC 8414 §3.3). The comparison is exact, code point for
code point: a trailing slash, host case, an explicit port and the path all
count, so `https://op.example` and `https://op.example/` are different issuers.
Both are fetched from `https://op.example/.well-known/openid-configuration`, and
each accepts only a document that declares exactly that issuer. A mismatch
fails with `ISSUER_MISMATCH`. No `DiscoveryPolicy` setting disables it.

Configure the issuer exactly as the provider declares it. Token validation
compares the `iss` claim against the same value (OIDC Core 1.0 §3.1.3.7).

Providers that serve more than one issuer, such as Descope
(`https://api.descope.com/{project_id}` and
`https://api.descope.com/v1/apps/{project_id}`), serve each issuer's document
from that issuer's own URL, so both forms pass.
