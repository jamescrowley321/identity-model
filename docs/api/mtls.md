# Mutual TLS (mTLS)

OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
(RFC 8705): authenticate the client with an X.509 certificate at the TLS layer
instead of a shared secret, and verify that an access token is bound to the
certificate that requested it.

## Client authentication

Attach an [`MtlsClientAuth`](#py_identity_model.core.models.MtlsClientAuth) to
any client-authenticating request (`ClientCredentialsTokenRequest`,
`AuthorizationCodeTokenRequest`, `RefreshTokenRequest`, introspection,
revocation, PAR, device, token-exchange, and UserInfo requests) via its `mtls`
field. The certificate is presented during the TLS handshake, `client_id` goes
in the request body, and no `Authorization` header is sent (RFC 8705 §2).
When both are present, `private_key_jwt` takes precedence over `mtls`, which
takes precedence over `client_secret`.

```python
from py_identity_model import (
    ClientCredentialsTokenRequest,
    DiscoveryDocumentRequest,
    MtlsClientAuth,
    get_discovery_document,
    request_client_credentials_token,
    resolve_mtls_endpoint,
)

disco = get_discovery_document(DiscoveryDocumentRequest(address=DISCOVERY_URL))

# Prefer the mTLS alias of the endpoint when the AS advertises one (§5).
token_endpoint = resolve_mtls_endpoint(disco, "token_endpoint")

response = request_client_credentials_token(
    ClientCredentialsTokenRequest(
        address=token_endpoint,
        client_id="my-mtls-client",
        scope="api",
        mtls=MtlsClientAuth(
            certificate="/path/to/client-cert.pem",
            private_key="/path/to/client-key.pem",
            auth_method="self_signed_tls_client_auth",
        ),
    )
)
```

An `mtls` value cannot be combined with a caller-managed `http_client` on the
same request — a managed client cannot be guaranteed to present the
certificate, so supplying both is rejected rather than silently sending an
unauthenticated request.

## Certificate-bound access tokens

A resource server verifying a certificate-bound token compares the token's
`cnf["x5t#S256"]` confirmation claim against the thumbprint of the certificate
the client presented at the TLS layer. `validate_certificate_binding` performs
that comparison in constant time — call it **after** normal signature and
time validation:

```python
from py_identity_model import (
    CertificateBindingError,
    TokenValidationConfig,
    validate_certificate_binding,
    validate_token,
)

claims = validate_token(token, TokenValidationConfig(perform_disco=True, audience="api"), DISCOVERY_URL)

try:
    validate_certificate_binding(claims, presented_cert_pem)
except CertificateBindingError:
    ...  # token is bound to a different certificate — reject the request
```

[`CertificateBindingError`](../api/exceptions.md) subclasses
`TokenValidationException`, so existing `except TokenValidationException`
handlers fail closed on a binding mismatch.

## API

### Client authentication

::: py_identity_model.core.models.MtlsClientAuth

::: py_identity_model.core.mtls.resolve_mtls_endpoint

### Certificate binding

::: py_identity_model.core.mtls.validate_certificate_binding

::: py_identity_model.core.mtls.compute_certificate_thumbprint

::: py_identity_model.core.mtls.certificate_thumbprint_from_file

### Exceptions

::: py_identity_model.exceptions.CertificateBindingError
