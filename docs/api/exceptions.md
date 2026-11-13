# Exceptions

All exceptions inherit from `PyIdentityModelException`.

```
PyIdentityModelException
├── ValidationException
│   ├── AuthorizeCallbackException
│   │   └── JarmValidationException
│   ├── LogoutStateValidationException
│   ├── DiscoveryValidationError
│   │   ├── DiscoveryParseError
│   │   ├── DiscoveryMissingFieldsError
│   │   └── DiscoveryIssuerMismatchError
│   ├── JwksValidationError
│   └── TokenValidationException
│       ├── SignatureVerificationException
│       ├── TokenExpiredException
│       ├── InvalidAudienceException
│       ├── InvalidIssuerException
│       ├── KeyNotFoundException
│       ├── AmbiguousKeyException
│       ├── KeyAlgorithmMismatchException
│       ├── WeakKeyException
│       ├── CertificateBindingError
│       ├── ClaimsValidationError
│       ├── DPoPValidationError
│       ├── IntrospectedTokenError  (see Token Introspection)
│       ├── LogoutTokenValidationException
│       └── IdTokenValidationException
│           └── UntrustedAudienceException
├── NetworkException
│   ├── DiscoveryException
│   ├── JwksException
│   ├── TokenRequestException
│   └── UserInfoException
├── ConfigurationException
│   ├── ConfigError
│   ├── FAPIProfileError
│   ├── InvalidArgumentError
│   ├── DPoPKeyError
│   ├── ClientAuthMethodError
│   ├── AzpRequiresClientIdError
│   ├── DPoPReplayCacheError
│   └── DiscoveryHTTPSRequiredError
├── FailedResponseAccessError
└── SuccessfulResponseAccessError
```

A `NetworkException` means a provider could not be reached or answered with a
non-success status: retrying later may succeed. A `ValidationException` means
a token or a fetched document is invalid: retrying returns the same result. A
`ConfigurationException` means the call itself is misconfigured; it is raised,
never returned on a failed response.

## Base Exception

::: py_identity_model.exceptions.PyIdentityModelException

## Validation Exceptions

::: py_identity_model.exceptions.ValidationException

::: py_identity_model.exceptions.AuthorizeCallbackException

::: py_identity_model.exceptions.DiscoveryValidationError

::: py_identity_model.exceptions.DiscoveryParseError

::: py_identity_model.exceptions.DiscoveryMissingFieldsError

::: py_identity_model.exceptions.DiscoveryIssuerMismatchError

::: py_identity_model.exceptions.JwksValidationError

`JarmValidationException`: see [JARM](jarm.md#py_identity_model.exceptions.JarmValidationException).

`LogoutStateValidationException`: see [Logout](logout.md#py_identity_model.exceptions.LogoutStateValidationException).

::: py_identity_model.exceptions.TokenValidationException

::: py_identity_model.exceptions.SignatureVerificationException

::: py_identity_model.exceptions.TokenExpiredException

::: py_identity_model.exceptions.InvalidAudienceException

::: py_identity_model.exceptions.InvalidIssuerException

::: py_identity_model.exceptions.KeyNotFoundException

::: py_identity_model.exceptions.AmbiguousKeyException

::: py_identity_model.exceptions.KeyAlgorithmMismatchException

::: py_identity_model.exceptions.WeakKeyException

`CertificateBindingError`: see [Mutual TLS](mtls.md#py_identity_model.exceptions.CertificateBindingError).

`LogoutTokenValidationException`: see [Logout](logout.md#py_identity_model.exceptions.LogoutTokenValidationException).

`IdTokenValidationException`: see [ID Token validation](id-token.md#py_identity_model.exceptions.IdTokenValidationException).

`UntrustedAudienceException`: see [ID Token validation](id-token.md#py_identity_model.exceptions.UntrustedAudienceException).

## Network Exceptions

::: py_identity_model.exceptions.NetworkException

::: py_identity_model.exceptions.DiscoveryException

::: py_identity_model.exceptions.JwksException

::: py_identity_model.exceptions.TokenRequestException

::: py_identity_model.exceptions.UserInfoException

## Configuration Exceptions

::: py_identity_model.exceptions.ConfigurationException

::: py_identity_model.exceptions.DiscoveryHTTPSRequiredError

::: py_identity_model.exceptions.InvalidArgumentError

::: py_identity_model.exceptions.InvalidArgumentKind

::: py_identity_model.exceptions.DPoPKeyError

::: py_identity_model.exceptions.DPoPKeyErrorKind

`ConfigError`: see [Configuration](config.md#py_identity_model.core.config.ConfigError).

`FAPIProfileError`: see [FAPI 2.0](fapi.md#py_identity_model.core.fapi.FAPIProfileError).

## Response Guard Errors

::: py_identity_model.exceptions.FailedResponseAccessError

::: py_identity_model.exceptions.SuccessfulResponseAccessError
