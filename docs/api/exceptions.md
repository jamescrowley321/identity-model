# Exceptions

All exceptions inherit from `PyIdentityModelException`.

```
PyIdentityModelException
├── ValidationException
│   ├── AuthorizeCallbackException
│   │   └── JarmValidationException
│   ├── LogoutStateValidationException
│   └── TokenValidationException
│       ├── SignatureVerificationException
│       ├── TokenExpiredException
│       ├── InvalidAudienceException
│       ├── InvalidIssuerException
│       ├── AmbiguousKeyException
│       ├── KeyAlgorithmMismatchException
│       ├── CertificateBindingError
│       ├── LogoutTokenValidationException
│       └── IdTokenValidationException
│           └── UntrustedAudienceException
├── NetworkException
│   ├── DiscoveryException
│   │   ├── DiscoveryParseError
│   │   ├── DiscoveryMissingFieldsError
│   │   └── DiscoveryIssuerMismatchError
│   ├── JwksException
│   ├── TokenRequestException
│   └── UserInfoException
├── ConfigurationException
│   └── DiscoveryHTTPSRequiredError
├── FailedResponseAccessError
└── SuccessfulResponseAccessError
```

## Base Exception

::: py_identity_model.exceptions.PyIdentityModelException

## Validation Exceptions

::: py_identity_model.exceptions.ValidationException

::: py_identity_model.exceptions.AuthorizeCallbackException

`JarmValidationException`: see [JARM](jarm.md#py_identity_model.exceptions.JarmValidationException).

`LogoutStateValidationException`: see [Logout](logout.md#py_identity_model.exceptions.LogoutStateValidationException).

::: py_identity_model.exceptions.TokenValidationException

::: py_identity_model.exceptions.SignatureVerificationException

::: py_identity_model.exceptions.TokenExpiredException

::: py_identity_model.exceptions.InvalidAudienceException

::: py_identity_model.exceptions.InvalidIssuerException

::: py_identity_model.exceptions.AmbiguousKeyException

::: py_identity_model.exceptions.KeyAlgorithmMismatchException

`CertificateBindingError`: see [Mutual TLS](mtls.md#py_identity_model.exceptions.CertificateBindingError).

`LogoutTokenValidationException`: see [Logout](logout.md#py_identity_model.exceptions.LogoutTokenValidationException).

`IdTokenValidationException`: see [ID Token validation](id-token.md#py_identity_model.exceptions.IdTokenValidationException).

`UntrustedAudienceException`: see [ID Token validation](id-token.md#py_identity_model.exceptions.UntrustedAudienceException).

## Network Exceptions

::: py_identity_model.exceptions.NetworkException

::: py_identity_model.exceptions.DiscoveryException

::: py_identity_model.exceptions.DiscoveryParseError

::: py_identity_model.exceptions.DiscoveryMissingFieldsError

::: py_identity_model.exceptions.DiscoveryIssuerMismatchError

::: py_identity_model.exceptions.JwksException

::: py_identity_model.exceptions.TokenRequestException

::: py_identity_model.exceptions.UserInfoException

## Configuration Exceptions

::: py_identity_model.exceptions.ConfigurationException

::: py_identity_model.exceptions.DiscoveryHTTPSRequiredError

## Response Guard Errors

::: py_identity_model.exceptions.FailedResponseAccessError

::: py_identity_model.exceptions.SuccessfulResponseAccessError
