# Exceptions

All exceptions inherit from `PyIdentityModelException`.

```
PyIdentityModelException
├── ValidationException
│   ├── AuthorizeCallbackException
│   └── TokenValidationException
│       ├── SignatureVerificationException
│       ├── TokenExpiredException
│       ├── InvalidAudienceException
│       ├── InvalidIssuerException
│       └── AmbiguousKeyException
├── NetworkException
│   ├── DiscoveryException
│   ├── JwksException
│   ├── TokenRequestException
│   └── UserInfoException
├── ConfigurationException
├── FailedResponseAccessError
└── SuccessfulResponseAccessError
```

## Base Exception

::: py_identity_model.exceptions.PyIdentityModelException

## Validation Exceptions

::: py_identity_model.exceptions.ValidationException

::: py_identity_model.exceptions.AuthorizeCallbackException

::: py_identity_model.exceptions.TokenValidationException

::: py_identity_model.exceptions.SignatureVerificationException

::: py_identity_model.exceptions.TokenExpiredException

::: py_identity_model.exceptions.InvalidAudienceException

::: py_identity_model.exceptions.InvalidIssuerException

::: py_identity_model.exceptions.AmbiguousKeyException

## Network Exceptions

::: py_identity_model.exceptions.NetworkException

::: py_identity_model.exceptions.DiscoveryException

::: py_identity_model.exceptions.JwksException

::: py_identity_model.exceptions.TokenRequestException

::: py_identity_model.exceptions.UserInfoException

## Configuration Exceptions

::: py_identity_model.exceptions.ConfigurationException

## Response Guard Errors

::: py_identity_model.exceptions.FailedResponseAccessError

::: py_identity_model.exceptions.SuccessfulResponseAccessError
