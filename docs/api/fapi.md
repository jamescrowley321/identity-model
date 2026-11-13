# FAPI 2.0 Security Profile

A fail-closed FAPI 2.0 client profile, and compliance validation helpers for
the FAPI 2.0 Security Profile.

## Client Profile

::: py_identity_model.core.fapi.FAPI2ClientProfile

::: py_identity_model.core.fapi.FAPIProfileError

## Constants

::: py_identity_model.core.fapi.FAPI2_ALLOWED_SIGNING_ALGORITHMS

::: py_identity_model.core.fapi.FAPI2_MAX_NONCE_LENGTH

::: py_identity_model.core.fapi.FAPI2_MAX_REQUEST_OBJECT_LIFETIME

::: py_identity_model.core.fapi.FAPI2_REQUIRED_PKCE_METHOD

::: py_identity_model.core.fapi.FAPI2_REQUIRED_RESPONSE_TYPE

## Validation Result

::: py_identity_model.core.fapi.FAPIValidationResult

## Validation Functions

The validation functions check the FAPI 2.0 specification. The client
profile is narrower: it uses exactly one of `private_key_jwt` (tokens bound
with DPoP) or mTLS (tokens bound to the certificate), and it also checks the
discovery document, the endpoints and the redirect URI. So
`validate_fapi_client_config` accepts `private_key_jwt` with mTLS-bound
tokens, and mTLS client authentication with a DPoP key, which
`FAPI2ClientProfile` refuses. Use the profile when you want every check.

::: py_identity_model.core.fapi.validate_fapi_authorization_request

::: py_identity_model.core.fapi.validate_fapi_client_config

::: py_identity_model.core.fapi.validate_fapi_discovery
