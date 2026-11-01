# Authorize Callback

Parse OAuth 2.0 / OIDC authorization callback redirect URIs, validate the `state` parameter for CSRF protection, and validate the `iss` parameter (RFC 9207) to defend against authorization-server mix-up attacks.

These functions are pure (no I/O) and available identically from both sync and async modules.

## Response Model

::: py_identity_model.core.authorize_response.AuthorizeCallbackResponse

## Parsing

::: py_identity_model.core.authorize_response.parse_authorize_callback_response

## State Validation

::: py_identity_model.core.state_validation.AuthorizeCallbackValidationResult

::: py_identity_model.core.state_validation.StateValidationResult

::: py_identity_model.core.state_validation.validate_authorize_callback_state

## Issuer Validation (RFC 9207)

Validate the authorization-response `issuer` against the expected authorization
server to close the mix-up attack class. Drive enforcement from the discovery
metadata flag `authorization_response_iss_parameter_supported` (passed as
`iss_parameter_supported=`), or require it
strictly via `require=True`.

::: py_identity_model.core.state_validation.validate_authorize_callback_issuer
