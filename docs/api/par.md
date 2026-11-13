# Pushed Authorization Requests (PAR)

OAuth 2.0 Pushed Authorization Requests (RFC 9126) for enhanced authorization security.

## Request Model

::: py_identity_model.core.models.PushedAuthorizationRequest

To send the parameters as a signed request object (RFC 9101, RFC 9126 §3),
use `SignedPushedAuthorizationRequest`; see [JAR](jar.md).

::: py_identity_model.core.models.SignedPushedAuthorizationRequest

## Response Model

::: py_identity_model.core.models.PushedAuthorizationResponse

## Functions

::: py_identity_model.sync.par.push_authorization_request

## Authorization URL

::: py_identity_model.core.authorize_url.build_par_authorization_url
