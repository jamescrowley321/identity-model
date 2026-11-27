# JAR (JWT Secured Authorization Request)

OAuth 2.0 JWT Secured Authorization Request (RFC 9101) for passing authorization parameters as signed JWTs.

## Request Object Creation

::: py_identity_model.core.jar.create_request_object

## Signing Key

`FAPI2ClientProfile(request_object_key=...)` signs the pushed authorization
request with this key; see [FAPI 2.0](fapi.md).

::: py_identity_model.core.models.RequestObjectKey

## Authorization URL

::: py_identity_model.core.jar.build_jar_authorization_url
