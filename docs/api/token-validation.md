# Token Validation

JWT validation with optional OpenID Connect auto-discovery.

For sender-constrained access tokens (DPoP `cnf.jkt`, mTLS `cnf["x5t#S256"]`),
pass `presentation=` and set `required_binding`; see
[DPoP: Resource Server Verification](dpop.md#resource-server-verification).

## Configuration

::: py_identity_model.core.models.TokenValidationConfig

## Sync API

::: py_identity_model.sync.token_validation.validate_token

## Async API

::: py_identity_model.aio.token_validation.validate_token
