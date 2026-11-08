# Refresh Token

OAuth 2.0 Refresh Token Grant (RFC 6749 Section 6) for obtaining new access tokens.

For a DPoP-bound client, pass the flow's `dpop_key` so the refreshed access
token stays bound (RFC 9449 §5); see [DPoP](dpop.md#token-requests). A FAPI 2.0
client builds the request with `FAPI2ClientProfile.refresh_token_request`.

## Request Model

::: py_identity_model.core.models.RefreshTokenRequest

## Response Model

::: py_identity_model.core.models.RefreshTokenResponse

## Functions

::: py_identity_model.sync.token_client.refresh_token
