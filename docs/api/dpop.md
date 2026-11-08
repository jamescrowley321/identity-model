# DPoP (Demonstrating Proof of Possession)

OAuth 2.0 DPoP (RFC 9449) for binding tokens to a client's private key.

## Key Management

`generate_dpop_key` supports `ES256` (default), `ES384`, `ES512`, `PS256`,
`EdDSA` (Ed25519, RFC 8037) and `RS256`. A FAPI 2.0 client must use `ES256`,
`PS256` or `EdDSA` (FAPI 2.0 Security Profile §5.4.1), and one the server lists
in `dpop_signing_alg_values_supported`.

::: py_identity_model.core.dpop.DPoPKey

::: py_identity_model.core.dpop.generate_dpop_key

## Proof Creation

::: py_identity_model.core.dpop.create_dpop_proof

::: py_identity_model.core.dpop.compute_ath

## HTTP Headers

::: py_identity_model.core.dpop.build_dpop_headers

## Token Requests

Set `dpop_key` on a `PushedAuthorizationRequest`, `AuthorizationCodeTokenRequest`
or `RefreshTokenRequest` to bind the issued tokens to the key. Pass the same key
when refreshing, so the new access token stays bound (RFC 9449 §5, FAPI 2.0
Security Profile §5.3.3.1). Each call attaches a token-endpoint proof and
retries once on a `use_dpop_nonce` challenge (RFC 9449 §8).

```python
from py_identity_model import RefreshTokenRequest, refresh_token

response = refresh_token(
    RefreshTokenRequest(
        address=token_endpoint,
        client_id="my-client",
        refresh_token=tokens["refresh_token"],
        dpop_key=dpop_key,
        require_dpop_token_type=True,
    )
)
```

A server that ignores the proof can still answer with a Bearer token. With
`require_dpop_token_type=True` such a response fails: `is_successful` is
`False` and `error_kind` is `TokenErrorKind.DPOP_TOKEN_TYPE_MISMATCH`.
`token_type` is compared case-insensitively (RFC 6749 §7.1). The flag is off by
default; `FAPI2ClientProfile` sets it on every DPoP-bound token request it
builds.

::: py_identity_model.core.models.TokenErrorKind
