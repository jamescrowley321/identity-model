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

## Resource Server Verification

A resource server that accepts DPoP-bound access tokens must check, on every
request, that the token arrived with the `DPoP` scheme and a proof signed by the
key in its `cnf.jkt` (RFC 9449 §7.1, §6.1). Pass `validate_token` a
`TokenPresentation` that describes how the token arrived:

```python
from py_identity_model import (
    AuthorizationScheme,
    DPoPValidationError,
    TokenBinding,
    TokenPresentation,
    TokenValidationConfig,
    validate_token,
)

config = TokenValidationConfig(
    perform_disco=True,
    audience="urn:my-api",
    required_binding=TokenBinding.DPOP,  # refuse Bearer and unbound tokens
)

try:
    claims = validate_token(
        access_token,
        config,
        disco_doc_address,
        presentation=TokenPresentation(
            scheme=AuthorizationScheme.DPOP,       # from the Authorization header
            method=request.method,
            url="https://api.example.com/orders",  # the URI the client addressed
            dpop_proof=request.headers["DPoP"],
        ),
    )
except DPoPValidationError as exc:
    # 401, WWW-Authenticate: DPoP error="<exc.kind.oauth_error>"
    ...
```

The proof checks run in RFC 9449 §4.3 order: `typ` is `dpop+jwt`; `alg` is an
asymmetric algorithm DPoP keys support (`none` and `HS*` are refused); the `jwk`
header is a public key that fits `alg` and meets the RSA/EC strength floor; the
signature verifies with it; `htm` equals the request method; `htu` equals the
request URI, ignoring query and fragment, with scheme and host case and the
default port normalized (RFC 3986 §6.2.2.1, §6.2.3) and the path compared as sent;
`iat` is inside `[now - max_age - iat_leeway, now + iat_leeway]`; `nonce`
equals `TokenPresentation.expected_nonce` when one is set; `ath` is the hash of
the access token; the key's RFC 7638 thumbprint equals `cnf.jkt`; and last, the
`jti` has not been seen. A rejected proof never consumes its `jti`.

What `required_binding` does:

| `required_binding` | Token | Presented as | Result |
|---|---|---|---|
| any | `cnf.jkt` | `DPoP` + valid proof by the bound key | accepted |
| any | `cnf.jkt` | `Bearer`, or `DPoP` with no proof | `WRONG_SCHEME` / `PROOF_REQUIRED` |
| any | no `cnf.jkt` | `DPoP` | `NOT_BOUND` |
| `DPOP` | no `cnf.jkt` | anything | `NOT_BOUND` |
| any | `cnf["x5t#S256"]` | the bound client certificate | accepted (RFC 8705 §3) |
| any | `cnf["x5t#S256"]` | no client certificate, another one, or one that is not valid PEM/DER | `CertificateBindingError` |
| `MTLS` | no `cnf["x5t#S256"]` | anything | `CertificateBindingError` |
| `NONE` (default) | no `cnf` | `Bearer` | accepted |
| `NONE` | anything | no `presentation=` | not checked (the behaviour before this option existed) |

`required_binding=DPOP` or `MTLS` without `presentation=` raises
`ConfigurationException`. Every rejection is a `DPoPValidationError` (or
`CertificateBindingError` for mTLS), both `TokenValidationException`s, with a
typed `kind`. `kind.oauth_error` is the `WWW-Authenticate` error code:
`invalid_dpop_proof` for a bad proof and `invalid_token` for a failed binding.

Proof algorithms, the `iat` window and the `jti` replay cache are set with
`TokenValidationConfig(dpop=DPoPVerificationOptions(...))`. The default
replay cache is an in-memory cache for the process. It holds each `jti` for as
long as the window would accept its proof and never evicts a live one: when it
is full, a new proof is refused with `REPLAY_CACHE_FULL`, so size
`InMemoryDPoPReplayCache(max_entries=...)` above the proofs a process accepts
in one window. A deployment with several
processes or hosts needs a shared `DPoPReplayCache` so a proof replayed to
another worker is refused (RFC 9449 §11.1).

The FastAPI middleware does not build a `TokenPresentation` yet
([#1021](https://github.com/jamescrowley321/identity-model/issues/1021)).

::: py_identity_model.core.token_binding.TokenPresentation

::: py_identity_model.core.token_binding.AuthorizationScheme

::: py_identity_model.core.token_binding.TokenBinding

::: py_identity_model.core.dpop_verify.verify_dpop_proof

::: py_identity_model.core.dpop_verify.DPoPProofRequest

::: py_identity_model.core.dpop_verify.DPoPProof

::: py_identity_model.core.dpop_verify.DPoPVerificationOptions

::: py_identity_model.core.dpop_verify.DPoPErrorKind

::: py_identity_model.core.dpop_verify.DPoPValidationError

::: py_identity_model.core.dpop_verify.DPoPReplayCache

::: py_identity_model.core.dpop_verify.InMemoryDPoPReplayCache

::: py_identity_model.core.dpop.compute_jwk_thumbprint
