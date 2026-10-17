# JWKS

JSON Web Key Set operations per RFC 7517.

## Key Models

::: py_identity_model.core.models.JsonWebKey

::: py_identity_model.core.models.JsonWebKeyParameterNames

::: py_identity_model.core.models.JsonWebAlgorithmsKeyTypes

## Request / Response Models

::: py_identity_model.core.models.JwksRequest

::: py_identity_model.core.models.JwksResponse

## Signing key selection

Token validation picks the verification key from the JWK Set. Only signing
keys can verify a signature: keys whose `use` is `sig` or absent
([RFC 7517 §4.2](https://www.rfc-editor.org/rfc/rfc7517#section-4.2)). A key
marked `use: "enc"` is never used, whether the token's `kid` names it or the
token has no `kid`.

- A `kid` that names no signing key is a key miss. Validation refreshes the
  JWK Set once (subject to `Config.jwks_kid_miss_cooldown`) and then raises
  `KeyNotFoundException`.
- A token with no `kid` uses the single signing key left after narrowing by
  `alg` and `kty`. With no signing key in the set it raises
  `KeyNotFoundException`. With more than one left it raises
  `AmbiguousKeyException`.

::: py_identity_model.core.parsers.find_key_by_kid

## Sync API

::: py_identity_model.sync.jwks.get_jwks

::: py_identity_model.core.parsers.jwks_from_dict

## Async API

::: py_identity_model.aio.jwks.get_jwks
