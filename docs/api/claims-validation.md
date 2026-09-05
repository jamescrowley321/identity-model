# Claims Validation

Injectable, composable validators that run **after** the standard token checks
(signature, `iss`, `aud`, `exp`, `nbf`) pass. They let you assert
application-specific requirements — required claims, exact values, granted
scopes — as small, reusable pieces you compose together.

A claims validator is any callable `(claims) -> None` that raises to reject.
That's the whole contract, so a plain function still works:

```python
from py_identity_model import TokenValidationConfig

def require_tenant(claims) -> None:
    if "tenant_id" not in claims:
        raise ValueError("token is missing tenant_id")

config = TokenValidationConfig(
    perform_disco=True,
    issuer="https://issuer.example.com",
    audience="my-api",
    claims_validator=require_tenant,
)
```

## Ready-made validators

`require_claims`, `require_claim_value`, and `require_scopes` cover the common
cases and raise a typed [`ClaimsValidationError`](#py_identity_model.core.claims_validation.ClaimsValidationError)
that carries a structured `reason` (and the offending `claim`) — the reason
survives to the caller instead of being flattened to a generic string.

```python
from py_identity_model import require_claims, require_claim_value, require_scopes

require_claims("sub", "email")           # every listed claim must be present (non-null)
require_claim_value("token_use", "access")  # claim must be present AND equal
require_scopes("orders:read", "orders:write")  # from the `scope` string or `scp` array
```

`require_scopes` reads scopes from the space-delimited `scope` claim or the
`scp` array, and **fails closed**: a malformed (non-string, non-array) scope
claim yields no scopes and rejects rather than crashing.

## Composing validators

`combine_claims_validators` merges several into one:

- `require="all"` (default) — every validator must accept; fails fast on the
  first rejection.
- `require="any"` — passes if at least one accepts; if all reject, it aggregates
  their reasons. An empty `any`-of set is rejected at construction (it could
  never be satisfied).

```python
from py_identity_model import (
    TokenValidationConfig,
    combine_claims_validators,
    require_claim_value,
    require_scopes,
)

validator = combine_claims_validators(
    [
        require_claim_value("token_use", "access"),
        require_scopes("orders:read"),
    ]
)  # require="all"

config = TokenValidationConfig(
    perform_disco=True,
    issuer="https://issuer.example.com",
    audience="orders-api",
    claims_validator=validator,
)
```

Because the composed result is itself a plain `(claims) -> None` callable, it
drops straight into the FastAPI middleware / WebSocket authenticator's
`custom_claims_validator` with no adapter.

## Construction errors and edge cases

Impossible validators are rejected at **construction** (`ValueError`), not at
validation time: `require_claims()` / `require_scopes()` with zero arguments,
`combine_claims_validators` with `require="any"` and no members, or a
`require` value other than `"all"` / `"any"`.

In `"any"` mode, only a `ClaimsValidationError` counts as a clean rejection to
aggregate — any other exception from a member propagates immediately.
Validators are synchronous callables; composing async validators is not
supported.

## Backward compatibility

This is a pure opt-in layer. Any existing `(claims) -> None` callable that
rejects by raising continues to work exactly as before; only a validator that
raises `ClaimsValidationError` gets its structured reason preserved.

## API

::: py_identity_model.core.claims_validation.ClaimsValidator

::: py_identity_model.core.claims_validation.ClaimsValidationError

::: py_identity_model.core.claims_validation.combine_claims_validators

::: py_identity_model.core.claims_validation.require_claims

::: py_identity_model.core.claims_validation.require_claim_value

::: py_identity_model.core.claims_validation.require_scopes
