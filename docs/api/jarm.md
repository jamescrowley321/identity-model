# JARM (JWT-Secured Authorization Response Mode)

JARM wraps the entire authorization response in a signed JWT, so the RP can
verify that the `code`/`state` values really came from the authorization
server. Signed JARM (JWS) is supported for the `query.jwt`, `fragment.jwt`,
and `form_post.jwt` response modes; encrypted JARM (JWE) is not — an
encrypted response is rejected rather than silently accepted.

`process_jarm_response` verifies the response JWT end to end — signing
algorithm (default-deny: `none` and symmetric algorithms are refused, and the
algorithm must be advertised by the AS), signature against the JWKS, and the
`iss` / `aud` / `exp` claims (all three must be *present* as well as valid) —
then returns the same `AuthorizeCallbackResponse` the plain callback parser
produces, ready for `validate_authorize_callback_state`.

```python
from py_identity_model import (
    is_jarm_response,
    process_jarm_response,
    validate_authorize_callback_state,
)

if is_jarm_response(callback_url):
    result = process_jarm_response(
        callback_url,
        client_id=CLIENT_ID,
        disco_doc_address=DISCOVERY_URL,  # issuer, JWKS, and algorithms via discovery
    )
    # Bind the response to the original request (CSRF defense).
    validate_authorize_callback_state(result, expected_state)
    code = result.code
```

For `form_post.jwt`, the JWT arrives in the POST body rather than the URL —
pass the raw JWT with `is_jwt=True`. To validate without any network I/O,
supply `issuer`, `jwks`, and `algorithms` instead of `disco_doc_address`.

Verification failures surface as the specific exception for what went wrong:
`JarmValidationException` for a missing `response` parameter, a rejected
algorithm, or a missing required claim; `SignatureVerificationException`,
`InvalidIssuerException`, `InvalidAudienceException`, or
`TokenExpiredException` for a value that fails verification.

## Detection and extraction

::: py_identity_model.core.jarm.is_jarm_response

::: py_identity_model.core.jarm.extract_jarm_response_jwt

## Sync API

::: py_identity_model.sync.jarm.process_jarm_response

## Async API

::: py_identity_model.aio.jarm.process_jarm_response

## Exceptions

::: py_identity_model.exceptions.JarmValidationException
