# Logout

OpenID Connect logout on the RP side: **RP-Initiated Logout 1.0** (send the
user agent to the OP's end-session endpoint and verify the round trip back)
and **Back-Channel Logout 1.0** (validate the Logout Token the OP POSTs
directly to the RP).

## RP-initiated logout

`build_end_session_url` builds the redirect to the OP's `end_session_endpoint`
(from the discovery document); `validate_post_logout_state` verifies — in
constant time — that the `state` echoed back to the
`post_logout_redirect_uri` matches the one sent. Both are pure functions with
no I/O, shared by the sync and async APIs.

```python
from py_identity_model import build_end_session_url, validate_post_logout_state

logout_url = build_end_session_url(
    end_session_endpoint=disco.end_session_endpoint,
    id_token_hint=id_token,
    client_id=CLIENT_ID,
    post_logout_redirect_uri="https://app.example.com/logged-out",
    state=expected_state,
)
# Redirect the user agent to logout_url; then, on the post-logout callback:
validate_post_logout_state(expected_state, returned_state)  # raises on mismatch
```

## Back-channel logout

`validate_logout_token` runs the standard JWT validation (signature via
discovery/JWKS, `iss`, `aud`, `exp`) and then enforces the Logout-Token
profile of Back-Channel Logout 1.0 §2.4: `iss`/`aud`/`iat`/`jti`/`events`
must be present, the `events` object must contain the
`http://schemas.openid.net/event/backchannel-logout` member, at least one of
`sub` / `sid` must identify the session, and a `nonce` claim is prohibited
(so a Logout Token can never pass as an ID Token). Set `audience` to your
`client_id` and `issuer` to the OP issuer in the config.

```python
from py_identity_model import TokenValidationConfig, validate_logout_token

claims = validate_logout_token(
    logout_token,  # the `logout_token` form field the OP POSTs to your backchannel_logout_uri
    TokenValidationConfig(perform_disco=True, audience=CLIENT_ID, issuer=ISSUER),
    disco_doc_address=DISCOVERY_URL,
)
sid = claims.get("sid")  # terminate the matching session(s)
```

Failures raise `LogoutTokenValidationException` (profile rule) or
`TokenValidationException` (standard JWT failure) — both are caught by
`except TokenValidationException`, so handlers fail closed. The state check
raises `LogoutStateValidationException`.

## RP-initiated logout API

::: py_identity_model.core.logout_logic.build_end_session_url

::: py_identity_model.core.logout_logic.validate_post_logout_state

## Back-channel logout — Sync API

::: py_identity_model.sync.logout.validate_logout_token

## Back-channel logout — Async API

::: py_identity_model.aio.logout.validate_logout_token

## Claim-level building block

For callers that validate the JWT themselves, the Logout-Token profile checks
are available as a pure function over an already-validated claim set:

::: py_identity_model.core.logout_logic.validate_logout_token_claims

## Exceptions

::: py_identity_model.exceptions.LogoutTokenValidationException

::: py_identity_model.exceptions.LogoutStateValidationException
