# Dynamic Client Registration

OAuth 2.0 Dynamic Client Registration (RFC 7591) and Client Registration
Management (RFC 7592): register a client at runtime, then read, update, and
deregister it through the management URI the registration response returns.

Like the other endpoint clients, these functions return an error-carrying
response instead of raising on protocol errors — check `is_successful` before
touching the guarded fields (`client_id`, `client_secret`,
`registration_access_token`, `registration_client_uri`). Secrets are redacted
from `repr()`.

```python
from py_identity_model import (
    ClientDeleteRequest,
    ClientReadRequest,
    ClientRegistrationRequest,
    ClientUpdateRequest,
    delete_client,
    read_client,
    register_client,
    update_client,
)

registered = register_client(
    ClientRegistrationRequest(
        address=disco.registration_endpoint,
        redirect_uris=["https://rp.example.com/callback"],
        client_name="my-app",
        token_endpoint_auth_method="client_secret_basic",
        initial_access_token=initial_access_token,  # if the endpoint is protected
    )
)
mgmt_uri = registered.registration_client_uri
token = registered.registration_access_token

read = read_client(ClientReadRequest(address=mgmt_uri, registration_access_token=token))
token = read.registration_access_token or token  # RFC 7592 §3: the OP MAY rotate it

updated = update_client(
    ClientUpdateRequest(
        address=mgmt_uri,
        registration_access_token=token,
        client_id=registered.client_id,          # the PUT body must carry client_id
        redirect_uris=["https://rp.example.com/callback"],
        client_name="my-app-renamed",
        client_secret=registered.client_secret,  # echo back when required
    )
)
token = updated.registration_access_token or token

delete_client(ClientDeleteRequest(address=mgmt_uri, registration_access_token=token))
```

Two RFC 7592 behaviors to keep in mind: an update sends the **full** client
metadata (fields omitted from `ClientUpdateRequest` are treated by the server
as removed), and the OP may rotate `registration_access_token` on every
management response — always use the freshest token returned.

## Models

::: py_identity_model.core.models.ClientRegistrationRequest

::: py_identity_model.core.models.ClientReadRequest

::: py_identity_model.core.models.ClientUpdateRequest

::: py_identity_model.core.models.ClientDeleteRequest

::: py_identity_model.core.models.ClientRegistrationResponse

::: py_identity_model.core.models.ClientDeleteResponse

## Sync API

::: py_identity_model.sync.registration.register_client

::: py_identity_model.sync.registration.read_client

::: py_identity_model.sync.registration.update_client

::: py_identity_model.sync.registration.delete_client

## Async API

::: py_identity_model.aio.registration.register_client

::: py_identity_model.aio.registration.read_client

::: py_identity_model.aio.registration.update_client

::: py_identity_model.aio.registration.delete_client
